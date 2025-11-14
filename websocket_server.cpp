#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/http.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <mongocxx/client.hpp>
#include <mongocxx/instance.hpp>
#include <mongocxx/uri.hpp>
#include <bsoncxx/json.hpp>
#include <bsoncxx/builder/stream/document.hpp>
#include <curl/curl.h>
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <mutex>
#include <chrono>
#include <regex>


namespace beast = boost::beast;
namespace websocket = beast::websocket;
namespace net = boost::asio;
namespace http = beast::http;

using tcp = boost::asio::ip::tcp;
using bsoncxx::builder::stream::document;
using bsoncxx::builder::stream::finalize;

// MongoDB connection (configure this!)
// const std::string MONGODB_URI = "mongodb+srv://username:password@cluster.mongodb.net/lucidio?retryWrites=true&w=majority";

const char* mongo_uri_env = std::getenv("MONGODB_URI");
const std::string MONGODB_URI = mongo_uri_env ? mongo_uri_env : "mongodb://localhost:27017/lucidio";

struct ClientInfo {
    std::shared_ptr<websocket::stream<tcp::socket>> ws;
    std::string user_id;
    std::string api_key_id;
    std::string agent_id;
    std::string client_type; // for dashboard
};

std::vector<ClientInfo> clients;
std::mutex clients_mutex;

// Extract API key from WebSocket URL query string
std::string extract_api_key(const std::string& target) {
    std::regex pattern("api_key=([^&]+)");
    std::smatch match;
    if (std::regex_search(target, match, pattern)) {
        return match[1].str();
    }
    return "";
}

// Extract arbitrary query parameter from WebSocket URL (?param=value)
std::string extract_query_param(const std::string& target, const std::string& name) {
    std::regex pattern(name + "=([^&]+)");
    std::smatch match;
    if (std::regex_search(target, match, pattern)) return match[1].str();
    return "";
}


// Validate API key against MongoDB
bool validate_api_key(mongocxx::client& client, const std::string& api_key, 
                      std::string& user_id, std::string& api_key_id) {
    try {
        std::cout << "DEBUG: Validating API key: " << api_key << "\n";
        
        auto db = client["test"];
        auto collection = db["apikeys"];
        
        // First, let's see ALL keys in the database
        std::cout << "DEBUG: Checking all API keys in database:\n";
        auto cursor = collection.find({});
        int count = 0;
        for (auto&& doc : cursor) {
            count++;
            std::cout << "  Key " << count << ": " << bsoncxx::to_json(doc) << "\n";
        }
        std::cout << "DEBUG: Total keys found: " << count << "\n";
        
        auto query = document{} 
            << "key" << api_key 
            << "status" << "active" 
            << finalize;
        
        std::cout << "DEBUG: Query: " << bsoncxx::to_json(query.view()) << "\n";
    
        auto result = collection.find_one(query.view());
        
        if (result) {
            std::cout << "DEBUG: Match found!\n";
            auto doc = result->view();
            user_id = doc["userId"].get_oid().value.to_string();
            api_key_id = doc["_id"].get_oid().value.to_string();
            
            // Update last_used timestamp
            auto update = document{} 
                << "$set" << bsoncxx::builder::stream::open_document
                    << "lastUsed" << bsoncxx::types::b_date(std::chrono::system_clock::now())
                << bsoncxx::builder::stream::close_document
                << finalize;
            
            collection.update_one(query.view(), update.view());
            
            std::cout << "✓ API key validated for user: " << user_id << "\n";
            return true;
        }
        
        std::cout << "✗ No match found for API key\n";
        return false;
    } catch (const std::exception& e) {
        std::cerr << "Error validating API key: " << e.what() << "\n";
        return false;
    }
}

// Batch analyze for anomalies using the ML service 

static size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

std::string call_ml_service(const std::string& jsonPayload) {
    CURL* curl = curl_easy_init();
    std::string response;

    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://ml:8000/analyze_batch");
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonPayload.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, jsonPayload.size());

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }

    return response;
}

// Broadcast agent messages to all dashboards belonging to the same user
void broadcast_to_dashboards(const std::string& user_id, const std::string& message) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    for (auto& c : clients) {
        if (c.client_type == "dashboard" && c.user_id == user_id) {
            try {
                c.ws->text(true);
                c.ws->write(net::buffer(message));
            } catch (const std::exception& e) {
                std::cerr << "Broadcast error: " << e.what() << "\n";
            }
        }
    }
}

// Save network data to MongoDB
void save_network_data(mongocxx::client& mongo_client, const std::string& json_data,
                       const std::string& user_id, const std::string& agent_id) {
    try {
        auto db = mongo_client["test"];
        auto collection = db["networkflows"];
        
        // Parse JSON and add metadata
        auto doc = bsoncxx::from_json(json_data);
        auto builder = bsoncxx::builder::stream::document{};
        
        builder << "timestamp" << bsoncxx::types::b_date(std::chrono::system_clock::now())
                << "userId" << bsoncxx::oid(user_id)
                << "agentId" << agent_id
                << "data" << doc;
        
        collection.insert_one(builder.view());
        std::cout << "✓ Saved network data for user: " << user_id << "\n";
        
    } catch (const std::exception& e) {
        std::cerr << "Error saving network data: " << e.what() << "\n";
    }
}

void handle_client(tcp::socket socket, mongocxx::client& mongo_client) {
    try {
        std::cout << "=== DEBUG: Client connection started ===\n";
        
        auto ws = std::make_shared<websocket::stream<tcp::socket>>(std::move(socket));
        
        std::cout << "DEBUG: Created WebSocket stream\n";
        
        // Read the handshake request to extract API key
        beast::flat_buffer buffer;
        http::request<http::string_body> req;
        
        std::cout << "DEBUG: About to read HTTP request\n";
        http::read(ws->next_layer(), buffer, req);
        std::cout << "DEBUG: HTTP request read successfully\n";
        std::cout << "DEBUG: Target: " << req.target() << "\n";
        std::cout << "DEBUG: Method: " << req.method_string() << "\n";
        
        std::string target(req.target());
        std::string api_key = extract_api_key(target);
        std::string client_type = extract_query_param(target, "type");
        if (client_type.empty()) client_type = "agent"; // default to agent if not specified

        std::cout << "DEBUG: Extracted client type: " << client_type << "\n";

        
        std::cout << "DEBUG: Extracted API key: " << (api_key.empty() ? "EMPTY" : api_key.substr(0, 16) + "...") << "\n";
        
        
        if (api_key.empty()) {
            std::cerr << "✗ No API key provided\n";
            ws->close(websocket::close_code::policy_error);
            return;
        }
        
        // Validate API key
        std::string user_id, api_key_id;
        if (!validate_api_key(mongo_client, api_key, user_id, api_key_id)) {
            std::cerr << "✗ Invalid API key\n";
            ws->close(websocket::close_code::policy_error);
            return;
        }
        
        // Accept WebSocket connection
        ws->accept(req);
        
        std::cout << "✓ Client authenticated and connected\n";
        
        // Generate agent ID
        std::string agent_id = "agent_" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
        
        // Store client info
        {
            std::lock_guard<std::mutex> lock(clients_mutex);
            clients.push_back({ws, user_id, api_key_id, agent_id, client_type});

        }
        
        // Read messages from agent
        while (true) {
            beast::flat_buffer msg_buffer;
            ws->read(msg_buffer);
            
            std::string message = beast::buffers_to_string(msg_buffer.data());
            
            if (!message.empty()) {
                std::cout << "Received data from agent " << agent_id << "\n";
                save_network_data(mongo_client, message, user_id, agent_id);

                auto parsed = bsoncxx::from_json(message);
                auto view = parsed.view();

                if (view.find("topFlows") != view.end()) {

                    // ---- Build ML input ----
                    bsoncxx::builder::basic::array flowsForML;
                    auto flowsInput = view["topFlows"].get_array().value;

                    for (auto&& f : flowsInput) {
                        auto fdoc = f.get_document().value;

                        double duration = fdoc["duration_ms"].get_int64() / 1000.0;

                        bsoncxx::builder::basic::document flowDoc;
                        flowDoc.append(
                            bsoncxx::builder::basic::kvp("packets",  fdoc["packets"].get_int32()),
                            bsoncxx::builder::basic::kvp("bytes",    fdoc["bytes"].get_int32()),
                            bsoncxx::builder::basic::kvp("duration", duration),
                            bsoncxx::builder::basic::kvp("entropy",  fdoc["entropy"].get_double())
                        );

                        flowsForML.append(flowDoc);
                    }

                    // ---- Call ML ----
                    bsoncxx::builder::basic::document mlDoc;
                    mlDoc.append(bsoncxx::builder::basic::kvp("flows", flowsForML));

                    std::string mlPayload = bsoncxx::to_json(mlDoc.view());
                    std::string mlResult  = call_ml_service(mlPayload);

                    auto mlJson = bsoncxx::from_json(mlResult);
                    auto mlView = mlJson.view();

                    if (mlView.find("scores") == mlView.end()) {
                        broadcast_to_dashboards(user_id, message);
                        continue;
                    }

                    auto scores = mlView["scores"].get_array().value;

                    // ---- Build enriched ----
                    // ---- Build enriched JSON ----
                    bsoncxx::builder::stream::document enriched;

                    auto ctx = enriched
                        << "timestamp" << view["timestamp"].get_value()
                        << "sensorId"  << view["sensorId"].get_value()
                        << "summary"   << view["summary"].get_value()
                        << "protocols" << view["protocols"].get_value()
                        << "anomalies" << view["anomalies"].get_value()
                        << "topFlows"  << bsoncxx::builder::stream::open_array;

                    // ---- Add each flow ----
                    int i = 0;
                    for (auto&& f : flowsInput) {
                        auto fdoc = f.get_document().value;
                        auto sdoc = scores[i].get_document().value;

                        // Build a complete document using basic builder
                        bsoncxx::builder::basic::document flowWithML;
                        
                        // Copy all original field
                        for (auto&& elem : fdoc) {
                            flowWithML.append(bsoncxx::builder::basic::kvp(elem.key(), elem.get_value()));
                        }
                        
                        // Add ML fields
                        flowWithML.append(
                            bsoncxx::builder::basic::kvp("anomalyScore", sdoc["anomalyScore"].get_double()),
                            bsoncxx::builder::basic::kvp("anomalyLabel", std::string(sdoc["anomalyLabel"].get_string().value))
                        );
                        
                        // Append the complete document to the array
                        ctx << flowWithML.extract();
                        
                        i++;
                    }


                    // ---- Close array ----
                    ctx << bsoncxx::builder::stream::close_array;


                    std::string finalPayload = bsoncxx::to_json(enriched.view());
                    broadcast_to_dashboards(user_id, finalPayload);
                }
                else {
                    broadcast_to_dashboards(user_id, message);
                }

            }


            
            msg_buffer.clear();
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Client handler error: " << e.what() << "\n";
        
        // Remove client from list on disconnect
        // (implement cleanup logic here)
    }
}

void accept_connections(net::io_context& ioc, tcp::acceptor& acceptor, 
                       mongocxx::client& mongo_client) {
    while (true) {
        tcp::socket socket(ioc);
        acceptor.accept(socket);
        
        std::cout << "New connection attempt...\n";
        std::thread(handle_client, std::move(socket), std::ref(mongo_client)).detach();
    }
}

int main() {
    try {
        // Initialize MongoDB driver
        mongocxx::instance instance{};
        mongocxx::client mongo_client{mongocxx::uri{MONGODB_URI}};
        
        std::cout << "Attempting to connect to MongoDB...\n";
        std::cout << "URI: " << MONGODB_URI << "\n";
        
        // Force actual connection and validate
        try {
            auto admin_db = mongo_client["admin"];
            auto result = admin_db.run_command(bsoncxx::builder::stream::document{} << "ping" << 1 << bsoncxx::builder::stream::finalize);
            std::cout << "✓ MongoDB ping successful\n";
            
            // Now test the actual database
            auto db = mongo_client["test"];
            auto collections = db.list_collection_names();
            
            std::cout << "✓ Connected to 'test' database\n";
            std::cout << "Collections found: ";
            for (const auto& coll : collections) {
                std::cout << coll << " ";
            }
            std::cout << "\n";
            
            // Count API keys
            auto api_keys_coll = db["apikeys"];
            int64_t key_count = api_keys_coll.count_documents({});
            std::cout << "✓ API keys in database: " << key_count << "\n";
            
        } catch (const std::exception& e) {
            std::cerr << "❌ MongoDB connection FAILED: " << e.what() << "\n";
            std::cerr << "Check your MONGODB_URI environment variable\n";
            return 1;
        }
        
        // Start WebSocket server
        net::io_context ioc;
        tcp::acceptor acceptor(ioc, tcp::endpoint(tcp::v4(), 8080));
        
        std::cout << "\n";
        std::cout << "╔═══════════════════════════════════════╗\n";
        std::cout << "║   Lucidio WebSocket Server           ║\n";
        std::cout << "╠═══════════════════════════════════════╣\n";
        std::cout << "║  Port: 8080                           ║\n";
        std::cout << "║  MongoDB: Connected                   ║\n";
        std::cout << "║  Status: Waiting for agents...        ║\n";
        std::cout << "╚═══════════════════════════════════════╝\n";
        std::cout << "\n";
        
        accept_connections(ioc, acceptor, mongo_client);
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}