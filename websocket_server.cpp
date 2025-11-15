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
const std::string MONGODB_URI = mongo_uri_env ? mongo_uri_env : "mongodb+srv://localhost:27001";

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
        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        
        curl_easy_setopt(curl, CURLOPT_URL, "http://ml:8000/analyze_batch");
       // curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:8000/analyze_batch");
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
         curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers); 
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonPayload.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, jsonPayload.size());

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        CURLcode res = curl_easy_perform(curl);
        
        if (res != CURLE_OK) {
            std::cerr << "cURL error: " << curl_easy_strerror(res) << "\n";
        } else {
            long http_code = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
            std::cout << "HTTP response code: " << http_code << "\n";
        }
        
        curl_slist_free_all(headers); 


        curl_easy_cleanup(curl);
    }

    return response;
}

// Normalize raw ML anomaly score (e.g. -0.25 .. -0.05) into 0.0 ... 1.0
double normalize_anomaly(double raw) {
    // Tune these to your model’s typical range
    const double minVal = -0.30;  // "very normal"
    const double maxVal = -0.10;  // "least normal"

    double n = (raw - minVal) / (maxVal - minVal);

    if (n < 0.0) n = 0.0;
    if (n > 1.0) n = 1.0;
    return n;
}

// Simple threshold: consider >= 0.75 as an anomaly
inline bool is_anomalous(double normalized) {
    return normalized >= 0.75;
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
    std::string last_message;
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
            last_message = message; 

            if (!message.empty()) {
                // Trim whitespace from the message
            size_t start = message.find_first_not_of(" \t\n\r");
            size_t end = message.find_last_not_of(" \t\n\r");
            
            if (start == std::string::npos) {
                std::cerr << "IGNORING EMPTY FRAME\n";
                continue;
            }
            
            message = message.substr(start, end - start + 1);
            
            std::cout << "Received data from agent " << agent_id << "\n";
            std::cout << "Message length: " << message.length() << "\n";
            
            // Parse JSON first
            bsoncxx::document::value parsed = bsoncxx::from_json(message);
            std::cout << "Parsed JSON: " << bsoncxx::to_json(parsed.view()) << "\n";
                
                auto view = parsed.view();
                std::cout << "Now attempting to save network data..." << "\n";
                save_network_data(mongo_client, message, user_id, agent_id);

                if (view.find("topFlows") != view.end()) {
                    int anomaliesDetected = 0;
                    auto summaryDoc = view["summary"].get_document().value;

                    // ---- Build ML input ----
                    bsoncxx::builder::basic::array flowsForML;
                    auto flowsInput = view["topFlows"].get_array().value;

                    for (auto&& f : flowsInput) {
                        auto fdoc = f.get_document().value;

                        // Helper function to safely get values
                        auto getInt = [&](const char* key) -> int32_t {
                            auto elem = fdoc[key];
                            if (elem.type() == bsoncxx::type::k_int32) return elem.get_int32().value;
                            if (elem.type() == bsoncxx::type::k_int64) return static_cast<int32_t>(elem.get_int64().value);
                            return 0;
                        };

                        auto getDouble = [&](const char* key) -> double {
                            auto elem = fdoc[key];
                            if (elem.type() == bsoncxx::type::k_double) return elem.get_double().value;
                            if (elem.type() == bsoncxx::type::k_int32) return static_cast<double>(elem.get_int32().value);
                            if (elem.type() == bsoncxx::type::k_int64) return static_cast<double>(elem.get_int64().value);
                            return 0.0;
                        };

                        bsoncxx::builder::basic::document flowDoc;
                        flowDoc.append(
                            // Basic stats
                            bsoncxx::builder::basic::kvp("bytes", getDouble("bytes")),
                            bsoncxx::builder::basic::kvp("packets", getDouble("packets")),
                            bsoncxx::builder::basic::kvp("inbound_bytes", getDouble("inbound_bytes")),
                            bsoncxx::builder::basic::kvp("outbound_bytes", getDouble("outbound_bytes")),
                            
                            // Packet statistics
                            bsoncxx::builder::basic::kvp("packet_size_mean", getDouble("packet_size_mean")),
                            bsoncxx::builder::basic::kvp("packet_size_variance", getDouble("packet_size_variance")),
                            
                            // Buckets
                            bsoncxx::builder::basic::kvp("volume_bucket", getDouble("volume_bucket")),
                            bsoncxx::builder::basic::kvp("packet_bucket", getDouble("packet_bucket")),
                            
                            // Timing
                            bsoncxx::builder::basic::kvp("flow_duration_ms", getDouble("flow_duration_ms")),
                            bsoncxx::builder::basic::kvp("iat_mean", getDouble("iat_mean")),
                            bsoncxx::builder::basic::kvp("iat_variance", getDouble("iat_variance")),
                            
                            // Burst
                            bsoncxx::builder::basic::kvp("burst_count", getDouble("burst_count")),
                            bsoncxx::builder::basic::kvp("burst_current", getDouble("burst_current")),
                            
                            // Time of day
                            bsoncxx::builder::basic::kvp("hour_of_day", getDouble("hour_of_day")),
                            bsoncxx::builder::basic::kvp("minute_of_day", getDouble("minute_of_day")),
                            bsoncxx::builder::basic::kvp("lifetime_bucket", getDouble("lifetime_bucket")),
                            
                            // TCP flags
                            bsoncxx::builder::basic::kvp("syn_count", getDouble("tcp_syn")),
                            bsoncxx::builder::basic::kvp("fin_count", getDouble("tcp_fin")),
                            bsoncxx::builder::basic::kvp("rst_count", getDouble("tcp_rst")),
                            bsoncxx::builder::basic::kvp("ack_count", getDouble("tcp_ack")),
                            bsoncxx::builder::basic::kvp("is_closed", getDouble("is_closed")),
                            
                            // Direction and locality
                            bsoncxx::builder::basic::kvp("is_outbound", getDouble("outbound_bytes") > 0 ? 1.0 : 0.0),
                            bsoncxx::builder::basic::kvp("is_inbound", getDouble("inbound_bytes") > 0 ? 1.0 : 0.0),
                            bsoncxx::builder::basic::kvp("client_is_local", getDouble("client_is_local")),
                            bsoncxx::builder::basic::kvp("server_is_local", getDouble("server_is_local")),
                            bsoncxx::builder::basic::kvp("role_determined", getDouble("role_determined")),
                            
                            // Layer 7 protocols
                            bsoncxx::builder::basic::kvp("l7_http", getDouble("l7_http")),
                            bsoncxx::builder::basic::kvp("l7_tls", getDouble("l7_tls")),
                            bsoncxx::builder::basic::kvp("l7_dns", getDouble("l7_dns")),
                            bsoncxx::builder::basic::kvp("l7_mdns", getDouble("l7_mdns")),
                            bsoncxx::builder::basic::kvp("l7_ssdp", getDouble("l7_ssdp")),
                            
                            // TLS details
                            bsoncxx::builder::basic::kvp("tls_seen", getDouble("tls_seen")),
                            bsoncxx::builder::basic::kvp("tls_first_content_type", getDouble("tls_first_content_type")),
                            bsoncxx::builder::basic::kvp("tls_first_version_major", getDouble("tls_first_version_major")),
                            bsoncxx::builder::basic::kvp("tls_first_version_minor", getDouble("tls_first_version_minor")),
                            bsoncxx::builder::basic::kvp("tls_handshake_count", getDouble("tls_handshake_count")),
                            bsoncxx::builder::basic::kvp("tls_appdata_count", getDouble("tls_appdata_count")),
                            bsoncxx::builder::basic::kvp("tls_alert_count", getDouble("tls_alert_count")),
                            bsoncxx::builder::basic::kvp("tls_heartbeat_count", getDouble("tls_heartbeat_count")),
                            
                            // HTTP details
                            bsoncxx::builder::basic::kvp("http_seen", getDouble("http_seen")),
                            bsoncxx::builder::basic::kvp("http_is_response", getDouble("http_is_response")),
                            
                            // DNS details
                            bsoncxx::builder::basic::kvp("dns_seen", getDouble("dns_seen")),
                            bsoncxx::builder::basic::kvp("dns_query_type", getDouble("dns_query_type")),
                            bsoncxx::builder::basic::kvp("dns_query_class", getDouble("dns_query_class")),
                            
                            // Entropy and protocol
                            bsoncxx::builder::basic::kvp("payload_entropy", getDouble("payload_entropy")),
                            bsoncxx::builder::basic::kvp("protocol", [&]() -> double {
                                auto proto = fdoc["protocol"];
                                if (proto.type() == bsoncxx::type::k_string) {
                                    std::string p(proto.get_string().value);
                                    if (p == "TCP") return 6.0;
                                    if (p == "UDP") return 17.0;
                                    if (p == "ICMP") return 1.0;
                                }
                                return getDouble("protocol");
                            }())
                        );

                        flowsForML.append(flowDoc);
                    }

                    // ---- Call ML ----
                    bsoncxx::builder::basic::document mlDoc;
                    mlDoc.append(bsoncxx::builder::basic::kvp("flows", flowsForML));

                    std::string mlPayload = bsoncxx::to_json(mlDoc.view());
                    std::cout << "DEBUG: Calling ML service with payload (truncated): " 
                            << mlPayload.substr(0, 200) << "..." << "\n";

                    std::string mlResult = call_ml_service(mlPayload);

                    // // ---- Build ML input ----
                    // bsoncxx::builder::basic::array flowsForML;
                    // auto flowsInput = view["topFlows"].get_array().value;

                    // // Track how many flows are anomalous (after normalization)
                    // int anomaliesDetected = 0;

                    // // Keep original summary so we can reuse packet/byte counts
                    // auto summaryDoc = view["summary"].get_document().value;


                    // for (auto&& f : flowsInput) {
                    //     auto fdoc = f.get_document().value;

                    //     // double duration = fdoc["duration_ms"].get_int64() / 1000.0;

                    //     auto durElem = fdoc["duration_ms"];
                    //     double duration = 0.0;

                    //     if (durElem.type() == bsoncxx::type::k_int32) {
                    //         duration = durElem.get_int32().value / 1000.0;
                    //     } else if (durElem.type() == bsoncxx::type::k_int64) {
                    //         duration = durElem.get_int64().value / 1000.0;
                    //     } else {
                    //         duration = 0.0;
                    //     }

                    //     bsoncxx::builder::basic::document flowDoc;
                    //     flowDoc.append(
                    //         bsoncxx::builder::basic::kvp("packets",  fdoc["packets"].get_int32()),
                    //         bsoncxx::builder::basic::kvp("bytes",    fdoc["bytes"].get_int32()),
                    //         bsoncxx::builder::basic::kvp("duration", duration),
                    //         bsoncxx::builder::basic::kvp("entropy",  fdoc["entropy"].get_double())
                    //     );

                    //     flowsForML.append(flowDoc);
                    // }

                    // // ---- Call ML ----
                    // bsoncxx::builder::basic::document mlDoc;
                    // mlDoc.append(bsoncxx::builder::basic::kvp("flows", flowsForML));

                    // std::string mlPayload = bsoncxx::to_json(mlDoc.view());
                    // std::cout << "DEBUG: Calling ML service with payload: " << mlPayload << "\n";

                    // std::string mlResult = call_ml_service(mlPayload);

                    std::cout << "DEBUG: ML service response: " << mlResult << "\n";
                    std::cout << "DEBUG: ML response length: " << mlResult.length() << "\n";

                    if (mlResult.empty() || mlResult.find_first_not_of(" \t\n\r") == std::string::npos) {
                        std::cerr << "ERROR: ML service returned empty response\n";
                        //broadcast_to_dashboards(user_id, message);
                        try {
                            broadcast_to_dashboards(user_id, message);
                        } catch (const std::exception& broadcast_error) {
                            std::cerr << "⚠️ Broadcast error (non-fatal): " << broadcast_error.what() << "\n";
                        }
                        continue;
                    }

                    auto mlJson = bsoncxx::from_json(mlResult);
                    auto mlView = mlJson.view();

                    if (mlView.find("scores") == mlView.end()) {
                        try {
                            broadcast_to_dashboards(user_id, message);
                        } catch (const std::exception& broadcast_error) {
                            std::cerr << "⚠️ Broadcast error (non-fatal): " << broadcast_error.what() << "\n";
                        }
                        continue;
                    }

                    auto scores = mlView["scores"].get_array().value;

                    // ---- Build enriched ----
                    // ---- Build enriched JSON ----
                    bsoncxx::builder::stream::document enriched;

                    // ----- Convert timestamp to ISO8601 string -----
                    std::string timestampStr;
                    auto tsElem = view["timestamp"];

                    if (tsElem.type() == bsoncxx::type::k_date) {
                        // Real BSON date from production
                        auto ts = tsElem.get_date().value;
                        auto millis = ts.count();
                        std::time_t t = millis / 1000;
                        std::tm tm = *std::gmtime(&t);
                        char buffer[32];
                        std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &tm);
                        timestampStr = std::string(buffer);
                    } else if (tsElem.type() == bsoncxx::type::k_int32 || tsElem.type() == bsoncxx::type::k_int64) {
                        // Test data with integer timestamp
                        int64_t millis = (tsElem.type() == bsoncxx::type::k_int32) 
                            ? tsElem.get_int32().value 
                            : tsElem.get_int64().value;
                        std::time_t t = millis / 1000;
                        std::tm tm = *std::gmtime(&t);
                        char buffer[32];
                        std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &tm);
                        timestampStr = std::string(buffer);
                    } else {
                        // Fallback: use current time
                        auto now = std::chrono::system_clock::now();
                        std::time_t t = std::chrono::system_clock::to_time_t(now);
                        std::tm tm = *std::gmtime(&t);
                        char buffer[32];
                        std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &tm);
                        timestampStr = std::string(buffer);
                    }

                    auto ctx = enriched
                        << "timestamp" << timestampStr
                        << "sensorId"  << view["sensorId"].get_value()
                        << "summary"   << bsoncxx::builder::stream::open_document
                            << "totalPackets"      << summaryDoc["totalPackets"].get_int32()
                            << "totalBytes"        << summaryDoc["totalBytes"].get_int32()
                            << "activeFlows"       << summaryDoc["activeFlows"].get_int32()
                            << "anomaliesDetected" << anomaliesDetected
                        << bsoncxx::builder::stream::close_document
                        << "protocols" << view["protocols"].get_value()
                        << "anomalies" << view["anomalies"].get_value()
                        << "topFlows"  << bsoncxx::builder::stream::open_array;

                    int i = 0;
                    for (auto&& f : flowsInput) {
                        auto fdoc = f.get_document().value;
                        auto sdoc = scores[i].get_document().value;

                        double rawScore  = sdoc["anomalyScore"].get_double();
                        double normScore = normalize_anomaly(rawScore);

                        if (is_anomalous(normScore)) {
                            anomaliesDetected++;
                        }

                        bsoncxx::builder::basic::document flowWithML;

                        for (auto&& elem : fdoc) {
                            flowWithML.append(bsoncxx::builder::basic::kvp(elem.key(), elem.get_value()));
                        }

                        flowWithML.append(
                            bsoncxx::builder::basic::kvp("anomalyScore", normScore),
                            bsoncxx::builder::basic::kvp(
                                "anomalyLabel",
                                std::string(sdoc["anomalyLabel"].get_string().value)
                            )
                        );

                        ctx << flowWithML.extract();
                        i++;
                    }

                    // Close array and finalize
                    auto finalDoc = ctx << bsoncxx::builder::stream::close_array
                                        << bsoncxx::builder::stream::finalize;

                    std::string finalPayload = bsoncxx::to_json(finalDoc.view());

                    std::cout << "\n=== FINAL PAYLOAD SENT TO DASHBOARD ===\n";
                    std::cout << finalPayload << "\n";
                    std::cout << "=======================================\n";


                    //broadcast_to_dashboards(user_id, finalPayload);
                    try {
                        broadcast_to_dashboards(user_id, finalPayload);
                    } catch (const std::exception& broadcast_error) {
                        std::cerr << "⚠️ Broadcast error (non-fatal): " << broadcast_error.what() << "\n";
                    }
                }
                else {
                   // broadcast_to_dashboards(user_id, message);
                   try {
                        broadcast_to_dashboards(user_id, message);
                    } catch (const std::exception& broadcast_error) {
                        std::cerr << "⚠️ Broadcast error (non-fatal): " << broadcast_error.what() << "\n";
                    }
                }

            }


            
            msg_buffer.clear();
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Client handler error: " << e.what() << "\n";
        std::cerr << "STACK TRACE OCCURRED DURING MESSAGE:\n" << last_message << "\n";
        
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