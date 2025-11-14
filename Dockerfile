FROM amazonlinux:2023

RUN yum update -y && yum install -y \
    gcc-c++ \
    make \
    cmake \
    boost-devel \
    openssl-devel \
    libcurl-devel \
    git \
    tar \
    wget \
    && yum clean all

# Build MongoDB C driver from source
WORKDIR /tmp
RUN wget https://github.com/mongodb/mongo-c-driver/releases/download/1.24.4/mongo-c-driver-1.24.4.tar.gz && \
    tar -xzf mongo-c-driver-1.24.4.tar.gz && \
    cd mongo-c-driver-1.24.4 && \
    mkdir cmake-build && cd cmake-build && \
    cmake -DENABLE_AUTOMATIC_INIT_AND_CLEANUP=OFF .. && \
    make && make install

# Build MongoDB C++ driver
WORKDIR /tmp
RUN wget https://github.com/mongodb/mongo-cxx-driver/releases/download/r3.8.0/mongo-cxx-driver-r3.8.0.tar.gz && \
    tar -xzf mongo-cxx-driver-r3.8.0.tar.gz && \
    cd mongo-cxx-driver-r3.8.0/build && \
    cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local && \
    cmake --build . && \
    cmake --build . --target install

WORKDIR /app
COPY websocket_server.cpp .
COPY CMakeLists.txt .

RUN mkdir build && cd build && cmake .. && make

EXPOSE 8080

CMD ["./build/websocket_server"]