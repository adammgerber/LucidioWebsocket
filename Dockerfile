FROM amazonlinux:2023

# Install dependencies
RUN yum update -y && yum install -y \
    gcc-c++ \
    make \
    cmake \
    boost-devel \
    openssl-devel \
    git \
    tar \
    wget \
    && yum clean all

# Install MongoDB C driver
RUN yum install -y mongo-c-driver-devel

# Install MongoDB C++ driver
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

RUN mkdir build && cd build && \
    cmake .. && \
    make

EXPOSE 8080

CMD ["./build/websocket_server"]