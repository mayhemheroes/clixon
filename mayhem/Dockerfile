FROM ubuntu:22.04 AS builder

# For clixon and cligen
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y git git make build-essential gcc flex bison libcurl4-openssl-dev clang libssl-dev wget

# # nghttp2 dependencies
# RUN apk add --update nghttp2

# Create a directory to hold source-code, dependencies etc
RUN mkdir /clixon

RUN mkdir /clixon/build
WORKDIR /clixon

# Clone cligen at 6.5.0 (last version with time2str(struct timeval, ...) value semantics)
RUN git clone --depth=1 --branch 6.2.0 https://github.com/clicon/cligen.git

# Build cligen
WORKDIR /clixon/cligen
RUN ./configure --prefix=/install
RUN make
RUN make install

# www-data already exists in ubuntu:22.04

WORKDIR /
RUN wget https://github.com/nghttp2/nghttp2/releases/download/v1.51.0/nghttp2-1.51.0.tar.gz
RUN tar -xvf nghttp2-1.51.0.tar.gz
WORKDIR /nghttp2-1.51.0
RUN ./configure
RUN make -j8
RUN make install

# Copy Clixon from local dir
RUN mkdir /clixon/clixon
WORKDIR /clixon/clixon
COPY . /clixon/clixon
RUN ./configure --prefix=/install --with-cligen=/install --with-restconf=native --enable-nghttp2 --enable-http1
# Configure, build and install clixon

RUN make -j8
RUN make install
ENV LD_LIBRARY_PATH=/install/lib
RUN clang++ /clixon/clixon/mayhem/fuzz_clixon_trim.cpp -fsanitize=fuzzer,address -L /install/lib/ -lclixon -o /fuzz

FROM ubuntu:22.04 AS package
COPY --from=builder /install /install
COPY --from=builder /fuzz /fuzz_clixon_trim
ENV LD_LIBRARY_PATH=/install/lib
