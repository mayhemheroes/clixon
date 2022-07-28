FROM alpine as builder

# For clixon and cligen
RUN apk add --update git make build-base gcc flex bison curl-dev

# nghttp2 dependencies
RUN apk add --update nghttp2

# Create a directory to hold source-code, dependencies etc
RUN mkdir /clixon

RUN mkdir /clixon/build
WORKDIR /clixon

# Clone cligen
RUN git clone https://github.com/clicon/cligen.git

# Build cligen
WORKDIR /clixon/cligen
RUN ./configure --prefix=/install
RUN make
RUN make install

# Need to add www user manually
RUN adduser -D -H -G www-data www-data

# Copy Clixon from local dir
RUN mkdir /clixon/clixon
WORKDIR /clixon/clixon
COPY . /clixon/clixon

# Configure, build and install clixon
RUN ./configure --prefix=/install --with-cligen=/install --with-restconf=native --enable-nghttp2 --enable-http1

RUN make
RUN make install

FROM alpine as package
COPY --from=builder /install /install
ENV LD_LIBRARY_PATH=/install/lib
