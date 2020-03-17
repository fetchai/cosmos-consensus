FROM golang:buster AS build-env

# Set up dependencies
ENV PACKAGES curl make git libc-dev bash gcc python cmake g++ swig libgmp-dev

# Set working directory for the build
WORKDIR /tendermint-src

# Add source files
COPY . .

# Install minimum necessary dependencies, build Cosmos SDK, remove packages
RUN apt update && \
	apt install -y $PACKAGES

# Install mcl
RUN git clone --depth 1 https://github.com/herumi/mcl.git  && \
  cd mcl && \ 
  make install && \ 
  ldconfig

# Compile C++ Library
RUN cd beacon/beacon_cpp && \
	rm -Rf build && \
	mkdir build && \
	cd build && \
	cmake ../.. && \ 
	make TrustedDealer && \ 
	cd ../..

# Compile tendermint
WORKDIR /tendermint-src

RUN export CGO_ENABLED=1 && \
    go build -o build/tendermint ./cmd/tendermint/

# ######### Finished building tendermint executbales ##############
FROM debian:buster

# Install gmp for mcl
RUN apt update && \
	apt install -y libgmp-dev

WORKDIR /tendermint

# Copy over binaries from the build-env
COPY --from=build-env /tendermint-src/build/tendermint /usr/bin/tendermint
COPY --from=build-env /tendermint-src/beacon/beacon_cpp/build/TrustedDealer /usr/bin/TrustedDealer
COPY --from=build-env /usr/local/lib/libmcl.so /usr/local/lib/libmcl.so
RUN ldconfig


COPY ./deployments/tendermint_container/run-node.sh /usr/bin/run-node.sh

WORKDIR /tm_data
COPY ./deployments/tendermint_container/tm_data/ .

EXPOSE 26656
EXPOSE 26657
EXPOSE 26658
STOPSIGNAL SIGTERM

