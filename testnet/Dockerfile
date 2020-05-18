FROM ubuntu:18.04 AS build-env

# Set up dependencies
ENV PACKAGES curl make git libc-dev bash gcc python cmake g++ swig libboost-serialization-dev wget libgmp-dev

# Install minimum necessary dependencies, build tendermint DRB, remove packages
RUN apt update && \
	apt install -y $PACKAGES

# Set working directory for the build
WORKDIR /project

# add the pre-generated project to /project
ADD project.tar.gz /

# Install mcl
RUN wget https://github.com/herumi/mcl/archive/v1.05.tar.gz &&\
    tar xvf v1.05.tar.gz && cd mcl-1.05 && \
    make install

# Compile tendermint
WORKDIR /project

# install go - note we do NOT want to use FROM golang:buster as we need to build and run in the same environment
COPY go1.14.2.linux-amd64.tar.gz .
RUN tar -C /usr/local -xzf go1.14.2.linux-amd64.tar.gz

RUN export CGO_ENABLED=1 && \
    /usr/local/go/bin/go build -o build/tendermint ./cmd/tendermint/

# ######### Finished building tendermint executbales ##############
FROM ubuntu:18.04

RUN apt update && \
	apt install -y libboost-serialization netcat socat lsof

WORKDIR /tendermint

# Copy over binaries from the build-env
COPY --from=build-env /project/build/tendermint /usr/bin/tendermint
COPY --from=build-env /usr/local/lib/libmcl.so /usr/lib/libmcl.so
COPY --from=build-env /usr/local/lib/libmcl.a /usr/lib/libmcl.a

EXPOSE 26655-26658
EXPOSE 26654

COPY ./mytestnet/node0/data/priv_validator_state.json .
COPY run.sh .
