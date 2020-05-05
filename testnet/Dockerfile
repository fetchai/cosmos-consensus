FROM ubuntu:18.04 AS build-env

# Set up dependencies
ENV PACKAGES curl make git libc-dev bash gcc python cmake g++ swig libboost-all-dev wget libgmp-dev

# Install minimum necessary dependencies, build tendermint DRB, remove packages
RUN apt update && \
	apt install -y $PACKAGES

# Set working directory for the build
WORKDIR /project

# add the pre-generated project to /project
ADD project.tar.gz /

# Need to install MCL
RUN git clone https://github.com/herumi/mcl
RUN cd mcl && make install

# Compile tendermint
WORKDIR /project

# install go - note we do NOT want to use FROM golang:buster as we need to build and run in the same environment
COPY go1.14.2.linux-amd64.tar.gz .
#RUN wget https://dl.google.com/go/go1.14.2.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf go1.14.2.linux-amd64.tar.gz

RUN export CGO_ENABLED=1 && \
    /usr/local/go/bin/go build -o build/tendermint ./cmd/tendermint/

# ######### Finished building tendermint executbales ##############
FROM ubuntu:18.04

RUN apt update && \
	apt install -y libboost-all-dev netcat ucspi-tcp vim dnsutils iputils-ping libboost-all-dev

WORKDIR /tendermint

# Copy over binaries from the build-env
COPY --from=build-env /project/build/tendermint /usr/bin/tendermint

EXPOSE 26655-26658

COPY ./mytestnet/node0/data/priv_validator_state.json .
COPY run.sh .
