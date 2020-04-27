FROM golang:buster

RUN apt update -y && \
    apt upgrade  -y && \
    apt install -y curl jq file make git libgmp-dev wget gcc g++ swig && \
    git clone https://github.com/herumi/mcl && cd mcl && make install && ldconfig &&\
    echo "GOPRIVATE=github.com/fetchai/*" >> $HOME/.bashrc 

WORKDIR /source
CMD ["make", "build"]