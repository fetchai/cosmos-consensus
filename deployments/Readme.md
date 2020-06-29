## Run a constellation of 4 tendermint_drb nodes

### Requirements

You need to have **docker** and **docker-compose** installed.

For MAC, all you need is to install the [Docker Desktop](https://hub.docker.com/editions/community/docker-ce-desktop-mac)

For Ubuntu, I suggest of the following installation

```
# Installing docker
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh && rm get-docker.sh

#Installing docker-compose
sudo curl -L "https://github.com/docker/compose/releases/download/1.25.4/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

[Docker compose docs page](https://docs.docker.com/compose/install/)

If you want to run Docker as a non-root user, you should consider doing the following:

```
sudo usermod -aG docker $USER
```

A restart or a relog is probably required.

### Building the docker image

To build the tendermint_drb docker image, execute `./build_docker_img.sh`

You have to answer Local, if you are not building the image for cloud deployment

### Running the constellation

You can start the constellation by running: `docker-compose up`

You can clear all remaining running nodes by doing `docker-compose down`