#!/usr/bin/env python3

import argparse
import subprocess
import sys
import os
import traceback
import ipdb
import fileinput
import shutil
from pathlib import Path

DOCKER_IMG_NAME="gcr.io/fetch-ai-sandbox/tendermint-drb"
DOCKER_IMG_TAG="no-tag-found"

# If this is true, deployments use :latest rather than the commit tag
USE_LATEST_TAG = False

#DOCKER_IMG_PULL_POLICY="Never"
DOCKER_IMG_PULL_POLICY="Always"
DOCKER_RESTART_POLICY="Always"

YAML_DIR = "yaml_files"
GRAFANA_DIR = "monitoring"

THIS_FILE_DIR = os.path.dirname(os.path.realpath(__file__))
os.chdir(THIS_FILE_DIR)

def parse_commandline():
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--validators', type=int, default=3, help='The number of validators for the network')
    parser.add_argument('-b', '--build-docker', action='store_true', help='Build the docker image then quit')
    parser.add_argument('-p', '--push-docker-img', action='store_true', help='Whether to push the docker image')
    parser.add_argument('-d', '--deploy-grafana', action='store_true', help='Whether to deploy prom + grafana')
    parser.add_argument('-r', '--remove-network', action='store_true', help='Unapply the network (yaml files)')
    parser.add_argument('-u', '--update-img-tag', action='store_true', help='Update the latest docker image with our commit tag (and push)')
    return parser.parse_args()

def get_docker_img_name():
    version = subprocess.check_output("git describe --always --dirty=_wip".split()).decode().strip()

    global DOCKER_IMG_TAG
    if USE_LATEST_TAG:
        DOCKER_IMG_TAG = "latest"
    else:
        DOCKER_IMG_TAG = version

def build_docker_image(args):

    executable_full_path = os.path.abspath("build_docker_img.sh")

    exit_code = subprocess.call([executable_full_path, DOCKER_IMG_NAME, DOCKER_IMG_TAG], cwd=THIS_FILE_DIR)

    if exit_code:
        print(exit_code)
        print("quitting due to exit code")
        sys.exit(1)

def push_docker_image(args):
    exit_code = subprocess.call(["docker", "push", DOCKER_IMG_NAME+":"+DOCKER_IMG_TAG], cwd=THIS_FILE_DIR)

    if exit_code:
        print(exit_code)
        print("quitting due to exit code")
        sys.exit(1)

def deploy_nodes():

    # Note: important to load the config before anything else
    pathlist = Path(YAML_DIR).glob('**/*config*.yaml')
    for path in pathlist:
        exit_code = subprocess.call(["kubectl", "apply", "-f", path])

        if exit_code:
            print(exit_code)
            print("quitting due to exit code")
            sys.exit(1)

    pathlist = Path(YAML_DIR).glob('**/*.yaml')
    for path in pathlist:
        exit_code = subprocess.call(["kubectl", "apply", "-f", path])

        if exit_code:
            print(exit_code)
            print("quitting due to exit code")
            sys.exit(1)

def deploy_grafana(args):

    pathlist = Path(GRAFANA_DIR).glob('**/*.yaml')
    for path in pathlist:
        exit_code = subprocess.call(["kubectl", "apply", "-f", path])

        if exit_code:
            print(exit_code)
            print("quitting due to exit code")
            sys.exit(1)

def create_files_for_validators(validators: int):

    # Ask tendermint to create the desired files
    exit_code = subprocess.call(["tendermint", "testnet", "--v", str(validators)], cwd=THIS_FILE_DIR)

    if exit_code:
        print(exit_code)
        print("quitting due to exit code")
        sys.exit(1)

    # perform a search and replace on the config files to turn on
    # metrics
    pathlist = Path("mytestnet").glob('**/config.toml')
    for path in pathlist:
        with fileinput.FileInput(path, inplace=True) as file:
            for line in file:
                print(line.replace("prometheus = false", "prometheus = true"), end='')

    # perform a search and replace on the genesis file to
    # extend the dkg length for bigger node sizes
    if validators >= 8:
        pathlist = Path("mytestnet").glob('**/genesis.json')
        for path in pathlist:
            with fileinput.FileInput(path, inplace=True) as file:
                for line in file:
                    print(line.replace('"aeon_length": "200"', '"aeon_length": "200"'), end='')

def create_network(validators: int):
    """Create a network of N validators
    in kubernetes. Note that the docker image
    should already be built
    """

    create_files_for_validators(validators)
    get_docker_img_name()
    populate_node_yaml(validators)
    deploy_nodes()

def populate_node_yaml(validators: int):

    # Wipe the directory
    if not os.path.exists(YAML_DIR):
        os.makedirs(YAML_DIR)
    else:
        shutil.rmtree(YAML_DIR)
        os.makedirs(YAML_DIR)

    # Now create the yaml for each node
    for i in range(0, validators):
        node_template = open("yaml_templates/node_yaml_template.txt").readlines()

        node_template = "".join(node_template)

        node_name = "node"+str(i)
        container_name = DOCKER_IMG_NAME+":"+DOCKER_IMG_TAG

        print(container_name)

        node_template = node_template.format(node = node_name, pull_policy=DOCKER_IMG_PULL_POLICY, container=container_name, restart_policy=DOCKER_RESTART_POLICY)

        with open("{}/{}.yaml".format(YAML_DIR, node_name), mode="w") as f:
            f.write(node_template)

        with open("{}/config_{}.yaml".format(YAML_DIR, node_name), mode="w") as f:
            cmd = f"kubectl create configmap config-{node_name} --from-file mytestnet/{node_name}/config -o yaml --dry-run"
            files_config = subprocess.check_output(cmd.split()).decode().strip()

            f.write(files_config)

# Delete statefulsets and persistentVolumeClaims with the tendermint-drb label (so only stuff we have deployed)
def remove_network():
    exit_code = subprocess.call(["kubectl", "delete", "sts,pods,pvc,svc", "-l", "networkName=tendermint-drb"])

    if exit_code:
        print(exit_code)
        print("quitting due to exit code")
        sys.exit(1)

def update_img_tag():
    exit_code = subprocess.call(f"docker tag {DOCKER_IMG_NAME} {DOCKER_IMG_NAME}:{DOCKER_IMG_TAG}".split())

    if exit_code:
        print(exit_code)
        print("quitting due to exit code")
        sys.exit(1)

def main():
    args = parse_commandline()

    get_docker_img_name()

    if args.remove_network:
        remove_network()
        sys.exit(0)

    if args.update_img_tag:
        update_img_tag()
        print("pushing docker image")
        push_docker_image(args)
        sys.exit(0)

    # Note: the docker build needs files created here
    create_files_for_validators(args.validators)

    # build the docker image
    if args.build_docker:
        build_docker_image(args)

        # optionally push
        if args.push_docker_img:
            print("pushing docker image")
            push_docker_image(args)
        sys.exit(0)

    populate_node_yaml(args.validators)
    deploy_nodes()

    # Optionally deploy grafana if doing locally
    if args.deploy_grafana:
        deploy_grafana(args)

if __name__ == '__main__':
    main()
