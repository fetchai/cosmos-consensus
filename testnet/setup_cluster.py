#!/usr/bin/env python3

import argparse
import subprocess
import sys
import os
import traceback
import ipdb
import fileinput
from pathlib import Path

DOCKER_IMG_NAME="gcr.io/fetch-ai-sandbox/tendermint-drb"
DOCKER_IMG_TAG="no-tag-found"

DOCKER_IMG_PULL_POLICY="Never"
#DOCKER_IMG_PULL_POLICY="Always"

YAML_DIR = "yaml_files"
GRAFANA_DIR = "monitoring"

def parse_commandline():
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--validators', type=int, default=3, help='The number of validators for the network')
    parser.add_argument('-n', '--no-build-docker', action='store_true', help='Do not build the docker image')
    parser.add_argument('-p', '--push-docker-img', action='store_false', help='Whether to push the docker image')
    parser.add_argument('-d', '--deploy-grafana', action='store_true', help='Whether to deploy prom + grafana also')
    return parser.parse_args()

def get_docker_img_name():
    version = subprocess.check_output("git describe --always --dirty=_wip".split()).decode().strip()

    global DOCKER_IMG_TAG
    DOCKER_IMG_TAG = version

def build_docker_image(args):

    executable_full_path = os.path.abspath("build_docker_img.sh")

    exit_code = subprocess.call([executable_full_path, DOCKER_IMG_NAME, DOCKER_IMG_TAG], cwd=os.getcwd())

    if exit_code:
        print(exit_code)
        print("quitting due to exit code")
        sys.exit(1)

def push_docker_image(args):
    exit_code = subprocess.call(["docker", "push", DOCKER_IMG_NAME+":"+DOCKER_IMG_TAG], cwd=os.getcwd())

    if exit_code:
        print(exit_code)
        print("quitting due to exit code")
        sys.exit(1)

def deploy_nodes():

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
    exit_code = subprocess.call(["tendermint", "testnet", "--v", str(validators)], cwd=os.getcwd())

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
    # Now create the yaml for each node
    for i in range(0, validators):
        node_template = open("yaml_templates/node_yaml_template.txt").readlines()

        node_template = "".join(node_template)

        node_name = "node"+str(i)

        node_template = node_template.format(node = node_name, pull_policy=DOCKER_IMG_PULL_POLICY)

        if not os.path.exists(YAML_DIR):
                os.makedirs(YAML_DIR)

        with open("{}/{}.yaml".format(YAML_DIR, node_name), mode="w") as f:
            f.write(node_template)

        with open("{}/config_{}.yaml".format(YAML_DIR, node_name), mode="w") as f:
            cmd = f"kubectl create configmap config-{node_name} --from-file mytestnet/{node_name}/config -o yaml --dry-run"
            files_config = subprocess.check_output(cmd.split()).decode().strip()

            f.write(files_config)


def main():
    args = parse_commandline()

    # Note: the docker build needs files created here
    create_files_for_validators(args.validators)

    get_docker_img_name()

    # first build the docker image
    if not args.no_build_docker:
        build_docker_image(args)

        # optionally push
        if args.push_docker_img:
            push_docker_image(args)

    populate_node_yaml(args.validators)
    deploy_nodes()

    # Optionally deploy grafana if doing locally
    if args.deploy_grafana:
        deploy_grafana(args)

if __name__ == '__main__':
    try:
        main()
    except:
        extype, value, tb = sys.exc_info()
        traceback.print_exc()
        ipdb.post_mortem(tb)
