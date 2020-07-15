#!/usr/bin/env python3

import argparse
import subprocess
import sys
import os
import traceback
import ipdb
import fileinput
import shutil
import time
from pathlib import Path

DOCKER_HOST="gcr.io/fetch-ai-sandbox/"
DOCKER_IMG_NAME=DOCKER_HOST+"tendermint-drb"
DOCKER_IMG_TAG="no-tag-found"
TRADER_CONTAINER = DOCKER_HOST+"traders:latest"

# Whether to supress stdout when calling programs like kubectl
SILENT_MODE=False
STDOUT_DEFAULT=None if True else subprocess.DEVNULL

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
    parser.add_argument('-v', '--validators', type=int, default=0, help='Create a network witn N validators')
    parser.add_argument('-b', '--build-docker', action='store_true', help='Build the docker image')
    parser.add_argument('-p', '--push-docker-img', action='store_true', help='Whether to push the docker image after building')
    parser.add_argument('-d', '--deploy-grafana', action='store_true', help='Deploy prom + grafana')
    parser.add_argument('-r', '--remove-network', action='store_true', help='Unapply the network (yaml files)')
    parser.add_argument('-u', '--update-img-tag', action='store_true', help='Update the latest docker image with our commit tag (and push)')
    parser.add_argument('-t', '--traders', action='store_true', help='Deploy a traders (sends lots of TXs) container targeting N validators (need to specify with -v flag)')
    parser.add_argument('-a', '--adjust-network-size', type=int, default=-1, help='Adjust the network down to N nodes (remove)')
    parser.add_argument('-y', '--restore-network-size', type=int, default=-1, help='Return the network to N nodes (reapply yaml)')
    parser.add_argument('-c', '--clear-network-delays', action='store_true', help='Clear network delays - must also be done before setting any network delays')
    parser.add_argument('-n', '--network-delays', action='append', nargs=3, help='Create network delays in ms when used in the format (pods) node1-0 node2-0 100ms (node1-0 -> node2-0 delay)')
    # TODO(HUT): correct this.
    parser.add_argument('-x', '--send-html', action='append', nargs="*", help='Send html string to node. Format: node0-0 index.html')
    parser.add_argument('-l', '--log-level', type=str, default="", help='Change node log level. Uses Tendermint log level format e.g. beacon:info')
    parser.add_argument('-f', '--config', type=str, default="", help="Modifications to config file with as a comma separated list of variable_name:new_value")
    return parser.parse_args()

# Helper function to run commands in their directory, optionally silently (set by STDOUT_DEFAULT)
def run_command(command: str, command_args: str = ""):

    return_obj = subprocess.run([command, *command_args.split()], cwd=THIS_FILE_DIR, stdout=STDOUT_DEFAULT)

    if return_obj.returncode:
        print(f"Failed to run command {command} {command_args}, error code: {return_obj.returncode}")
        sys.exit(1)

# Check that the docker image your network is to use actually has it at the remote
# to avoid an image pull error
def docker_img_remote(remote_name: str):

    for i in range(0,10):
        return_obj = subprocess.run(["docker", "pull", remote_name])
        if return_obj.returncode == 0:
            return True
        print("Failed to find image at remote. The deployment might fail! Will retry...", file=sys.stderr)
        time.sleep(30)
    return False

def get_docker_img_name():
    version = subprocess.check_output("git describe --always --dirty=_wip".split()).decode().strip()

    global DOCKER_IMG_TAG
    if USE_LATEST_TAG:
        DOCKER_IMG_TAG = "latest"
    else:
        DOCKER_IMG_TAG = version

def build_docker_image(args):
    executable_full_path = os.path.abspath("build_docker_img.sh")
    run_command(executable_full_path, f"{DOCKER_IMG_NAME} {DOCKER_IMG_TAG}")

# Note: this will also push the image
def build_traders_img(args):
    executable_full_path = os.path.abspath(f"{THIS_FILE_DIR}/traders/build_docker_img.sh")
    run_command(executable_full_path)

def deploy_traders(validators: int):

    trader_template = open("yaml_templates/trader_yaml_template.txt").readlines()

    trader_template = "".join(trader_template)

    # Must be of the format "node0", "node1"... etc
    trader_args_spaced = ", ".join(['"node'+str(x)+'"' for x in range(0,validators)])

    trader_template = trader_template.format(pull_policy=DOCKER_IMG_PULL_POLICY, container=TRADER_CONTAINER, restart_policy=DOCKER_RESTART_POLICY, trader_args=trader_args_spaced)

    trader_file = "{}/{}.yaml".format(YAML_DIR, "trader")

    with open(trader_file, mode="w") as f:
        f.write(trader_template)

    run_command("kubectl", f"apply -f {trader_file}")

def adjust_network_size(new_size: int):

    pathlist = Path(YAML_DIR).glob('**/node*.yaml')
    for path in pathlist:
        node_number = int(str(path).split('node')[1].split('.yaml')[0])

        if node_number >= new_size:
            run_command("kubectl", f"delete -f {path}")

def restore_network_size(new_size: int):

    pathlist = Path(YAML_DIR).glob('**/node*.yaml')
    for path in pathlist:
        node_number = int(str(path).split('node')[1].split('.yaml')[0])

        if node_number <= new_size - 1:
            run_command("kubectl", f"apply -f {path}")

def push_docker_image(args):
    run_command("docker", f"push {DOCKER_IMG_NAME}:{DOCKER_IMG_TAG}")

def deploy_nodes():

    # Note: important to load the config before anything else
    pathlist = Path(YAML_DIR).glob('**/*config*.yaml')
    for path in pathlist:
        run_command("kubectl", f"apply -f {path}")

    pathlist = Path(YAML_DIR).glob('**/*.yaml')
    for path in pathlist:
        run_command("kubectl", f"apply -f {path}")

def deploy_grafana(args):

    pathlist = Path(GRAFANA_DIR).glob('**/*.yaml')
    for path in pathlist:
        run_command("kubectl", f"apply -f {path}")

def create_files_for_validators(validators: int, log_level : str = "", config : str = ""):

    # Ask tendermint to create the desired files
    run_command("tendermint", f"testnet --v {validators}")

    # perform a search and replace on the config files to turn on
    # metrics
    pathlist = sorted(Path("mytestnet").glob('**/config.toml'))
    i = 0
    for path in pathlist:
        with fileinput.FileInput(str(path), inplace=True) as file:
            for line in file:
                for new_variable in config.split(","):
                    if len(new_variable) == 0:
                        continue
                    new_variable_pair = new_variable.split(":")
                    if line.startswith(new_variable_pair[0]):
                        line = f"{new_variable_pair[0]} = {new_variable_pair[1]}\n"
                        break
                if log_level != "" and "log_level" in line:
                    print(line.replace('log_level = "main:info,state:info,*:error"', f'log_level = "{log_level},main:info,state:info,*:error"'), end='')
                else:
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
    run_command("kubectl", "delete sts,pods,pvc,svc -l networkName=tendermint-drb")

def update_img_tag():
    run_command("docker", f"tag {DOCKER_IMG_NAME} {DOCKER_IMG_NAME}:{DOCKER_IMG_TAG}")

def check_node_ready(node: str):

    for i in range(0,100):
        response = ""

        # Use JSONPATH to query kubernetes for a pod's status
        try:
            response = subprocess.check_output(("kubectl get pods -o=jsonpath='{.items[?(@.metadata.name==\""+node+"\")].status.conditions[1].type}'").split(), stderr=subprocess.DEVNULL).decode().strip()
        except:
            pass

        if 'Ready' in response:
            return
        elif i >= 50:
            print("Waited too long for pod to become ready!", file=sys.stderr)
            sys.exit(1)
        else:
            print(f"Waiting for pod {node} to become ready. Got response: '{response}'")
            time.sleep(5)

def run_on_pods(command: str, nodes: list):

    parsed = []

    if nodes[0] == "*":
        response = subprocess.check_output("kubectl get pods".split()).decode().strip()

        for line in response.split('\n'):
            if 'node' in line:
                parsed = [*parsed, line.split()[0]]
    else:
        parsed = nodes

    print(f"Running \"{command}\" on nodes {parsed}")

    # Note that nodes must be online - this will be checked here to avoid
    # race conditions
    for node in parsed:
        check_node_ready(node)
        run_command("kubectl", f"exec {node} {command}")

def do_network_delays(delays: list):

    # For speed, collect all the delays one node is to have and submit
    # it in bulk (if the delay is always the same)
    commands = {}
    default_delay = delays[0][2]
    for desired_delay in delays:
        node_from = desired_delay[0]
        node_to   = desired_delay[1].split('-')[0] # Need the DNS name of the node here
        delay     = desired_delay[2]

        if not 'node' in node_from or not 'node' in node_to or not 'ms' in delay:
            print("Incorrect args when setting delay: use the format node0-0 node1-0 100ms. Make sure to specify by pod.")
            sys.exit(1)

        if delay != default_delay:
            run_on_pods(f"/tendermint/network_control.sh delay {delay} {node_to}", nodes=[node_from])
            continue

        if node_from not in commands:
            commands[node_from] = f"/tendermint/network_control.sh delay {delay} "

        commands[node_from] += f" {node_to}"

    for key, value in commands.items():
        run_on_pods(value, nodes=[key])

def send_html(args: list):
    # Args is a list of lists
    for arg in args:
        run_on_pods(" ".join(arg[1:]), nodes=[arg[0]])

def main():
    args = parse_commandline()

    get_docker_img_name()

    if args.send_html:
        send_html(args.send_html)
        sys.exit(0)

    if args.clear_network_delays:
        run_on_pods("/tendermint/network_control.sh reset", nodes=["*"])
        sys.exit(0)

    if args.network_delays:
        do_network_delays(args.network_delays)
        sys.exit(0)

    if args.traders:
        if args.validators <= 0:
            print("Please specify how many validators/nodes for the trader to target")
            sys.exit(1)
        build_traders_img(args)
        deploy_traders(args.validators)
        sys.exit(0)

    if args.adjust_network_size > 0:
        adjust_network_size(args.adjust_network_size)
        sys.exit(0)

    if args.restore_network_size > 0:
        restore_network_size(args.restore_network_size)
        sys.exit(0)

    if args.remove_network:
        remove_network()
        sys.exit(0)

    if args.update_img_tag:
        update_img_tag()
        print("pushing docker image")
        push_docker_image(args)
        sys.exit(0)

    # Note: the docker build needs files created here
    create_files_for_validators(args.validators, args.log_level, args.config)

    # build the docker image
    if args.build_docker:
        build_docker_image(args)

        # optionally push
        if args.push_docker_img:
            print("pushing docker image")
            push_docker_image(args)
        sys.exit(0)

    # At this point it is deploy-network mode
    if args.validators <= 0:
        print("Please specify how many validators/nodes for the trader to target")
        sys.exit(1)

    container_location = f"{DOCKER_IMG_NAME}:{DOCKER_IMG_TAG}"
    if not docker_img_remote(container_location):
        print(f"Attempting to set up a network with container: {container_location}, \
                but this does not exist at remote. Build and upload the image with -b -u or retag it with -u.", file=sys.stderr)
        sys.exit(1)

    populate_node_yaml(args.validators)
    deploy_nodes()

    # Optionally deploy grafana if doing locally
    if args.deploy_grafana:
        deploy_grafana(args)

if __name__ == '__main__':
    main()
