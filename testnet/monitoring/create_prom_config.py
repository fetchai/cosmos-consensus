#!/usr/bin/env python3

# This file can be used to generate the prometheus.yml file in this directory
# for manually scraping pods

config_string = """

global:
  scrape_interval:     3s # By default, scrape targets every 15 seconds.

  # Attach these labels to any time series or alerts when communicating with
  # external systems (federation, remote storage, Alertmanager).
  external_labels:
    monitor: 'manual-prom-monitor'

# A scrape configuration containing exactly one endpoint to scrape:
# Here it's Prometheus itself.
scrape_configs:
  # The job name is added as a label `job=<job_name>` to any timeseries scraped from this config.
  - job_name: 'nodes'

    scrape_interval: 3s

    static_configs:
"""

static_config = """
    - targets: [ '{node_name}.{namespace}.svc.cluster.local:26660' ]
      labels:
        app: '{node_name}'
        kubernetes_namespace: '{namespace}'
"""

for i in range (0,30):
    config_string += static_config.format(node_name = f"node{i}", namespace = "nathan")

for i in range (0,30):
    config_string += static_config.format(node_name = f"node{i}", namespace = "jenny")

for i in range (0,30):
    config_string += static_config.format(node_name = f"sentry{i}", namespace = "james")
    config_string += static_config.format(node_name = f"node{i}", namespace = "james")
    config_string += static_config.format(node_name = f"validator{i}", namespace = "james")


with open("prometheus.yml", 'w') as myfile:
    myfile.write(config_string)

