#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Python example script showing Cisco Secure Workload (Tetration).

Copyright (c) 2020 Cisco and/or its affiliates.
This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at
               https://developer.cisco.com/docs/licenses
All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.
"""

import json
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from tetpyclient import RestClient

import env as env

# Disable insecure request warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

######################################################################
# Get sensors
######################################################################
def get_sensors(
    host=env.TET_HOST.get("host"),
    api_key=env.TET_API_KEY,
    api_sec=env.TET_API_SEC):

    # Build URL
    url = f"https://{host}"
 
    restclient = RestClient(url,
                            api_key=api_key,
                            api_secret=api_sec,
                            verify=True)

    # HTTP Get Request
    response = restclient.get("/sensors")

    # If successful response code return list sensors 
    if response.status_code == 200:
        return response.json()

    # If response code is anything but 200, print error message with response code
    else:
        print(f"Error code: {response.status_code} getting sensors: {response.content}")

######################################################################
# Print sensors
######################################################################
def print_sensors( sensor_data ):

    print ('\033[1m',"{:<20} {:<12} {:<20} {:<30}".format('HOSTNAME', 'TYPE','IP ADDRESS', 'PLATFORM'), '\033[0m')
    for sensor in sensor_data["results"]:
        sensor_hostname = sensor["host_name"]
        sensor_type = sensor["agent_type"]
        sensor_platform = sensor["platform"]

        for nic in sensor["interfaces"]:
            # If tags exist on this NIC we can assume this is the IP we want to print
            if nic["tags"]:
                sensor_ip = nic["ip"]

        print ("{:<20} {:<12} {:<20} {:<30}".format(sensor_hostname, sensor_type, sensor_ip, sensor_platform))

######################################################################
# MAIN 
######################################################################
if __name__ == "__main__":

    # Get all sensors
    sensors = get_sensors()

    # Print sensors
    print_sensors(sensors)
