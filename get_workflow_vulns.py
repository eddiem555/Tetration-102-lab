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
# Generic function that takes get request URI and returns json
######################################################################
def get_tet_json(request_str,
    host=env.TET_HOST.get("host"),
    api_key=env.TET_API_KEY,
    api_sec=env.TET_API_SEC):

    # Build URL
    url = f"https://{host}"
 
    restclient = RestClient(url,
                            api_key=api_key,
                            api_secret=api_sec,
                            verify=False)

    # Get Request
    response = restclient.get(request_str)

    # If successful response code return list sensors 
    if response.status_code == 200:
        #print ("DEBUG GET:", json.dumps(response.json(), indent=2))
        return response.json()

    # If response code is anything but 200, print error message with response code
    else:
        print(f"Error processing GET request on {request_str}. Error code: {response.status_code}.")


######################################################################
# Print packages
######################################################################
def get_vulnerabilities ( sensor_data, v3_min_score ):

    for sensor in sensor_data["results"]:
        sensor_hostname = sensor["host_name"]
        sensor_uuid = sensor["uuid"]
        for nic in sensor["interfaces"]:
            # If tags exist on this NIC we can assume this is the IP we want to print
            if nic["tags"]:
                sensor_ip = nic["ip"]

        vulnerabilities = get_tet_json("/workload/" + sensor_uuid + "/vulnerabilities");

        # If CVSS score >= <v3_min_score>, print the CVE ID, scores, package name and version
        print ("\n")
        print ("{:<18} {:<16} {:<16} {:<10} {:<10} {:<16} {:20}".format(
               'HOSTNAME', 'IP', 'CVE ID', 'SCORE(V2)', 'SCORE(V3)', 'PACKAGE', 'VERSION'))
        for vul in vulnerabilities:
            if ( vul['v3_score'] >= v3_min_score):
                print ("{:<18} {:16} {:<16} {:<10} {:<10} {:<16} {:20}".format(
                       sensor_hostname, sensor_ip, vul['cve_id'], vul['v2_score'], vul['v3_score'],
                       vul['package_infos'][0]['name'], vul['package_infos'][0]['version']))

######################################################################
# MAIN 
######################################################################
if __name__ == "__main__":

    # Get all sensors
    sensors = get_tet_json("/sensors")

    # For each sensor print vulnerabilities found with CVSS score >= <min_score>
    v3_min_score = 8.0
    get_vulnerabilities(sensors, v3_min_score)
