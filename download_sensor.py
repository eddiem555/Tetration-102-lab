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

import sys
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
        print(f"IP Address {value} can not be found. Error code {response.status_code}.")

#######################################################################
# Get available sensor platforms
######################################################################
def get_available_platforms(
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
    #response = restclient.get('/sw_assets/platforms')

    #response = restclient.download('tet-sensor-3.3.2.16-1.el7.x86_64.zip',
    #'/sw_assets/download?platform=CentOS-7.7&agent_type=enforcer&arch=x86_64')
    #print (json.dumps(response.json(), indent=2))
    # response = restclient.get("/sw_assets/download?platform=<platform>&agent_type=<agent_type>&pkg_type=<pkg_type>&arch=<arch>&list_version=<list_version>")
    response = restclient.download('/sw_assets/download?platform=CentOS-6.6&pkg_type=sensor_w_cfg&arch=x86_64&list_version=True')
    # SAMPLE '/sw_assets/download?platform=OracleServer-6.3&pkg_type=sensor_w_cfg&arch=x86_64&list_version=True'

    if response.status_code == 200:
        print (json.dumps(response.json(), indent=2))
        return response.json()

    # If response code is anything but 200, print error message with response code
    else:
        print(f"Error retrieving agent platforms: {response.status_code}.")



#######################################################################
# Utility function to accept numberical input or exit
######################################################################
def get_digit_input (input_str):
    print(" Q)  QUIT/CANCEL \n")
    inp = input(input_str)
    if not inp.isdigit():
        sys.exit()
    else:
        ret = int(inp)
    return ret

#######################################################################
# Allow user to choose sensor platform/type/arch to download
######################################################################
def sensor_chooser( platform_data ):

    agent_os_ver = 0

    print("\n Available Agent Platforms")
    print(" 1)  Windows (x86_64)")
    print(" 2)  CentOS or RedHat Linux 5.7 - 5.11 (x86_64)")
    print(" 3)  CentOS, RedHat or Oracle Linux 6.0 - 6.10 (x86_64)")
    print(" 4)  CentOS, RedHat or Oracle Linux 7.0 - 7.8 (x86_64)")
    print(" 5)  CentOS, RedHat or Oracle Linux 8.0 - 8.2 (x86_64)")
    print(" 6)  SUSE Linux 11.2 - 11.4 (x86_64)")
    print(" 7)  SUSE Linux 11.2 - 11.4 (s390) ALPHA")
    print(" 8)  SUSE Linux 12.0 - 12.5 (s390) ALPHA")
    print(" 9)  Universal Linux (amd64)")
    print(" 10) Universal Linux (386)")
    print(" 11) AIX (ppc)")
    print(" 12) Solaris (amd64)")
    agent_os_ver = get_digit_input(" Choose Tetration agent platform to download (1-12): ")

    print("\n Available Agent Types")
    print(" 1)  Deep Visibility Agent")
    print(" 2)  Enforcement Agent")
    agent_type = get_digit_input(" Choose agent type to download (1-2): ")

    agent_metadata = { "osversion":agent_os_ver, "type":agent_type }
    
    agent_list = [ { "option":None, "filename":None, "version":None, "type":None, "platform":None, "arch":None },
                   { "option":1, "filename":"tet-win-sensor-3.4.1.6.win64-tet-pov-rtp1.enforcer.zip",
                     "version":"3.4.1.6.win64-sensor", "type":"sensor", "arch":"x86_64" },
                   { "option":1, "filename":"tet-win-sensor-3.4.1.6.win64-tet-pov-rtp1.enforcer.zip",
                     "version":"3.4.1.6.win64-sensor", "type":"sensor", "arch":"x86_64" },
    ]

######################################################################
# MAIN
######################################################################
if __name__ == "__main__":

    # Get all sensors
    available_platforms = get_available_platforms()

    # Allow user to choose sensors
    #download_platform = sensor_chooser(available_platforms);
