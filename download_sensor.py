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

#######################################################################
# Get version string given agent data
######################################################################
def download_agent(p_opt, t_opt):

    agent_metadata = [ { "option":None, "prefix":None, "suffix":None, "arch":None, "extension":None, "platform":None },
                       { "option":1, "prefix":"tet-win-sensor-", "suffix":".win64", "arch":"x86_64", "extension":".zip", "platform":"MSWindows10Pro" },
                       { "option":2, "prefix":"tet-sensor-", "suffix":".el5", "arch":"x86_64", "extension":".rpm", "platform":"CentOS-5.11" },
                       { "option":3, "prefix":"tet-sensor-", "suffix":".el6", "arch":"x86_64", "extension":".rpm", "platform":"CentOS-6.10" },
                       { "option":4, "prefix":"tet-sensor-", "suffix":".el7", "arch":"x86_64", "extension":".rpm", "platform":"CentOS-7.8" },
                       { "option":5, "prefix":"tet-sensor-", "suffix":".el8", "arch":"x86_64", "extension":".rpm", "platform":"CentOS-8.2" },
                       { "option":6, "prefix":"tet-sensor-", "suffix":".sles11", "arch":"x86_64", "extension":".rpm", "platform":"SUSELinuxEnterpriseServer-11.4" },
                       { "option":7, "prefix":"tet-sensor-", "suffix":".sles11", "arch":"s390x", "extension":".rpm", "platform":"SUSELinuxEnterpriseServer-11.4" },
                       { "option":8, "prefix":"tet-sensor-", "suffix":".sles12", "arch":"s390x", "extension":".rpm", "platform":"SUSELinuxEnterpriseServer-12.5" },
                       { "option":9, "prefix":"tet-sensor-lw-", "suffix":".lw-linux-amd64", "arch":"amd64", "extension":".zip", "platform":"linux-amd64" },
                       { "option":10, "prefix":"tet-sensor-lw-", "suffix":".lw-linux-386", "arch":"386", "extension":".zip", "platform":"linux-amd64" },
                       { "option":11, "prefix":"tet-sensor-lw-", "suffix":".lw-aix-ppc", "arch":"ppc", "extension":".zip", "platform":"AIX-7.2" },
                       { "option":12, "prefix":"tet-sensor-lw-", "suffix":".lw-solaris-amd64", "arch":"amd64", "extension":".zip", "platform":"AIX-7.2" } ]

    agent_platform = agent_metadata[p_opt]['platform']
    agent_arch = agent_metadata[p_opt]['arch']

    if t_opt == 1:
        agent_type = "sensor"
    else:
        agent_type = "enforcer"

    host=env.TET_HOST.get("host")
    api_key=env.TET_API_KEY
    api_sec=env.TET_API_SEC

    # Build URL
    url = f"https://{host}"
 
    restclient = RestClient(url,
                            api_key=api_key,
                            api_secret=api_sec,
                            verify=True)

    print (" Getting supported agent version...")
    get_ver_url = "/sw_assets/download?platform=" + agent_platform + "&agent_type=" + agent_type + "&arch=" + agent_arch + "&list_version=True"
    response = restclient.get(get_ver_url)

    if response.status_code == 200:
        versions = response.content.decode('utf-8').splitlines()
        agent_version = versions[0].strip()
    else:
        print(f"Error retrieving agent version: {response.status_code}.")

    # Now that we retrieved the supported version, we can form the complete filename
    agent_filename = agent_metadata[p_opt]['prefix'] + agent_version + agent_metadata[p_opt]['suffix'] + '.' + agent_arch + agent_metadata[p_opt]['extension']

    # Now that we have the filename, we can create the download URL
    download_url = "/sw_assets/download?platform=" + agent_platform + "&agent_type=" + agent_type + "&arch=" + agent_arch

    # Download agent
    print (" Downloading agent...")
    response = restclient.download(agent_filename, download_url)

    if not response.status_code == 200:
        print(f"Error retrieving agent version: {response.status_code}.")

    return agent_filename


#######################################################################
# Utility function to accept ranged numeric input or exit
######################################################################
def get_digit_input (minval, maxval, input_str):
    print(" Q)  QUIT/CANCEL \n")
    inp = input(input_str)
    if not inp.isdigit():
        # Assume q for any non-numeric and exit
        sys.exit()
    else:
        ret = int(inp)

    if (ret < minval or ret > maxval):
        print(f"Error: Input value outside of supported range")
        sys.exit()

    return ret

#######################################################################
# Allow user to choose sensor platform/type/arch to download
######################################################################
def agent_chooser( ):

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
    platform_opt = get_digit_input(1, 12, " Choose Tetration agent platform to download (1-12): ")

    print("\n Available Agent Types")
    print(" 1)  Deep Visibility Agent")
    print(" 2)  Enforcement Agent")
    type_opt = get_digit_input(1, 2, " Choose agent type to download (1-2): ")

    filename = download_agent(platform_opt, type_opt)

    return filename
    
######################################################################
# MAIN
######################################################################
if __name__ == "__main__":

    # Allow user to choose sensor
    agent_filename = agent_chooser();

    print (" Success! Look for "+ agent_filename + " in current directory\n")
