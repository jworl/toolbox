#!/usr/bin/env python3

"""
Author: Joshua Worley

requires a json file containing API Key!
the path to this file should be specified in
arguement -t

expected format of JSON file:
{
    "Content-Type": "application/json",
    "X-Auth-Token": "Y0URSUP3RS3CRETK3Y/APIID"
}

Be wise: chmod 400 your json file.

Documentation:
    - https://developer.carbonblack.com/reference/carbon-black-cloud/platform-apis/
    - FYI: Threathunter = CB Cloud = Carbon Black EDR

"""

import argparse
import requests
import json
import pprint

pp = pprint.PrettyPrinter(indent=1)

parser = argparse.ArgumentParser(description='CB Uninstaller')
parser.add_argument('-o', action='store', required=True, dest='ORG_ID', help='CB Cloud org id')
parser.add_argument('-q', action='store', required=True, dest='QUERY', help='Lucene query string')
parser.add_argument('-u', action='store', required=True, dest='URL', help='CB Cloud URL')
parser.add_argument('-t', action='store', required=True, dest='TOKEN', help='Path to token file')

P = parser.parse_args()

def http(U, P, H, D):
    return requests.post("{}{}".format(U, P), headers=H, json=D)

def REMOVAL(R, U, A, H):
    for act in ["UNINSTALL_SENSOR", "DELETE_SENSOR"]:
        ACTION_DATA = {
            "action_type": act,
            "device_id": R
        }
        # pp.pprint(ACTION_DATA)
        UDR = http(U, A, H, ACTION_DATA)
        if not UDR.status_code == 204:
            print("[!] {} status code: {}".format(act, UDR.status_code))
            pp.pprint(UDR.json())
            return False

    return True

URL = P.URL
SEARCH = "appservices/v6/orgs/{}/devices/_search".format(P.ORG_ID)
ACTION = "appservices/v6/orgs/{}/device_actions".format(P.ORG_ID)

SEARCH_DATA = {
  "criteria": {
    "status": [
      "REGISTERED"
    ]
  },
  "query": P.QUERY,
  "sort": [
    {
      "field": "last_contact_time",
      "order": "ASC"
    }
  ]
}



with open(P.TOKEN) as f:
    HEADERS = json.load(f)

SDR = http(URL, SEARCH, HEADERS, SEARCH_DATA)

if SDR.json()['num_found'] == 0:
    print("[!] No results")
    exit(2)
else:
    print("[i] {} results".format(SDR.json()['num_found']))
    RESULTS = SDR.json()['results']
    # pp.pprint(RESULTS)

RM = []
for data in RESULTS:
    print("[i] {} {} {} {}".format(
        data['os'], data['name'],
        data['id'], data['uninstall_code']
    ))
    RM.append(data['id'])

if REMOVAL(RM, URL, ACTION, HEADERS) is False:
    print("[&] Failed to remove {}".format(RM))
else:
    print("[i] Successful removal of {}".format(RM))
