#!/usr/bin/env python3

import argparse, requests, json, pprint
pp = pprint.PrettyPrinter(indent=1)

def cfListZones(u,H):
    # https://api.cloudflare.com/#zone-list-zones
    URL = "{}/client/v4/zones".format(u)
    page = 1
    RESULTS = []

    while page == 1 or R.json()["result_info"]["total_pages"] > R.json()["result_info"]["page"]:
        R = requests.get(
            URL,
            headers=H,
            params={
                "per_page": 50,
                "page": page
            }
        )
        RESULTS.extend(R.json()["result"])
        page = page + 1

    return RESULTS


def cfCreateZone(u,H,n,a):
    # https://support.cloudflare.com/hc/en-us/articles/360000841472#3Mk8dKAR73TTdEKH2WLfzb
    URL = "{}/client/v4/zones".format(u)
    D = {
        "account": {"id": a},
        "jump_start": False,
        "name": n,
        "type": "full"
    }
    R = requests.post(
        URL,
        headers=H,
        data=json.dumps(D)
    )
    # print(R.__dict__)
    # pp.pprint(R.json())
    return R.json()

def cfListDnsRecords(u,H,z):
    # https://api.cloudflare.com/#dns-records-for-a-zone-list-dns-records
    URL = "{}/client/v4/zones/{}/dns_records".format(u,z)
    page = 1
    RESULTS = []

    while page == 1 or R.json()["result_info"]["total_pages"] > R.json()["result_info"]["page"]:
        R = requests.get(
            URL,
            headers=H,
            params={
                "per_page": 50,
                "page": page
            }
        )

        if R.status_code == 403:
            print("[&] API token rejected. Check permissions.")
            exit(2)
        if R.json()["success"] is True and R.json()["result_info"]["total_count"] > 0:
            RESULTS.extend(R.json()["result"])
        else:
            return None
        page = page + 1

    return RESULTS

def cfMailSecurity(u,H,n,z,T,f):
    # https://api.cloudflare.com/#dns-records-for-a-zone-create-dns-record
    URL = "{}/client/v4/zones/{}/dns_records".format(u,z)
    D = {
        "TXT": {
            "spf": {
                "type": "TXT",
                "name": n,
                "content": "v=spf1 -all",
                "ttl": 1
            },
            "dmarc": {
                "type": "TXT",
                "name": "_dmarc.{}".format(n),
                "content": "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s;",
                "ttl": 1
            },
            "dkim": {
                "type": "TXT",
                "name": "*._domainkey.{}".format(n),
                "content": "v=DKIM1; p=",
                "ttl": 1
            }
        },
        "CNAME": {
            "parent": {
                "type": "CNAME",
                "name": "{}".format(n),
                "content": "{}".format(f),
                "ttl": 1,
                "proxied": True
            },
            "subdomains": {
                "type": "CNAME",
                "name": "*.{}".format(n),
                "content": "{}".format(f),
                "ttl": 1,
                "proxied": True
            }
        }
    }

    R = {}
    for recType,entry in D.items():
        for k,v in entry.items():
            update = False
            if T is not None and recType in T and v["name"] in T[recType]:
                print("[i] {} {} exists".format(v["name"],k))
                if v["content"] == T[recType][v["name"]]["content"]:
                    print("[i] {} content correct: {}".format(k, T[recType][v["name"]]["content"]))
                    continue
                else:
                    print("[!] {} incorrect content: {}".format(k, T[recType][v["name"]]["content"]))
                    update = True
                    record_id = T[recType][v['name']]["id"]

            print("[i] Creating {} {}".format(k, v["name"]))
            if update is False:
                R[k] = requests.post(
                    URL,
                    headers=H,
                    data=json.dumps(v)
                )
                if R[k].json()["success"] is True:
                    print("[i] {} {} successfully created".format(k, v["name"]))
                else:
                    print("[i] {} {} failed creation".format(k, v["name"]))
            else:
                R[k] = requests.patch(
                    "{}/{}".format(URL, record_id),
                    headers=H,
                    data=json.dumps(v)
                )
                if R[k].json()["success"] is True:
                    print("[i] {} {} successfully updated".format(k, v["name"]))
                else:
                    print("[i] {} {} failed update".format(k, v["name"]))

    return R

def cfListPageRules(u,H,z):
    # https://api.cloudflare.com/#page-rules-for-a-zone-list-page-rules
    URL = "{}/client/v4/zones/{}/pagerules".format(u,z)
    R = requests.get(
        URL,
        headers=H
    )

    if R.json()["success"] is True and len(R.json()["result"]) > 0:
        return R.json()["result"]
    elif R.json()["success"] is False:
        pp.pprint(R.json()["errors"])
        exit(2)
    else:
        return None

def cfCreatePageRules(u,H,n,z,f,P):
    URL = "{}/client/v4/zones/{}/pagerules".format(u,z)
    D = {
        "parent": {
            "targets": [{
                "target": "url",
                "constraint": {
                    "operator": "matches",
                    "value": "{}/".format(n)
                }
            }],
            "actions": [{
                "id": "forwarding_url",
                "value": {
                    "status_code": 301,
                    "url": "https://www.{}/".format(f)
                }
            }],
            "status": "active"
        },
        "subdomain": {
            "targets": [{
                "target": "url",
                "constraint": {
                    "operator": "matches",
                    "value": "*.{}/*".format(n)
                }
            }],
            "actions": [{
                "id": "forwarding_url",
                "value": {
                    "status_code": 301,
                    "url": "https://www.{}/".format(f)
                }
            }],
            "status": "active"
        }
    }

    R = {}
    for k,v in D.items():
        if P is not None and v["targets"][0]["constraint"]["value"] in P:
            print("[i] {} {} page rule exists; patching".format(n,k))
            update = True
            rule_id = P[v["targets"][0]["constraint"]["value"]]["id"]
        else:
            print("[i] Creating {} page rule".format(k))
            update = False

        if update is False:
            R[k] = requests.post(
                URL,
                headers=H,
                data=json.dumps(v)
            )
        else:
            R[k] = requests.patch(
                "{}/{}".format(URL,rule_id),
                headers=H,
                data=json.dumps(v)
            )

        if R[k].json()["success"] is True:
            print("[i] {} {} success".format(n,k))
        else:
            print("[!] {} {} failed".format(n,k))
            pp.pprint(R[k].json()["errors"])

    return R

def main(ARGS):
    URL = "https://api.cloudflare.com"
    with open(ARGS.TOKEN, 'r') as f:
        T = json.load(f)

    rZones = cfListZones(URL, T)
    Z = { zone["name"]:zone for zone in rZones }

    if ARGS.CREATE in Z:
        print("[i] {} exists: {}".format(ARGS.CREATE, Z[ARGS.CREATE]["id"]))
        rDnsRecords = cfListDnsRecords(
            URL, T,  Z[ARGS.CREATE]["id"]
        )

        if rDnsRecords is not None:
            orgDnsRecs = {}
            for rec in rDnsRecords:
                orgDnsRecs[rec["type"]] = {}
            for rec in rDnsRecords:
                orgDnsRecs[rec["type"]][rec["name"]] = rec
        else:
            orgDnsRecs = None

        pp.pprint(orgDnsRecs)
        rMailSecurity = cfMailSecurity(
            URL, T, ARGS.CREATE,
            Z[ARGS.CREATE]["id"],
            orgDnsRecs, ARGS.FORWARD
        )

        rListPageRules = cfListPageRules(
            URL, T, Z[ARGS.CREATE]["id"]
        )

        if rListPageRules is not None:
            pageRules = { rule["targets"][0]["constraint"]["value"]:rule for rule in rListPageRules }
        else:
            pageRules = None

        rCreatePageRules = cfCreatePageRules(
            URL, T, ARGS.CREATE,
            Z[ARGS.CREATE]["id"],
            ARGS.FORWARD, pageRules
        )

        for ns in Z[ARGS.CREATE]["name_servers"]:
            print("[i] {} name server: {}".format(ARGS.CREATE,ns))
    else:
        print("[!] {} missing".format(ARGS.CREATE))
        rCreateZone = cfCreateZone(
            URL, T, ARGS.CREATE, ARGS.ACCT
        )

        if rCreateZone["success"] is False:
            print("[&] {} failed to create".format(ARGS.CREATE))
            pp.pprint(rCreateZone)
            exit(2)
        else:
            rMailSecurity = cfMailSecurity(
                URL, T, ARGS.CREATE,
                rCreateZone["result"]["id"],
                None, ARGS.FORWARD
            )
            rCreatePageRules = cfCreatePageRules(
                URL, T, ARGS.CREATE,
                rCreateZone["result"]["id"],
                ARGS.FORWARD, None
            )
            for ns in rCreateZone["result"]["name_servers"]:
                print("[i] {} name server: {}".format(ARGS.CREATE,ns))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='script for parking a domain on Cloudflare'
    )
    parser.add_argument(
        '-t', action='store', required=True, dest='TOKEN',
        help='path to Cloudflare API token'
    )
    parser.add_argument(
        '-a', action='store', required=True, dest='ACCT',
        help='Cloudflare account ID'
    )
    parser.add_argument(
        '-c', action='store', required=True, dest='CREATE',
        help='Zone you want to create'
    )
    parser.add_argument(
        '-f', action='store', required=False, dest='FORWARD',
        help='Forwarding URL'
    )

    args = parser.parse_args()
    main(args)
