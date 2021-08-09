#!/usr/bin/env python3

import argparse
import boto3
import botocore.exceptions
import datetime
import pprint

pp = pprint.PrettyPrinter(indent=1)

def LIST_USERS():
    """
    list_users
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.list_users
    """
    r = IAMc.list_users()
    DATA = r['Users']
    while r["IsTruncated"] is True:
        r = IAMc.list_users(Marker=r["Marker"])
        DATA.extend(r['Users'])
    return DATA

def GET_LOGIN_PROFILE(U):
    """
    Check for console access
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.get_login_profile
    """
    DATA = []
    USERS = {}
    for u in U:
        USERS[u["UserName"]] = {"UserId":u["UserId"]}
        try:
            r = IAMc.get_login_profile(UserName=u["UserName"])
            DATA.append(r)
            USERS[u["UserName"]]["console_access"] = True
        except IAMc.exceptions.NoSuchEntityException as e:
            USERS[u["UserName"]]["console_access"] = False
    return DATA,USERS

def LIST_MFA_DEVICES(u):
    """
    Gather MFA devices assigned to user
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.list_mfa_devices
    """
    r = IAMc.list_mfa_devices(UserName=u["UserName"])
    DATA = r["MFADevices"]
    if r["MFADevices"]:
        return r,True
    else:
        return r,False

def LIST_ACCESS_KEYS(u):
    """
    Gather access keys for specified user
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.list_access_keys
    """
    r = IAMc.list_access_keys(UserName=u["UserName"])
    DATA = r['AccessKeyMetadata']
    while r["IsTruncated"] is True:
        r = IAMc.list_access_keys(Marker=r["Marker"])
        DATA.extend(r['AccessKeyMetadata'])
    return DATA

def GET_ACCESS_KEY_LAST_USED(k):
    """
    get_access_key_last_used
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.get_access_key_last_used
    """
    r = IAMc.get_access_key_last_used(AccessKeyId=k)
    # R["get_access_key_last_used"][u["UserName"]] = r
    # USERS[u["UserName"]]["access_keys"][state][k].update(r["AccessKeyLastUsed"])
    return r

def ORGANIZE_ACCESS_KEYS(K):
    """
    Concise organization for user keys
    """
    if K:
        DATA = {"active":{}, "inactive":{}}
        for k in K:
            if k["Status"] == "Active":
                DATA["active"].update({k["AccessKeyId"]: {"CreateDate":k["CreateDate"]}})
            elif k["Status"] == "Inactive":
                DATA["inactive"].update({k["AccessKeyId"]: {"CreateDate":k["CreateDate"]}})
    else:
        DATA = None
    return DATA

def main(c):
    R = {} # store JSON responses from API

    R["list_users"] = LIST_USERS()
    R["get_login_profile"],USERS = GET_LOGIN_PROFILE(R["list_users"])

    R["list_mfa_devices"] = {}
    R["list_access_keys"] = {}
    R["get_access_key_last_used"] = {}
    for u in R["list_users"]:
        R["list_mfa_devices"][u["UserName"]],USERS[u["UserName"]]["mfa"] = LIST_MFA_DEVICES(u)
        R["list_access_keys"][u["UserName"]] = LIST_ACCESS_KEYS(u)
        USERS[u["UserName"]]["access_keys"] = ORGANIZE_ACCESS_KEYS(R["list_access_keys"][u["UserName"]])
        if USERS[u["UserName"]]["access_keys"]:
            for state in ["active", "inactive"]:
                for k in USERS[u["UserName"]]["access_keys"][state].copy():
                    R["get_access_key_last_used"][u["UserName"]] = GET_ACCESS_KEY_LAST_USED(k)
                    USERS[u["UserName"]]["access_keys"][state][k].update(R["get_access_key_last_used"][u["UserName"]]["AccessKeyLastUsed"])

    # quick analysis
    # ANALYSIS = {"active_tokens_never_used":{}, "active_tokens_rotate_age":{}, "active_tokens_unused_90_days": {}, "console_without_mfa": {}}
    ANALYSIS = {}

    for u,data in USERS.copy().items():
        ANALYSIS.update({data["UserId"]:{}})
        # if user has console access without MFA, report
        if data["console_access"] is True and data["mfa"] is False:
            print("{}: [MFA] needs remediation".format(u))
            ANALYSIS[data["UserId"]]["console_without_mfa"] = True

        # if active key is older than 90 days
        if data["access_keys"] is not None:
            if data["access_keys"]["active"]:
                for k,d in data["access_keys"]["active"].items():
                    SINCE_CREATED = datetime.datetime.now(datetime.timezone.utc) - d["CreateDate"]
                    if "LastUsedDate" in d:
                        SINCE_USED = datetime.datetime.now(datetime.timezone.utc) - d["LastUsedDate"]
                        if SINCE_USED.days > 90:
                            # print("{} {} [API Token Unused] more than 90 days".format(u, k))
                            if "active_tokens_unused_90_days" in ANALYSIS[data["UserId"]]:
                                ANALYSIS[data["UserId"]]["active_tokens_unused_90_days"].append(k)
                            else:
                                ANALYSIS[data["UserId"]]["active_tokens_unused_90_days"] = [k]
                    else:
                        if SINCE_CREATED.days > 30:
                            # print("{} {} [API Token Unused] never used".format(u, k))
                            if "active_tokens_never_used" in ANALYSIS[data["UserId"]]:
                                ANALYSIS[data["UserId"]]["active_tokens_never_used"].append(k)
                            else:
                                ANALYSIS[data["UserId"]]["active_tokens_never_used"] = [k]
                    if SINCE_CREATED.days > 180:
                        # print("{} {} [API Token Age] older than 180 days".format(u, k))
                        if "active_tokens_rotate_age" in ANALYSIS[data["UserId"]]:
                            ANALYSIS[data["UserId"]]["active_tokens_rotate_age"].append(k)
                        else:
                            ANALYSIS[data["UserId"]]["active_tokens_rotate_age"] = [k]
                    # else:
                    #     print("{} {} [API Token Age] is compliant".format(u, k))
        if ANALYSIS[data["UserId"]]:
            ANALYSIS[data["UserId"]].update({"username":u})
        else:
            # remote entries for compliant users
            ANALYSIS.pop(data["UserId"])
    # pp.pprint(ANALYSIS)
    epoch = str(datetime.datetime.utcnow().timestamp()).split('.')[0]
    with open("{}-aws-users.json".format(epoch), 'w') as f:
        json.dump(ANALYSIS, f)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--profile", help="AWS profile from credentials file", type=str, action="store", default="default")
    args = parser.parse_args()
    s = boto3.Session(profile_name=args.profile)
    IAMc = s.client('iam')
    main(IAMc)
