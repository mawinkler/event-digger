#!/usr/bin/python3

DOCUMENTATION = """
---
module: antimalware_report.py

short_description: Queries Cloud One Workload Ssecurity for scheduled scan and
                   antimalware events within a given timeframe. Creates an
                   Excel file with the report.

description:
    - "TODO"

options:
    none

author:
    - Markus Winkler (markus_winkler@trendmicro.com)
"""

EXAMPLES = """
./antimalware_report.py
"""

RETURN = """
{'Eicar_test_file': {'k8sn3', 'k8sn2'},
 'Ransom_PETYA.A': {'k8sn3', 'k8sn2'},
 'Ransom_PETYA.E': {'k8sn3', 'k8sn2'},
 'TSPY_INFOSTEAL.XXF': {'k8sn2'},
 'Trojan.Win32.KILLAV.AF': {'k8sn2'},
 'computers': 12,
 'scan_count': 54,
 'scans_running': 0}
"""
import csv
import json
import pprint
import sys
import time
import datetime
import pandas as pd
from vincent.colors import brews

from datetime import date, datetime

import requests
import yaml
from requests import Session
from zeep import helpers
from zeep.client import Client
from zeep.transports import Transport

from elasticsearch import Elasticsearch, exceptions

# 794	Scheduled Malware Scan Failure Resolved
# 795	Scheduled Malware Scan Failure
# 796	Scheduled Malware Scan Task has been Missed
# 1527	Scheduled Malware Scan Cancellation In Progress
# 1528	Scheduled Malware Scan Cancellation Completed
# 1531	Scheduled Malware Scan Paused
# 1532	Scheduled Malware Scan Resumed
# 1547	Scheduled Malware Scan Task has been cancelled
SCHEDULED_MALWARE_SCAN_STARTED = 1523
SCHEDULED_MALWARE_SCAN_COMPLETED = 1524

SCAN_TYPE_SCHEDULED = "SCHEDULED"
SCAN_TYPE_ALL = "ALL"

es = Elasticsearch(['127.0.0.1:9200'])

pp = pprint.PrettyPrinter()
es_index = "test-index"

def get_paged_computers(api_key, host):
    paged_computers = []
    id_value, total_num = 0, 0
    max_items = 2000

    header = {"api-version": "v1", "api-secret-key": api_key}
    session_url = "https://" + host + "/api/computers/search"
    query = {"expand": "antiMalware"}

    try:
        while True:
            payload = {
                "maxItems": max_items,
                "searchCriteria": [
                    {
                        "idValue": id_value,
                        "idTest": "greater-than",
                    }
                ],
                "sortByObjectID": "true",
            }

            response = requests.post(
                session_url, headers=header, params=query, json=payload
            )
            computers = json.loads(response.content)
            if "message" in computers:
                sys.exit(computers["message"])

            num_found = len(computers["computers"])
            if num_found == 0:
                break

            for computer in computers["computers"]:
                paged_computers.append(computer)

            id_value = computers["computers"][-1]["ID"]

            if num_found == 0:
                break

            total_num = total_num + num_found

        return paged_computers

    except requests.exceptions.RequestException as e:
        return e


def get_indexed(data, index):
    indexed_data = {}
    for element in data:
        indexed_data[element[index]] = element

    return indexed_data


def get_computers_groups(api_key, host):
    session_url = "https://" + host + "/api/computergroups"
    headers = {"api-secret-key": api_key, "api-version": "v1"}

    try:
        response = requests.request("GET", session_url, headers=headers)
    except requests.exceptions.RequestException as e:
        return e

    computer_groups = response.json()
    indexed_computer_groups = {}
    for element in computer_groups["computerGroups"]:
        indexed_computer_groups[element["ID"]] = element

    return indexed_computer_groups


def get_policies(api_key, host):
    session_url = "https://" + host + "/api/policies"
    headers = {"api-secret-key": api_key, "api-version": "v1"}

    try:
        response = requests.request("GET", session_url, headers=headers)
    except requests.exceptions.RequestException as e:
        return e

    policies = response.json()
    return policies["policies"]


def add_computer_info(api_key, host, computers):
    computers_groups = get_computers_groups(api_key, host)
    policies = get_policies(api_key, host)
    indexed_policies = get_indexed(data=policies, index="ID")
    computer_info_list = []

    for computer in computers:
        computer_info = {
            "id": computer["ID"],
            "name": computer["hostName"],
            "os": computer["platform"],
            "am_mode": computer["antiMalware"]["state"],
        }
        if computer["groupID"] != 0:
            computer_info["group"] = computers_groups[computer["groupID"]]["name"]
        if "policyID" in computer:
            computer_info["policy"] = indexed_policies[computer["policyID"]]["name"]
        computer_info_list.append(
            computer_info,
        )

    return computer_info_list


def soap_auth(client, tenant, username, password):
    return client.service.authenticateTenant(
        tenantName=tenant, username=username, password=password
    )


def logout(client, sID):
    client.service.endSession(sID)
    return True


def create_event_id_filter(factory, id, operator):
    EnumOperator = factory.EnumOperator(operator)
    IDFilterTransport = factory.IDFilterTransport(id=id, operator=EnumOperator)
    return IDFilterTransport


def create_host_filter(factory, groupID, hostID, securityProfileID, enumType):
    EnumHostFilter = factory.EnumHostFilterType(enumType)
    HostFilterTransport = factory.HostFilterTransport(
        hostGroupID=groupID,
        hostID=hostID,
        securityProfileID=securityProfileID,
        type=EnumHostFilter,
    )
    return HostFilterTransport


def create_file_filter(factory, TimeRangeFrom, TimeRangeTo, TimeSpecific, type):
    Timetype = factory.EnumTimeFilterType(type)
    TimeFilterTransport = factory.TimeFilterTransport(
        rangeFrom=TimeRangeFrom,
        rangeTo=TimeRangeTo,
        specificTime=TimeSpecific,
        type=Timetype,
    )
    return TimeFilterTransport


def get_am_events(
    client,
    factory,
    timespan_from,
    timespan_to,
    tenant,
    username,
    password,
    indexed_computers,
    scan_type=SCAN_TYPE_ALL,
):
    sID = soap_auth(client, tenant, username, password)
    epochStart = datetime.strptime(timespan_from + " 00:00:00", "%m.%d.%Y %H:%M:%S")
    epochEnd = datetime.strptime(timespan_to + " 23:59:59", "%m.%d.%Y %H:%M:%S")

    events = []
    id_value, num_requests = 0, 0

    while True:
        try:
            amEvents = client.service.antiMalwareEventRetrieve(
                timeFilter=create_file_filter(
                    factory, epochStart, epochEnd, None, "CUSTOM_RANGE"
                ),
                hostFilter=create_host_filter(factory, None, None, None, "ALL_HOSTS"),
                eventIdFilter=create_event_id_filter(factory, id_value, "GREATER_THAN"),
                sID=sID,
            )
        except:
            logout(client, sID)
            break

        try:
            if amEvents["antiMalwareEvents"] != None:
                for event in amEvents["antiMalwareEvents"]["item"]:
                    eventID = event["scanType"]
                    if scan_type == SCAN_TYPE_ALL or scan_type == eventID:
                        format_event = {
                            "antiMalwareConfigID": event["antiMalwareConfigID"],
                            "antiMalwareEventID": event["antiMalwareEventID"],
                            "endTime": event["endTime"],
                            "errorCode": event["errorCode"],
                            "hostID": event["hostID"],
                            "infectedFilePath": event["infectedFilePath"],
                            "infectionSource": event["infectionSource"],
                            # "timestamp": time.mktime(event["logDate"]),
                            "timestamp": event["logDate"].timestamp(),
                            "logDate": event["logDate"],
                            # "logDate": event["logDate"].strftime("%m.%d.%Y %H:%M:%S"),
                            "malwareName": event["malwareName"],
                            "malwareType": event["malwareType"],
                            "protocol": event["protocol"],
                            "quarantineRecordID": event["quarantineRecordID"],
                            "scanResultAction1": event["scanResultAction1"],
                            "dscanResultAction2ata": event["scanResultAction2"],
                            "scanType": event["scanType"],
                            # "spywareItems": event["spywareItems"],
                            "startTime": event["startTime"],
                            "tags": event["tags"],
                            "scanAction1": event["scanAction1"],
                            "scanAction2": event["scanAction2"],
                            "summaryScanResult": event["summaryScanResult"],
                        }

                        if "hostID" in event:
                            if event["hostID"] in indexed_computers:
                                format_event["hostName"] = indexed_computers[
                                        event["hostID"]
                                    ]["name"]
                                if "group" in indexed_computers[event["hostID"]]:
                                    format_event["computerGroup"] = indexed_computers[
                                        event["hostID"]
                                    ]["group"]
                        if "computerGroup" not in format_event:
                            format_event["computerGroup"] = "None"

                        events.append(
                            format_event,
                        )

                id_value = amEvents["antiMalwareEvents"]["item"][-1]["antiMalwareEventID"]

                num_requests += 1
                if num_requests == 100:
                    logout(client, sID)
                    num_requests = 0
                    sID = soap_auth(client, tenant, username, password)
            else:
                logout(client, sID)
                break
        except Exception as e:
            print(e)
            logout(client, sID)
            break

    return events


def get_sys_events(
    client,
    factory,
    timespan_from,
    timespan_to,
    tenant,
    username,
    password,
    indexed_computers,
    event_id=0,
):
    sID = soap_auth(client, tenant, username, password)
    epochStart = datetime.strptime(timespan_from + " 00:00:00", "%m.%d.%Y %H:%M:%S")
    epochEnd = datetime.strptime(timespan_to + " 23:59:59", "%m.%d.%Y %H:%M:%S")

    events = []
    id_value, num_requests = 0, 0

    while True:
        try:
            sysEvents = client.service.systemEventRetrieve(
                timeFilter=create_file_filter(
                    factory, epochStart, epochEnd, None, "CUSTOM_RANGE"
                ),
                hostFilter=create_host_filter(factory, None, None, None, "ALL_HOSTS"),
                eventIdFilter=create_event_id_filter(factory, id_value, "GREATER_THAN"),
                includeNonHostEvents=True,
                sID=sID,
            )
        except:
            logout(client, sID)
            break

        try:
            if sysEvents["systemEvents"] != None:
                for event in sysEvents["systemEvents"]["item"]:
                    eventID = event["eventID"]
                    if event_id == 0 or event_id == eventID:
                        format_event = {
                            "actionPerformedBy": event["actionPerformedBy"],
                            "description": event["description"],
                            "event": event["event"],
                            "eventID": event["eventID"],
                            "eventOrigin": event["eventOrigin"],
                            "managerHostname": event["managerHostname"],
                            "systemEventID": event["systemEventID"],
                            "tags": event["tags"],
                            "target": event["target"],
                            "targetID": event["targetID"],
                            "targetType": event["targetType"],
                            # "timestamp": datetime.strptime(event["time"].strftime("%m.%d.%Y %H:%M:%S"), "%m.%d.%Y %H:%M:%S").timestamp(),
                            "timestamp": event["time"].timestamp(),
                            "time": event["time"],
                            "type": event["type"],
                        }

                        if "targetID" in event:
                            if event["targetID"] in indexed_computers:
                                if "group" in indexed_computers[event["targetID"]]:
                                    format_event["computerGroup"] = indexed_computers[
                                        event["targetID"]
                                    ]["group"]
                        if "computerGroup" not in format_event:
                            format_event["computerGroup"] = "None"

                        events.append(
                            format_event,
                        )

                id_value = sysEvents["systemEvents"]["item"][-1]["systemEventID"]

                num_requests += 1
                if num_requests == 100:
                    logout(client, sID)
                    num_requests = 0
                    sID = soap_auth(client, tenant, username, password)
            else:
                logout(client, sID)
                break
        except Exception as e:
            print(e)
            logout(client, sID)
            break

    return events

def getSystemEventID(element):
    return element["systemEventID"]



# Elastic Search
def load_data_in_es(data):
    """ creates an index in elasticsearch """
    print("Loading data in elasticsearch ...")
    index=1
    for entry in data:
        res = es.index(index=es_index, doc_type="event", id=entry['timestamp'], body=entry)
        index += 1
    print("Total events loaded: ", len(data))

def safe_check_index(index, retry=3):
    """ connect to ES with retry """
    if not retry:
        print("Out of retries. Bailing out...")
        sys.exit(1)
    try:
        status = es.indices.exists(index)
        return status
    except exceptions.ConnectionError as e:
        print(e)
        print("Unable to connect to ES. Retrying in 5 secs...")
        time.sleep(5)
        safe_check_index(index, retry-1)

def check_and_load_index(data):
    """ checks if index exits and loads the data accordingly """
    # if not safe_check_index(es_index):
    #     print("Index not found...")
    load_data_in_es(data)


def main():

    # Read configuration
    with open("config.yml", "r") as ymlfile:
        cfg = yaml.load(ymlfile, Loader=yaml.FullLoader)

    host = cfg["deepsecurity"]["server"]
    username = cfg["deepsecurity"]["username"]
    password = cfg["deepsecurity"]["password"]
    api_key = cfg["deepsecurity"]["api_key"]
    tenant = cfg["deepsecurity"]["tenant"]
    timespan_from = cfg["deepsecurity"]["timespan_from"]
    timespan_to = cfg["deepsecurity"]["timespan_to"]

    print("Retrieving computers...")
    computers = get_paged_computers(api_key, host)

    computers_info = add_computer_info(api_key, host, computers)
    indexed_computers = get_indexed(data=computers_info, index="id")

    session = Session()
    session.verify = True
    transport = Transport(session=session, timeout=1800)
    url = "https://{0}/webservice/Manager?WSDL".format(host)
    client = Client(url, transport=transport)
    factory = client.type_factory("ns0")

    ###
    # Anti Malware Findings (Within scheduled scans only)
    ###
    print("Retrieving system events")
    sys_events = get_sys_events(
        client,
        factory,
        timespan_from,
        timespan_to,
        tenant,
        username,
        password,
        indexed_computers,
    )

    print("Retrieving anti malware events")
    am_events = get_am_events(
        client,
        factory,
        timespan_from,
        timespan_to,
        tenant,
        username,
        password,
        indexed_computers,
    )

    ###
    # Creating Result Sets
    ###
    results = []
    for event in sys_events:
        results.append(event)
    for event in am_events:
        results.append(event)

    check_and_load_index(results)

if __name__ == "__main__":
    main()
