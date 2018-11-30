#!/usr/bin/python2i
#Importing the Libraries
import socket,nmap,os
import sys
import argparse
import mysql.connector
from netaddr import *i
from pyzabbix import ZabbixAPI

# Function to Pass IP as an argument and Iterate the IPs
def iterateIp(start_ip,end_ip=None):
    print ("The range of IP given below is:" ),
    r = None
    ip_list = list()
    if end_ip is not None:
        r = list(iter_iprange(start_ip, end_ip))
    else:
        r = list(IPNetwork(start_ip))
    for ip in r:
        print (str(ip))
        ip_list.append(str(ip))
    return ip_list

parser = argparse.ArgumentParser()
parser.add_argument('-i', dest='ip', help='Give an iprange e.g X.X.X.X-Y or X.X.X.X/Y')
results = parser.parse_args()
#print(results)
iprange = results.ip


# Create ZabbixAPI connection: Fetch Group IDs
ZabbixServer='http://15.213.248.33/zabbix'
zapi = ZabbixAPI(url=ZabbixServer, user='api-user', password='Zapi123')
Group_Win = zapi.hostgroup.get(filter={"name": "Windows_HG_API"}, output=["groupid"])
GroupId_Win = Group_Win[0]['groupid']
print('{0} {1}'.format("GroupID is for Windows is :", GroupId_Win))
Group_Lin = zapi.hostgroup.get(filter={"name": "Linux_HG_API"}, output=["groupid"])
GroupId_Lin = Group_Lin[0]['groupid']
print('{0} {1}'.format("GroupID is for Linux is :", GroupId_Lin))

# Checking the Hosts present in Discovered Hosts 
Group = zapi.hostgroup.get(filter={"name": "Discovered Hosts"}, output=["groupid"])
GroupId = Group[0]['groupid']
print('{0} {1}'.format("GroupID for Discovered Hosts is:", GroupId))
print("Getting the Hosts along with the Host IDs from the Host Group"),
