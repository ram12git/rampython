#!/usr/bin/python3.6
import socket,nmap,os
import paramiko
import sys
from argparse import ArgumentParser
from netaddr import *
from pyzabbix import ZabbixAPI
from scp import SCPClient

def secureConn():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect('15.213.248.31', username='provision')
    print ("Connecting to the Remote Server" )
    scp = SCPClient(client.get_transport())
    scp.put('/home/georgbij/zabbix_api/linux_list.txt', recursive=False, remote_path='/home/provision/ansible1/')
    #cmd = 'mkdir /tmp/farhan'
    cmd = '/home/provision/ansible1/ssh.py'
    #client.exec_command('python /home/provision/ansible1/ssh.py >> /home/provision/ansible1/python_log.txt ')
    #client.exec_command("os.system('python /home/provision/ansible1/ssh.py')")
    client.exec_command(cmd)
    client.exec_command('ansible-playbook -i /home/provision/ansible1/ping.txt /home/provision/ansible1/rk.yml >> /home/provision/ansible1/ansible_log.txt')
    client.close()


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

parser = ArgumentParser()
parser.add_argument('-i', dest='ip', help='Give an iprange e.g X.X.X.X-Y or X.X.X.X/Y')
results = parser.parse_args()
iprange = results.ip


def hostDetection():
    if os.path.exists("output.txt"):
        print("Removing file output.txt!")
        os.remove("output.txt")
    else:
        print("output.txt file doesn't exist")
    if os.path.exists("linux_list.txt"):
        print("Removing file linux_list.txt!")
        os.remove("linux_list.txt")
    else:
        print("linux_list.txt file doesn't exist")
    nm = nmap.PortScanner()
    if (os.getuid() == 0):
        print('----------------------------------------------------')
        nm.scan(hosts=iprange, arguments="-O")
        print(nm.all_hosts())
        for host in nm.all_hosts():
             if 'osmatch' in nm[host]:
                 print(host , file=open("output.txt", "a"))
                 linux_list = set()
                 for osmatch in nm[host]['osmatch']:
                     print('{0} : {1}'.format(host,osmatch['name'])),
                     print('')
                     if "Windows" in osmatch['name']:
                         print (host,"is a windows machine"),
                         print ("Fetching the Host ID for the",host),
                         dns = get_dns_from_ip(host)
                         print (dns)
                         HostIdWin = zapi.host.get(filter={"host": dns}, output=["hostid"])
                         print (HostIdWin)
                         print("Adding host to the Windows Host Group"),
                         if len(HostIdWin):
                             hostId_Win = HostIdWin[0]['hostid']
                             HostAddWin = zapi.host.massadd(hosts=[hostId_Win], groups=[GroupId_Win])
                             print(HostAddWin)
                         else:
                             print ('WARNING : This WINDOWS host is not present in the discovered host. So it will not be added to the host group')


                         #hostupdate_win = zapi.host.update{"host": host,"status": 0},"id": 1}

                     elif "Linux" in osmatch['name']:
                         print (host,"is a Linux machine"),
                         #print (str(host) , file=open("linux_list.txt", "a"))
                         linux_list.add(host)
                         print ("Fetching the Host ID for the",host),
                         dns = get_dns_from_ip(host)
                         print (dns)
                         HostIdLin = zapi.host.get(filter={"host": dns}, output=["hostid"])
                         print (HostIdLin)
                         print("Adding host to the Linux Host Group"),
                         if len(HostIdLin):
                             hostId_Lin = HostIdLin[0]['hostid']
                             HostAddLin = zapi.host.massadd(hosts=[hostId_Lin], groups=[GroupId_Lin])
                             print(HostAddLin)
                         else:
                             print ('WARNING : This LINUX host is not present in the discovered host. So it will not be added to the host group')

                     else:
                         print (host,"is neither Linux nor windows"),
             for host in linux_list:
                 print (str(host) , file=open("linux_list.txt", "a"))

def get_dns_from_ip(ip):
    try:
#hostDetection
        return socket.gethostbyaddr(ip)[0]
    except:
        return ip


print("Connecting to zabbix ...")

# Create ZabbixAPI clag: instance
ZabbixServer='http://15.213.248.33/zabbix'
zapi = ZabbixAPI(url=ZabbixServer, user='api-user', password='Zapi123')
Group_Win = zapi.hostgroup.get(filter={"name": "Windows_HG_API"}, output=["groupid"])
GroupId_Win = Group_Win[0]['groupid']
#print('{0} {1}'.format("GroupID is for Windows is :", GroupId_Win))
Group_Lin = zapi.hostgroup.get(filter={"name": "Linux_HG_API"}, output=["groupid"])
GroupId_Lin = Group_Lin[0]['groupid']
#print('{0} {1}'.format("GroupID is for Linux is :", GroupId_Lin))
#hostDetection()

# Get list of enabled hosts
#result = zapi.host.get(status=0)
#print(result)

# Print all enabled hosts with a running serial number
#for number, zabbix_host in enumerate(result, 1):
#   print('{0}. {1}'.format(number, zabbix_host['host']))
#print("^^^List of all hosts")


# Get the group ID of specific group
Group = zapi.hostgroup.get(filter={"name": "Discovered Hosts"}, output=["groupid"])
GroupId = Group[0]['groupid']
#print('{0} {1}'.format("GroupID for Discovered Hosts is:", GroupId))

# Get list of hosts from specific group
#print("Hosts from specific group")
result = zapi.host.get(groupids=GroupId)

# Print all enabled hosts in the specific group
d_host_set = list()
input_set = list()

####
zabbix_hosts = []
for number, zabbix_host in enumerate(result, 1):
    #print('{0}. {1}'.format(number, zabbix_host['host']))
    d_host_set.append(zabbix_host['host'])
    zabbix_hosts.append(zabbix_host['host'])

####

nm = nmap.PortScanner()
nm.scan(hosts=iprange, arguments="-O")
all_hosts = nm.all_hosts()

matched_hosts = []
for host in all_hosts:
    for zabbix_host in zabbix_hosts:
        if get_dns_from_ip(host) == zabbix_host:
            matched_hosts.append(zabbix_host)

print ('The matched hosts are: %s' % matched_hosts)
print (str(matched_hosts) , file=open("output.txt", "a"))



if '-' in iprange:
    start_ip, end = iprange.split('-')
    end_ip = str(start_ip.rsplit('.',1)[0]) + '.' + end
    input_set = iterateIp(start_ip,end_ip)
elif '/' in iprange:
    input_set = iterateIp(iprange)

#def get_all_ips_in_range(iprange):
#    end = int(iprange.aplit('-')[1])
#    start = int(iprange.split('.')[3])


hostDetection()
secureConn()
