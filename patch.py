#!/usr/bin/python3.6
import socket,os
import sys
import paramiko
from netaddr import *

def Conn():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    conn = open('linux_list.txt')
    for line in conn:
        try:
            client.connect(line , username='root')
            print (line,"Connection Established"),
            print (str(line) , file=open("linux_conn.txt", "a"))
        except paramiko.ssh_exception.AuthenticationException:
            print (line,"Connectionis not Established"),
            print (str(line) , file=open("linux_conn_not.txt", "a"))
    conn.close()

os.chdir(/home/provision/ansible1/)
print ("Going Inside the Path /home/provision/ansible1/")
