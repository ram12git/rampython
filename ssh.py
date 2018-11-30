#!/usr/bin/python

import paramiko
import socket
import os

# code to check the passwordless authentication between ansible master master & ansible clients
#All the authenticated  machines  IP's will write to out.txt & Not authenicated will write to

status = 'OK'
with open('ping.txt', 'w+') as z:
 with open('notping.txt', 'w+') as b:
    with open(r'linux_list.txt', 'r') as inp:
          for line in inp:
             line = line.strip()
             with paramiko.SSHClient() as ssh_client:
                 ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                 try:
                     ssh_client.connect(hostname=line, username="root")
                     print("Successful Connection to " + line)
                     stdin, stdout, stderr = ssh_client.exec_command(' ')
                     output = stdout.read()
                     with open('ping.txt', 'a') as out:
                         out.write(line + '\n')
                         #out.write(str(output) + '\n')
                         #out.write('\n')
                 except (socket.error, paramiko.AuthenticationException) as e:
                     with open('notping.txt', 'a') as f:
                         f.write(line + '\n')
                         #f.write('\n')
                         print('Not succesfull connection to ' + line)
                         status = 'fail'
