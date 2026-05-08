
'''
scanner logic(TCP connect):

create socket -> 
attempt connection -> 
check result(open port or closed/filtered) -> 
close socket

'''

import pyfiglet #ASCII art
import socket #connections
import sys #interpreter parameters
from datetime import datetime #how long the scanning will last

ascii_banner = pyfiglet.figlet_format("PORT SCANNER")
print(ascii_banner)

#defining target
if len(sys.argv) == 2: #argv -> command line parameters
    #dns translation(hostname to ipv4)
    target = socket.gethostbyname(sys.argv[1])
else:
    print("Insufficient Arguments")
    
#banner
print("-" * 50)
print(f"Scanning Target: {target}")
print(f"Scanning started at: {datetime.now()}")
print("-" * 50)

#TCP/UDP port numbers range(0-65535) are divided into three categories(well-know,registerd and dynamic/private ports) by IANA(Internet Assigned Numbers Authority)
# focusing on the well-know ports(0-1023)

try:
    #scan ports between 1 to 1023
    for port in range(1,1023):
        #AF_INET -> ipv4 addresses
        #SOCK_STREAM -> TCP connections
        #SOCK_DGRAM -> UDP connections
        #UDP is connectionless, so a socket often appears "open" even if nothing is listening
        #we have to send a specific packet and wait for a response or an error message
        tcp_conn = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        socket.setdefaulttimeout(1) #global timeout for all socket objects created
        
    
except:
    pass