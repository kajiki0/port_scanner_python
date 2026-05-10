
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
import errno
''' 
error indicators:
    0   SUCCESS
    13  EACCES  
    98  EADDRINUSE
    99  EADDRNOTAVAIL
    101 ENETUNREACH
    110 ETIMEOUT
    111 ECONNREFUSED
    113 EHOSTUNREACH
    114 EALREADY
    115 EINPROGRESS
'''

def port_scanner(target):
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
            
            #use connect_ex to return an error indicator(numeric valure,instead of a exception)
            
            result = tcp_conn.connect_ex((target,port))
            if  result == 0:
                print(f"Port {port} is open")
            
            elif result == 111:
                print(f"Connection refused: Port {port} is closed")
            elif result == 110:
                print(f"Connection timed out on Port {port}")
            elif result == 101:
                print(f"Routing problem: the network is unreachable on Port {port}")    
            else:#any other error types
                error_type = errno.errorcode.get(result,"Error")
                print(f"FAILED! error {result}: {error_type} on Port {port}")
            
            tcp_conn.close()
                
    # hadnling socket and keyboard errors to quit our script
    #KeyboardInterrupt -> CTRL+C
    except KeyboardInterrupt:
        print("\n EXITING!\n")
        sys.exit()
        
    #DNS error
    except socket.gaierror:
        print("HOSTNAME COULD NOT BE RESOLVED!\n")
        sys.exit()
        
    #network connection failure( different scenarios )
    except socket.error:
        print("SERVER NOT RESPONDING!")
        sys.exit()
        

# TCP/UDP port numbers range(0-65535) are divided into three categories(well-know,registerd and dynamic/private ports) by IANA(Internet Assigned Numbers Authority)
# well-know ports(0-1023)
# other important ports beside the well-know ports:
# 3389 - RDP (remote desktop protocol)
# 3306 - MySQL
# 1433 - Microsoft SQL server
# 1521 - Oracle DB
# 1723 - PPTP VPN (legacy vpn protocol)
# 5060 & 5061 - VoIP phone systems
# 5432 PostgreSQL
# 5900 - VNC (cross platform remote desktop)
# 8080 - HTTP alternate
# 1194 - OpenVPN

def main():
    ascii_banner = pyfiglet.figlet_format("BASIC PORT SCANNER")
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
    
    port_scanner(target)
    
    

if __name__ == "__main__":
    main()