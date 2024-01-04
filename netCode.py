"""
---------------------------------
ANSI escape codes:
    Red Background: \033[48;5;196m
    Green Background: \033[48;5;82m
    White Background: \033[48;5;255m
    Red: \033[38;5;196m
    Cyan: \033[38;5;87m
    Green: \033[38;5;82m
    Yellow: \033[38;5;228m
    Black: \033[38;5;0m
    Clear: \033[0m
---------------------------------
"""

import logging  # For suppressing the warnings from scapy
import os  # For executing the commands like clear, curl, etc.
import re  # For checking the validity of the IP address
import socket  # For checking if the device is connected to the network
import sys  # For exiting the program
import threading  # For running the scan and loading animation simultaneously
# For the sleep function in the loading animation and pinging the api for vendor info
import time
# For parsing the arguments
from argparse import ArgumentParser, RawTextHelpFormatter

# For sending and receiving packets in the class modules
from scapy.all import ARP, Ether, IP, TCP, UDP, sr1, sr, srp, conf, ICMP

# dict of common ICMP type 3 codes and theri meanings
ICMPDICT = {
    1: "Destination host unreachable",
    2: "Destination protocol unreachable / The port doesn't support the protocol used in the request",
    3: "Destination port unreachable / The port is closed or blocked by a firewall",
    9: "Network administratively prohibited / Destination network firewall blocked the request",
    10: "Host administratively prohibited / Target firewall blocked the request",
    13: "Communication administratively prohibited / Gateway firewall blocked the request"
}


# setting logging level of scapy to error so it doesn't throw warnings
# when you try to scan ports of local network devices
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


# loading animation funtion
# takes the thread object as argument and runs the animation while the thread is working
def loadAni(thrd: threading.Thread):
    while thrd.is_alive():
        for i in ["▹▹▹▹▹", "\033[38;5;87m▸\033[0m▹▹▹▹", "▹\033[38;5;87m▸\033[0m▹▹▹", "▹▹\033[38;5;87m▸\033[0m▹▹", "▹▹▹\033[38;5;87m▸\033[0m▹", "▹▹▹▹\033[38;5;87m▸\033[0m", "▹▹▹▹▹", "▹▹▹▹▹", "▹▹▹▹▹", "▹▹▹▹▹", "▹▹▹▹▹", "▹▹▹▹▹", "▹▹▹▹▹"]:
            print(f"\r\033[38;5;87m[+] Scanning the network \033[0m{i}", flush=True, end="")
            time.sleep(0.12)


def isConnected() -> bool:
    """
    Function to check if the device is connected to the network.
    """
    try:
        # connect to the host -- tells us if the host is actually reachable
        socket.create_connection(("1.1.1.1", 53))
        return True
    except OSError:
        pass
    return False


def updateRes():
    """
    Function to check if the user wants to update the results or exit the program
    """
    # Prompting the user to update the results
    print("\r" + " " * 100, end="", flush=True)
    update = input("\r\n\033[38;5;228m[+] Do you want to update the results? (y/n): \033[0m").lower()
    if update != "y":                       # Checking if the user wants to update the results
        sys.exit(0)                         # Exiting if not
    if os.name == "nt":                     # Checking if the OS is Windows
        os.system("cls")                    # Clearing the screen
    else:
        os.system("clear")
    print("\033[38;5;82m[+] Updating the results.\033[0m")


def getArgs():
    """
    Function to get the arguments from the command line

    Returns:
        options: The arguments
            options.target: The target IP / IP range [Required]
            options.port: The port(s) to scan [Optional]
            options.scanType: The type of scan [Optional]
    """
    parser = ArgumentParser(formatter_class=RawTextHelpFormatter)   # Creating the parser object
    # Adding the arguments
    parser.add_argument("-t", "--target",
                        dest="target",
                        help="target IP / IP Range.",
                        required=True)

    parser.add_argument("-p", "--port",
                        dest="port",
                        help="port number(s) or range to scan\
                            \nrange format p1 - p2 (eg. 1-100)\
                            \nmultiple ports can be specified using comma (eg. 1,2,3,4,5)",
                        required=False)

    parser.add_argument("-n", "--no-net-scan",
                        dest="net",
                        help="tell the application not to scan the subnet first",
                        required=False,
                        action="store_true")

    parser.add_argument("-s", "--scan-type",
                        dest="scanType",
                        help="the type of protocol to use for port scan\
                            \n1. tcpCONN: TCP Connect Scan - TCP threeway handshake scan\
                            \n2. tcpSYN: TCP SYN Scan - stealth scan, doesn't complete the connection [default scan]\
                            \n3. tcpWIN: TCP Window Scan - sends an ACK request and determines the port state by the window size of response\
                            \n4. tcpACK: TCP ACK Scan - used to determine whether a port is filtered or not\
                            \n5. udp: UDP Scan - sends a UDP packet to determine whether a port is open or not (not reliable)",
                        required=False,
                        choices=["tcpCONN", "tcpSYN", "tcpWIN", "tcpACK", "udp"])
    
    parser.add_argument("-v", "--verbose", 
                        dest="verbosity",
                        help="makes the scan more talkative", 
                        required=False, 
                        action="store_true")
    
    parser.add_argument("-a", "--all", 
                        dest="all",
                        help="shows all port scan results", 
                        required=False, 
                        action="store_true")
    
    parser.add_argument("-V", "--version", 
                        action="version",
                        version="%(prog)s 1.2")
    
    options = parser.parse_args()                       # Parsing the arguments
    # Checking if the target IP / IP range is specified, exiting if not
    if not options.target:
        parser.error("\033[38;5;196m[-] Please specify a target IP/IP range\n\033[38;5;228m[*]Use --help for more info.\033[0m")
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", options.target) and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d\/\d{1,3}$", options.target):
        parser.error("\033[38;5;196m[-] Please specify a valid format target IP/IP range\033[0m")
    if options.port:  # if the port argument is provided
        # check if its not a range
        if options.port.find("-") == -1:
            i = 0
            # Checking if the port number is a list
            if options.port.find(",") != -1:
                # Splitting the string into a list
                options.port = options.port.split(',')
            for port in options.port:
                try:
                    # Checking if the port number is valid integer, exiting if not
                    options.port[i] = int(port)
                    i += 1
                except ValueError:
                    parser.error("\033[38;5;196m[-] Please specify a valid port number.\033[0m")
        # if the range is given instead
        else:
            # splitting the string into two
            options.port = options.port.split('-')
            # try to convert the strings to integers and throw error if the value is not numerical
            try:
                options.port[0] = int(options.port[0])
                options.port[1] = int(options.port[1])
            except ValueError:
                parser.error("\033[38;5;196m[-] Please specify a valid port number.\033[0m")
        # Checking if the port number is valid, exiting if not
        if options.port[0] < 1 or options.port[1] > 65535:
            parser.error("\033[38;5;196m[-] Please specify a valid port number.\033[0m")
        if options.scanType == None:                        # Setting the scan type to tcpCONN if not specified
            options.scanType = "tcpSYN"
    return options