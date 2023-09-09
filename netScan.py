"""
---------------------------------
Dev: Prajwal Nautiyal
Date: 09 September 2023
---------------------------------
This is a simple network scanner.
It scans the network and returns the IP, MAC address and, with relative accuracy, the hardware vendor of the devices connected to the network.
It uses the ARP protocol to scan the network.
It uses the scapy library to send and receive packets.
It also has basic port scanning functionality.
---------------------------------
ANSI escape codes:
    Red Background: \033[48;5;196m
    Green Background: \033[48;5;82m
    White Background: \033[48;5;255m
    Red: \033[38;5;196m
    Cyan: \033[38;5;51m
    Green: \033[38;5;82m
    Yellow: \033[38;5;227m
    Black: \033[38;5;0m
    Clear: \033[0m
---------------------------------
Error Codes:
    0: No error
    1: No target IP
    2: Invalid Port Scan
    3: Invalid Port Number
    TODO: Add error codes
---------------------------------
"""

# Importing libraries
import argparse
import os
import sys
import time

import scapy.all as scapy

# Clearing the screen
os.system("clear")

# Loading animation
loading = lambda i: print(f"\r|\033[48;5;51;38;5;0m{'>' * (i * 25 // 100)}\033[0m{' ' * (25 - (i * 25 // 100))}|", end="") or time.sleep(0.01)

def getArgs():
    """
    Function to get the arguments from the command line

    Returns:
        options: The arguments
            options.target: The target IP / IP range [Required]
            options.port: The port to scan [Optional] !Not yet implemented!
            options.default: Scan the default ports [Optional] !Not yet implemented!
            options.scanType: The type of scan [Optional] !Not yet implemented!
    
    Raises:
        error code 1: If no target IP is specified
        error code 2: If both the port and the default port scan are specified
        error code 3: If the port number is invalid
    """
    parser = argparse.ArgumentParser()                  # Creating the parser object
    # Adding the arguments
    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP Range.", required=True)
    parser.add_argument("-p", "--port", dest="port", help="Port to scan.", required=False)
    parser.add_argument("-d", "--default", dest="default", help="Scan the default ports.", required=False, action="store_true")
    parser.add_argument("-s", "--scan-type", dest="scanType", help="Scan type.", required=False, choices=["tcpCONN","tcpSYN", "udp"])
    options = parser.parse_args()                       # Parsing the arguments
    if not options.target:                              # Checking if the target IP / IP range is specified, exiting if not
        parser.error("\033[38;5;196m[-] Please specify a target IP/IP range\n\033[38;5;227m[*]Use --help for more info.\033[0m")
        sys.exit(1)
    if options.default and options.port:                # Checking if both the port and the default port scan are specified, exiting if so
        parser.error("\033[38;5;196m[-] Please specify either a port or the default port scan.\033[0m")
        sys.exit(2)
    if options.port:
        try:
            options.port = int(options.port)            # Checking if the port number is valid integer, exiting if not
        except ValueError:
            parser.error("\033[38;5;196m[-] Please specify a valid port number.\033[0m")
            sys.exit(3)
        if options.port < 1 or options.port > 65535:    # Checking if the port number is valid, exiting if not
            parser.error("\033[38;5;196m[-] Please specify a valid port number.\033[0m")
            sys.exit(3)
        if options.scanType == None:                    # Setting the scan type to tcpCONN if not specified
            options.scanType = "tcpCONN"
    return options

def scan(ip):
    """
    Function to scan the network

    Args:
        ip (str): The IP range to scan

    Returns:
        answeredList: The list of answered packets

    Raises:
        None
    """
    answeredList = []
    # Checking if the IP range is specified in CIDR notation, if not, adding it
    if ip.find("/") == -1:
        pos = ip.rfind(".")                                                 # Finding the last occurence of a dot    
        ip = ip[:pos] + ".1/24"                                             # Slicing the IP from the postion of last '.' and adding the CIDR notation
    print("\033[38;5;82m[+] Scanning the network.\033[0m")
    print("\033[38;5;227m[+] Press Ctrl+C to stop the scan.\033[0m")
    arpRequest = scapy.ARP(pdst=ip)                                         # Creating the ARP segment
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")                        # Creating the ethernet frame
    packet = broadcast/arpRequest                                           # Combining the ethernet frame and the ARP segment
    while answeredList == []:
        answeredList = scapy.srp(packet, timeout=1, verbose=False)[0]       # Sending the packet until receiving the response
    return answeredList

def getVendor(mac):
    """
    Function to get the vendor of a device with the specified MAC address using macvendors API

    Args:
        mac (str): The MAC address of the device

    Returns:
        vendor: The vendor of the device
    """
    mac = mac.upper()                                                       # Converting the MAC address to uppercase
    mac = mac.replace(":", "-")                                             # Replacing the colons with hyphens
    vendor = os.popen(f"curl -s https://api.macvendors.com/{mac}").read()   # Getting the vendor from the API
    if str(vendor).find("errors") != -1:                                    # Checking if the vendor is not found
        vendor = "Unknown"
    return vendor

def displayScan(answeredList):
    """
    Function to display the scan results

    Args:
        answeredList: The list of answered packets

    Returns:
        None
    """
    list(map(loading, range(101)))                                          # Loading animation
    print("\n")
    print(f"\033[48;5;255;38;5;0m|{'IP':<20}|{'MAC Address':<20}|{'Vendor':<60}|\033[0m")
    print(f"\033[38;5;227m|{'-'*20}|{'-'*20}|{'-'*60}|\033[0m")
    for element in answeredList:
        print(f"\033[38;5;227m|{element[1].psrc:<20}|{element[1].hwsrc:<20}|{getVendor(element[1].hwsrc):<60}|\033[0m")

def scanPort(ip, port):
    print("\033[38;5;196m[-] Port scanning is not yet implemented.\033[0m")

def scanDefaultPorts(ip):
    print("\033[38;5;196m[-] Default port scanning is not yet implemented.\033[0m")

def main():
    """
    Function to run the program
    Exits when CTRL + C is pressed
    """
    options = getArgs()                                 # Getting the arguments
    if options.default:                                 # Checking if the default port scan is specified
        scanDefaultPorts(options.target)    
    elif options.port:                                  # Checking if the port is specified
        scanPort(options.target, options.port)
    else:                                               # If neither the port nor the default port scan is specified a network scan is performed
        try:
            while True:
                answeredList = scan(options.target)
                displayScan(answeredList)
                # Prompting the user to update the results
                update = input("\n\033[38;5;227m[+] Do you want to update the results? (y/n): \033[0m").lower()
                if update != "y":                       # Checking if the user wants to update the results
                    sys.exit(0)                         # Exiting if not
                os.system("clear")
                print("\033[38;5;82m[+] Updating the results.\033[0m")    
        except KeyboardInterrupt:
            print("\n\033[38;5;227m[-] Keyboard Interrupt. Exiting...\033[0m")
            sys.exit(0)

if __name__ == "__main__":
    main()