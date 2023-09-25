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

# Importing libraries
import argparse             # For parsing the arguments directly from the command line
import re                   # For checking the validity of the IP address
import os                   # For executing the commands like clear, curl, etc.
import sys                  # For exiting the program
import time                 # For the sleep function in the loading animation and pinging the api for vendor info
import socket               # For checking if the device is connected to the network
import random               # For generating random source ports
import logging              # For suppressing the warnings from scapy
import threading            # For running the scan and loading animation simultaneously

import scapy.all as scapy   # For sending and receiving packets


# dict of common ICMP type 3 codes and theri meanings
ICMPDICT = {
    1 : "Destination host unreachable",
    2 : "Destination protocol unreachable / The port doesn't support the protocol used in the request",
    3 : "Destination port unreachable / The port is closed or blocked by a firewall",
    9 : "Network administratively prohibited / Destination network firewall blocked the request",
    10: "Host administratively prohibited / Target firewall blocked the request",
    13: "Communication administratively prohibited / Gateway firewall blocked the request" 
}   


# setting logging level of scapy to error so it doesn't throw warnings
# when you try to scan ports of local network devices
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


# loading animation funtion
# takes the thread object as argument and runs the animation while the thread is working
def loadAni(thrd:threading.Thread):
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
    os.system("clear")
    print("\033[38;5;82m[+] Updating the results.\033[0m")



def getArgs():
    """
    Function to get the arguments from the command line

    Returns:
        options: The arguments
            options.target: The target IP / IP range [Required]
            options.port: The port(s) to scan [Optional] !Not yet implemented!
            options.scanType: The type of scan [Optional] !Not yet implemented!
    """
    parser = argparse.ArgumentParser()                  # Creating the parser object
    # Adding the arguments
    parser.add_argument("-t", "--target", dest="target", help="target IP / IP Range.", required=True)
    parser.add_argument("-p", "--port", dest="port", help="port number or range to scan.\tRange Format p1 - p2", required=False)
    parser.add_argument("-n", "--no-net-scan", dest="net", help="tell the application not to scan the subnet first", required=False, action="store_true")
    parser.add_argument("-s", "--scan-type", dest="scanType", help="the type of protocol to use for port scan", required=False, choices=["tcpCONN","tcpSYN", "tcpWIN", "udp"])
    parser.add_argument("-v", "--verbose", dest="verbosity", help="makes the scan more talkative", required=False, action="store_true")
    parser.add_argument("-a", "--all", dest="all", help="shows all port scan results", required=False, action="store_true")
    parser.add_argument("-V", "--version", action="version", version="%(prog)s 0.9 (alpha)")
    options = parser.parse_args()                       # Parsing the arguments
    if not options.target:                              # Checking if the target IP / IP range is specified, exiting if not
        parser.error("\033[38;5;196m[-] Please specify a target IP/IP range\n\033[38;5;228m[*]Use --help for more info.\033[0m")
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", options.target) and re.match(r"^\d{1,3}\.\d{1,3}\.\d?\/?\d{1,3}\.\d\/\d{1,3}$", options.target):
        parser.error("\033[38;5;196m[-] Please specify a valid format target IP/IP range\033[0m")
    if options.port:# if the port argument is provided
        # check if its not a range
        if options.port.find("-") == -1:
            try:
                options.port = int(options.port)            # Checking if the port number is valid integer, exiting if not
            except ValueError:
                parser.error("\033[38;5;196m[-] Please specify a valid port number.\033[0m")
        # if the range is given instead
        else:        
            options.port = options.port.split('-')          # splitting the string into two
            # try to convert the strings to integers and throw error if the value is not numerical
            try:
                options.port[0] = int(options.port[0])
                options.port[1] = int(options.port[1])
            except ValueError:
                parser.error("\033[38;5;196m[-] Please specify a valid port number.\033[0m")    
        if options.port[0] < 1 or options.port[1] > 65535:  # Checking if the port number is valid, exiting if not
            parser.error("\033[38;5;196m[-] Please specify a valid port number.\033[0m")
        if options.scanType == None:                        # Setting the scan type to tcpCONN if not specified
            options.scanType = "tcpCONN"
    return options


class subnetScan(threading.Thread):
    """
    Class to scan the network

    Args:
        ip (str): The IP range to scan

    Methods:
        run: Function to scan the network, and print the results
        getVendor: Function to get the vendor of a device with the specified MAC address using macvendors API
        displayScan: Function to display the scan results

    Attributes:
        answeredList: The list of answered packets
        ipRange: The IP range to scan
        mac: The MAC address of the device
        vendor: The vendor of the device
        resultsDict: The dictionary containing the results
    """
    def __init__(self, ip : str):
        threading.Thread.__init__(self)
        # Checking if the IP range is specified in CIDR notation, if not, adding it
        if ip.find("/") == -1:
            pos = ip.rfind(".")                                                 # Finding the last occurence of a dot    
            ip = ip[:pos] + ".1/24"                                             # Slicing the IP from the postion of last '.' and adding the CIDR notation
        self.answeredList = []
        self.ipRange = ip
        self.mac = ""
        self.vendor = ""
        self.resultsDict = {}
        
    def run(self) -> None:
        """
        Function to scan the network, and print the results

        Args:
            ip (str): The IP range to scan
        """
        print("\033[38;5;228m[+] Press Ctrl+C to stop the scan.\033[0m")
        arpRequest = scapy.ARP(pdst=self.ipRange)                                       # Creating the ARP segment
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")                                # Creating the ethernet frame
        packet = broadcast/arpRequest                                                   # Combining the ethernet frame and the ARP segment
        while self.answeredList == []:
            self.answeredList = scapy.srp(packet, timeout=1, verbose=False)[0]          # Sending the packet until receiving the response
        self.displayScan()                                                              # Displaying the scan results
    
    def getVendor(self, mac) -> None:
        """
        Function to get the vendor of a device with the specified MAC address using macvendors API

        Args:
            mac (str): The MAC address of the device
        """
        self.mac = mac.upper()                                                              # Converting the MAC address to uppercase
        self.vendor = os.popen(f"curl -s https://api.macvendors.com/{self.mac}").read()     # Getting the vendor from the API
        if str(self.vendor).find("errors") != -1:                                           # Checking if the vendor is not found
            self.vendor = "Unknown"

    def displayScan(self) -> None:
        """
        Function to display the scan results

        Args:
            answeredList: The list of answered packets
        """
        for element in self.answeredList:
            self.getVendor(element[1].hwsrc)
            self.resultsDict[element[1].psrc] = [element[1].hwsrc, self.vendor]
            time.sleep(1)
        print("\r" + " " * 100, end="", flush=True)
        print("\r\033[38;5;82m[+] Network Scan complete.\033[0m")
        print(f"\n\033[48;5;255;38;5;0m|{'IP':<16}|{'MAC Address':<18}|{'Vendor':<65}|\033[0m")
        print(f"\033[38;5;228m|{'-'*16}|{'-'*18}|{'-'*65}|\033[0m")
        for key in self.resultsDict:
            print(f"\033[38;5;228m|\033[38;5;87m{key:<16}\033[38;5;228m|\033[38;5;87m{self.resultsDict[key][0]:<18}\033[38;5;228m|\033[38;5;87m{self.resultsDict[key][1]:<65}\033[38;5;228m|\033[0m")
        print(f"\033[38;5;228m|{'-'*16}|{'-'*18}|{'-'*65}|\033[0m")
        print(f"\033[38;5;82m[+] Total devices found: {len(self.resultsDict)}\033[0m")
        print("\n")

    def getIPs(self):
        """
        Function to get the IP addresses of the devices found
        Used to provide the IP addresses for the port scan if subnet is performed first
        """
        return [key for key in self.resultsDict]


class portScan(threading.Thread):
    """
    Description:
        Class to scan the ports of the specified IP address
    
    Args:
        ip (str)[list]: The IP address(s) of the device
        port (int)[list]: The port number(s) to scan
        scanType (str): The type of scan to perform
        vFlag (bool): The verbosity flag
        aFlag (bool): The all flag

    Scans:
        tcpCONN: TCP Connect Scan / Full Open Scan / 3-Way Handshake Scan 
        tcpSYN: TCP SYN Scan / Stealth Scan / Half Open Scan
        tcpWIN: TCP Window Scan / TCP ACK Scan but checks the window size too
        udp: UDP Scan / UDP Ping Scan
    """
    def __init__(self, ip:str, port, scanType:str, vFlag:bool=False, aFlag:bool=False):
        threading.Thread.__init__(self)
        self.pMin = port[0]
        self.pMax = port[1]
        self.ipL = [ip]
        self.scanType = scanType
        self.resultsDict = {}
        self.vFlag = vFlag
        self.aFlag = aFlag

    def setIP(self, IPlist):
        # setting the IP list
        self.ipL = IPlist

    def run(self) -> None:
        """
        Function to run the scan
        Uses match case statement to run the scan based on the scan type
        """
        print("\r" + " " * 100, end="", flush=True)
        print("\r\033[38;5;228m[+] Press Ctrl+C to stop the scan.\033[0m")
        match self.scanType:
            case "tcpCONN":
                self.tcpCONN()
            case "tcpSYN":
                self.tcpSYN()
            case "tcpWIN":
                self.tcpWIN()
            case "udp":
                self.udp()
        self.display()
        
    def tcpCONN(self) -> None:
        """
        TCP Connect Scan / Full Open Scan / 3-Way Handshake Scan
        """
        for ip in self.ipL:
            count = 0
            # check for verbosity flag
            if self.vFlag:
                # clear the line and print the message
                print("\r" + " " * 100, end="", flush=True)
                print(f"\r\033[38;5;228m[*] Scanning {ip}")
            srcPort = random.randint(1025,65534)    # since first 1024 ports are reserved
            for port in range(self.pMin, self.pMax + 1):
                # constructing the packet with the source port as a random port, and SYN flag set
                packet = scapy.IP(dst=ip)/scapy.TCP(sport=srcPort, dport=port, flags='S')
                # sending the packet and storing the response
                # verbose=0 to suppress the output
                # timeout=2 to wait for 2 seconds for the response
                # retry=2 to retry sending the packet 2 times if no response is received 
                response = scapy.sr1(packet, verbose=0, timeout=2, retry=2)
                if not response:                    # if no response is received
                    # if aFlag is set, show all results
                    if self.aFlag:
                        self.resultsDict.setdefault(ip, []).append(f"\033[38;5;87m[=] {ip} : {port} is filtered (silently dropped).\033[0m")
                        count += 1
                # if the response is received and the packet has a TCP layer
                elif response.haslayer(scapy.TCP):
                    # if the response has the SYN and ACK flags set then the port is open
                    # 0x12 is the hex value of 10010 in binary, which is the value of the flags
                    # CWR, ECE, URG, ACK, PSH, RST, SYN, FIN
                    # 0    0    0    1    0    0    1    0 
                    if response.getlayer(scapy.TCP).flags == 0x12:
                        self.resultsDict.setdefault(ip, []).append(f"\033[38;5;82m[+] {ip} : {port} is open.\033[0m")
                        count += 1
                        # sending a RST packet to close the connection
                        packet = scapy.IP(dst=ip)/scapy.TCP(sport=srcPort,dport=port,flags='R')
                        response = scapy.sr(packet, verbose=0, timeout=2)
                    # if the response has the RST flag set then the port is closed
                    # 0x14 is the hex value of 10100 in binary, which is the value of the flags
                    # CWR, ECE, URG, ACK, PSH, RST, SYN, FIN
                    # 0    0    0    1    0    1    0    0
                    elif response.getlayer(scapy.TCP).flags == 0x14:
                        # if aFlag is set, show all results
                        if self.aFlag:
                            self.resultsDict.setdefault(ip, []).append(f"\033[38;5;196m[-] {ip} : {port} is closed.\033[0m")
                            count += 1
                # if the response is received and the packet has an ICMP layer
                elif response.haslayer(scapy.ICMP):
                    # if the response has the ICMP type 3 then the destination is unreachable
                    if int(response.getlayer(scapy.ICMP).type) == 3:
                        # using the ICMPDICT to get the meaning of the ICMP code
                        self.resultsDict.setdefault(ip, []).append(f"\033[38;5;196m[-] {ip} : {port} ICMP code: {int(response.getlayer(scapy.ICMP).code)} - {ICMPDICT.get(int(response.getlayer(scapy.ICMP).code), 'Please check the code with: https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages')}.\033[0m")
                        count += 1
            if count == 0 and not self.aFlag:
                self.resultsDict.setdefault(ip, []).append(f"\033[38;5;87m[=] {ip} : No open ports found.\033[0m")
            # check for verbosity flag
            if self.vFlag:
                # clear the line and print the message
                print("\r" + " " * 100, end="", flush=True)
                print(f"\r\033[38;5;82m[+] {ip} Scanned\n\033[0m") 

    def tcpSYN(self) -> None:
        print("\033[38;5;196m[-] tcpSYN scan is not yet implemented.\033[0m")

    def tcpWIN(self) -> None:
        print("\033[38;5;196m[-] tcpWIN scan is not yet implemented.\033[0m")

    def udp(self) -> None:
        print("\033[38;5;196m[-] udp scan is not yet implemented.\033[0m")

    def display(self):
        for k,v in self.resultsDict.items():
            print(f"\n{k}")
            for i in v:
                print(f"{i}")