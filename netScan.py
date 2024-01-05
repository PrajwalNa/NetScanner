#!/usr/bin/python3
"""
---------------------------------
Dev: Prajwal Nautiyal
Date: 30 September 2023
Version: 1.2
---------------------------------
This is a simple network scanner.
It scans the network and returns the IP, MAC address and, with relative accuracy, the hardware vendor of the devices connected to the network.
It uses the ARP protocol to scan the network.
It uses the scapy library to send and receive packets.
It also has basic port scanning functionality.
---------------------------------
"""

from netCode import *
from port import portScan
from subnet import subnetScan


def main():
    """
    Function to run the program
    Exits when CTRL + C is pressed
    """
    if not isConnected():
        print("\033[38;5;196m[-] Error: No network connection found!!\033[0m")
        sys.exit(1)
    options = getArgs()                             # Getting the arguments
    if os.name == "nt":                             # Checking if the OS is Windows
        os.system("cls")                            # Clearing the screen
    else:
        os.system("clear")
    try:
        routing(options)
    except KeyboardInterrupt:
        print("\n\033[38;5;228m[-] Keyboard Interrupt. Exiting...\033[0m")
        sys.exit(0)
    except Exception as e:
        print(f"\033[38;5;196m[-] Error: {e}\033[0m")
        sys.exit(1)

def routing(op):
    """
    Function to route the program

    Parameters:
        op (object): The object containing the arguments
    """
    while True:
        print("\033[38;5;228m[+] Press Ctrl+C to stop the scan.\033[0m")
        if not op.net:
            netScanResults = {}
            cidr = op.target[op.target.find("/")+1:]
            if cidr == "":
                cidr = "24"
            elif int(cidr) >= 24:
                cidr = "24"
            elif int(cidr) >= 16:
                cidr = "16"
            elif int(cidr) >= 8:
                cidr = "8"
            else:
                cidr = "0"
            match cidr:
                case "24":
                    addr = op.target[:op.target.rfind(".")] + ".1/26"
                    scanThread1 = subnetScan(addr)
                    addr = op.target[:op.target.rfind(".")] + ".64/26"
                    scanThread2 = subnetScan(addr)
                    addr = op.target[:op.target.rfind(".")] + ".128/26"
                    scanThread3 = subnetScan(addr)
                    addr = op.target[:op.target.rfind(".")] + ".192/26"
                    scanThread4 = subnetScan(addr)

                case "16":
                    addr = op.target[:op.target.rfind(".")] + ".1/18"
                    scanThread1 = subnetScan(addr)
                    addr = op.target[:op.target.rfind(".")] + ".64/18"
                    scanThread2 = subnetScan(addr)
                    addr = op.target[:op.target.rfind(".")] + ".128/18"
                    scanThread3 = subnetScan(addr)
                    addr = op.target[:op.target.rfind(".")] + ".192/18"
                    scanThread4 = subnetScan(addr)

                case "8":
                    addr = op.target[:op.target.rfind(".")] + ".1/10"
                    scanThread1 = subnetScan(addr)
                    addr = op.target[:op.target.rfind(".")] + ".64/10"
                    scanThread2 = subnetScan(addr)
                    addr = op.target[:op.target.rfind(".")] + ".128/10"
                    scanThread3 = subnetScan(addr)
                    addr = op.target[:op.target.rfind(".")] + ".192/10"
                    scanThread4 = subnetScan(addr)
            
            # starting the threads
            for thread in [scanThread1, scanThread2, scanThread3, scanThread4]:
                thread.daemon = True
                thread.start()
            
            # loading animation using the loadAni function using thread 4
            loadAni([scanThread1, scanThread2, scanThread3, scanThread4])

            # joining the threads
            for thread in [scanThread1, scanThread2, scanThread3, scanThread4]:
                thread.join()

            # updating the results
            for thread in [scanThread1, scanThread2, scanThread3, scanThread4]:
                netScanResults.update(thread.getResults())

            displayNetScan(netScanResults)

        # setting the scan thread as a daemon thread so that it exits when the main thread exits
        if not op.port == None:
            portScanResults = {}
            # if the user did not deny the subnet scan
            if not op.net:
                # creating the port scan threads
                # Convert the keys to a list
                keys = list(netScanResults.keys())

                # Calculate the size of each part
                size = len(keys) // 4

                # Split the keys into four parts
                keys1 = keys[:size]
                keys2 = keys[size:2*size]
                keys3 = keys[2*size:3*size]
                keys4 = keys[3*size:]

                portThreads = []
                # Create the port scan threads
                for key in [keys1, keys2, keys3, keys4]:
                    portThreads.append(portScan(key, op.port, op.scanType, op.verbosity, op.all))
            
            # if the user denied the subnet scan
            else:
                # creating the port scan thread
                portThreads = [portScan([op.target], op.port, op.scanType, op.verbosity, op.all)]
                
            # starting the threads
            for thread in portThreads:
                thread.daemon = True
                thread.start()

            # loading animation using the loadAni function using thread 4
            loadAni(portThreads)
            # joining the threads
            for thread in portThreads:
                thread.join()
            # updating the results
            for thread in portThreads:
                portScanResults.update(thread.getResults())
            
            displayPortScan(portScanResults)
        updateRes()

if __name__ == "__main__":
    main()