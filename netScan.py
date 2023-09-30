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
        scan = subnetScan(op.target)
        # setting the scan thread as a daemon thread so that it exits when the main thread exits
        scan.daemon = True
        if not op.net:
            scan.start()
            loadAni(scan)
            scan.join()
        if not op.port == None:
            pScan = portScan(op.target, op.port, op.scanType, op.verbosity, op.all)
            # same thing as scan thread
            pScan.daemon = True
            # if the user did not deny the subnet scan
            if not op.net:
                pScan.setIP(scan.getIPs())
            pScan.start()
            loadAni(pScan)
            pScan.join()
        updateRes()

if __name__ == "__main__":
    main()