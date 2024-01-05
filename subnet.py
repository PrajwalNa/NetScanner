from netCode import *
sem = threading.Semaphore()

class subnetScan(threading.Thread):
    """
    Class to scan the network

    Args:
        ip (str): The IP range to scan

    Methods:
        run: Function to scan the network, and print the results
        getVendor: Function to get the vendor of a device with the specified MAC address using macvendors API
        compileResults: Function to process the scan results and store them in a dictionary

    Attributes:
        answeredList: The list of answered packets
        ipRange: The IP range to scan
        mac: The MAC address of the device
        vendor: The vendor of the device
        resultsDict: The dictionary containing the results
    """

    def __init__(self, ip: str):
        threading.Thread.__init__(self)
        # Checking if the IP range is specified in CIDR notation, if not, adding it
        # if ip.find("/") == -1:
        #     # Finding the last occurence of a dot
        #     pos = ip.rfind(".")
        #     # Slicing the IP from the postion of last '.' and adding the CIDR notation
        #     ip = ip[:pos] + ".1/24"
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
        sem.acquire()
        # Creating the ARP segment
        arpRequest = ARP(pdst=self.ipRange)
        # Creating the ethernet frame
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        # Combining the ethernet frame and the ARP segment
        packet = broadcast/arpRequest
        while self.answeredList == []:
            # Sending the packet until receiving the response
            self.answeredList = srp(packet, timeout=1, verbose=False)[0]
        sem.release()
        # Displaying the scan results
        self.compileResults()

    def getVendor(self, mac) -> None:
        """
        Function to get the vendor of a device with the specified MAC address using macvendors API

        Args:
            mac (str): The MAC address of the device
        """
        self.mac = mac.upper()                                                              # Converting the MAC address to uppercase
        # Getting the vendor from the API
        self.vendor = os.popen(f"curl -s https://api.macvendors.com/{self.mac}").read()
        # Checking if the vendor is not found
        if str(self.vendor).find("errors") != -1:
            self.vendor = "Unknown"

    def compileResults(self) -> None:
        """
        Function to display the scan results

        Args:
            answeredList: The list of answered packets
        """
        for element in self.answeredList:
            self.getVendor(element[1].hwsrc)
            self.resultsDict.update({element[1].psrc: [element[1].hwsrc, self.vendor]})
            time.sleep(0.5)
        
    def getResults(self):
        """
        Function to get the results of the scan
        """
        return self.resultsDict

    def getIPs(self):
        """
        Function to get the IP addresses of the devices found
        Used to provide the IP addresses for the port scan if subnet is performed first
        """
        return [key for key in self.resultsDict]