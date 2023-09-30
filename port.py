from netCode import *
import random       # for generating random source ports

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
        tcpWIN: TCP Window Scan / Similiar to TCP ACK Scan but checks the window size
        tcpACK: TCP ACK Scan / TCP ACK Ping Scan, checks if the port is filtered or not
        udp: UDP Scan / UDP Ping Scan
    """

    def __init__(self, ip: str, port, scanType: str, vFlag: bool = False, aFlag: bool = False):
        threading.Thread.__init__(self)
        # if port is not a list then convert it to a list and store it in portL
        if not type(port) == list:
            self.portL = [port]
        else:
            # if the port is a range then convert it to a list and store it in portL
            if len(port) == 2:
                self.portL = [port for port in range(port[0], port[1] + 1)]
            else:
                # if the port is a list then store it in portL
                self.portL = port
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
            case "tcpACK":
                self.tcpACK()
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
            # since first 1024 ports are reserved
            srcPort = random.randint(1025, 65534)
            for port in self.portL:
                # constructing the packet with the source port as a random port, and SYN flag set
                packet = IP(dst=ip)/TCP(sport=srcPort, dport=port, flags='S')
                # sending the packet and storing the response
                # verbose=0 to suppress the output
                # timeout=2 to wait for 2 seconds for the response
                # retry=2 to retry sending the packet 2 times if no response is received
                response = sr1(packet, verbose=0, timeout=2, retry=2)
                if not response:                    # if no response is received
                    # if aFlag is set, show all results
                    if self.aFlag:
                        self.resultsDict.setdefault(ip, []).append(
                            f"\033[38;5;87m[=] {ip} : {port} is filtered (silently dropped).\033[0m")
                        count += 1
                # if the response is received and the packet has a TCP layer
                elif response.haslayer(TCP):
                    # if the response has the SYN and ACK flags set then the port is open
                    # 0x12 is the hex value of 10010 in binary, which is the value of the flags
                    # CWR, ECE, URG, ACK, PSH, RST, SYN, FIN
                    # 0    0    0    1    0    0    1    0
                    if response.getlayer(TCP).flags == 0x12:
                        self.resultsDict.setdefault(ip, []).append(
                            f"\033[38;5;82m[+] {ip} : {port} is open.\033[0m")
                        count += 1
                        # sending a RST packet to close the connection
                        packet = IP(dst=ip)/TCP(sport=srcPort, dport=port, flags='R')
                        response = sr(packet, verbose=0, timeout=2)
                    # if the response has the RST flag set then the port is closed
                    # 0x14 is the hex value of 10100 in binary, which is the value of the flags
                    # CWR, ECE, URG, ACK, PSH, RST, SYN, FIN
                    # 0    0    0    1    0    1    0    0
                    elif response.getlayer(TCP).flags == 0x14:
                        # if aFlag is set, show all results
                        if self.aFlag:
                            self.resultsDict.setdefault(ip, []).append(
                                f"\033[38;5;196m[-] {ip} : {port} is closed.\033[0m")
                            count += 1
                # if the response is received and the packet has an ICMP layer
                elif response.haslayer(ICMP):
                    # if the response has the ICMP type 3 then the destination is unreachable
                    if int(response.getlayer(ICMP).type) == 3:
                        if self.aFlag:
                            # using the ICMPDICT to get the meaning of the ICMP code
                            self.resultsDict.setdefault(ip, []).append(
                                f"\033[38;5;196m[-] {ip} : {port} ICMP code: {int(response.getlayer(ICMP).code)} - {ICMPDICT.get(int(response.getlayer(ICMP).code), 'Please check the code with: https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages')}.\033[0m")
                            count += 1
            if count == 0 and not self.aFlag:
                self.resultsDict.setdefault(ip, []).append(
                    f"\033[38;5;87m[=] {ip} : No open ports found.\033[0m")
            # check for verbosity flag
            if self.vFlag:
                # clear the line and print the message
                print("\r" + " " * 100, end="", flush=True)
                print(f"\r\033[38;5;82m[+] {ip} Scanned\n\033[0m")

    def tcpSYN(self) -> None:
        """
        TCP SYN Scan / Stealth Scan / Half Open Scan
        """
        for ip in self.ipL:
            count = 0
            # check for verbosity flag
            if self.vFlag:
                # clear the line and print the message
                print("\r" + " " * 100, end="", flush=True)
                print(f"\r\033[38;5;228m[*] Scanning {ip}")
            # since first 1024 ports are reserved
            srcPort = random.randint(1025, 65534)
            for port in self.portL:
                # constructing the packet with the source port as a random port, and SYN flag set
                packet = IP(dst=ip)/TCP(sport=srcPort, dport=port, flags='S')
                # sending the packet and storing the response
                # verbose=0 to suppress the output
                # timeout=2 to wait for 2 seconds for the response
                # retry=2 to retry sending the packet 2 times if no response is received
                response = sr1(packet, verbose=0, timeout=2, retry=2)
                if not response:                    # if no response is received
                    # if aFlag is set, show all results
                    if self.aFlag:
                        self.resultsDict.setdefault(ip, []).append(
                            f"\033[38;5;87m[=] {ip} : {port} is filtered (silently dropped).\033[0m")
                        count += 1
                # if the response is received and the packet has a TCP layer
                elif response.haslayer(TCP):
                    # if the response has the SYN and ACK flags set then the port is open
                    # 0x12 is the hex value of 10010 in binary, which is the value of the flags
                    # CWR, ECE, URG, ACK, PSH, RST, SYN, FIN
                    # 0    0    0    1    0    0    1    0
                    if response.getlayer(TCP).flags == 0x12:
                        self.resultsDict.setdefault(ip, []).append(
                            f"\033[38;5;82m[+] {ip} : {port} is open.\033")
                        count += 1
                        # sending a RST packet to close the connection
                        packet = IP(dst=ip)/TCP(sport=srcPort, dport=port, flags='R')
                        response = sr(packet, verbose=0, timeout=2)
                    # if the response has the RST flag set then the port is closed
                    # 0x14 is the hex value of 10100 in binary, which is the value of the flags
                    # CWR, ECE, URG, ACK, PSH, RST, SYN, FIN
                    # 0    0    0    1    0    1    0    0
                    elif response.getlayer(TCP).flags == 0x14:
                        # if aFlag is set, show all results
                        if self.aFlag:
                            self.resultsDict.setdefault(ip, []).append(
                                f"\033[38;5;196m[-] {ip} : {port} is closed.\033[0m")
                            count += 1
                # if the response is received and the packet has an ICMP layer
                elif response.haslayer(ICMP):
                    # if the response has the ICMP type 3 then the destination is unreachable
                    if int(response.getlayer(ICMP).type) == 3:
                        if self.aFlag:
                            # using the ICMPDICT to get the meaning of the ICMP code
                            self.resultsDict.setdefault(ip, []).append(
                                f"\033[38;5;196m[-] {ip} : {port} ICMP code: {int(response.getlayer(ICMP).code)} - {ICMPDICT.get(int(response.getlayer(ICMP).code), 'Please check the code with: https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages')}.\033[0m")
                            count += 1
            if count == 0 and not self.aFlag:
                self.resultsDict.setdefault(ip, []).append(
                    f"\033[38;5;87m[=] {ip} : No open ports found.\033[0m")
            # check for verbosity flag
            if self.vFlag:
                # clear the line and print the message
                print("\r" + " " * 100, end="", flush=True)
                print(f"\r\033[38;5;82m[+] {ip} Scanned\n\033[0m")

    def tcpWIN(self) -> None:
        """
        TCP Window Scan / TCP ACK Scan but checks the window size too
        """
        for ip in self.ipL:
            count = 0
            # check for verbosity flag
            if self.vFlag:
                # clear the line and print the message
                print("\r" + " " * 100, end="", flush=True)
                print(f"\r\033[38;5;228m[*] Scanning {ip}")
            # since first 1024 ports are reserved
            srcPort = random.randint(1025, 65534)
            for port in self.portL:
                # constructing the packet with the source port as a random port, and ACK flag set
                packet = IP(dst=ip)/TCP(sport=srcPort, dport=port, flags='A')
                # sending the packet and storing the response
                # verbose=0 to suppress the output
                # timeout=2 to wait for 2 seconds for the response
                # retry=2 to retry sending the packet 2 times if no response is received
                response = sr1(packet, verbose=0, timeout=2, retry=2)
                if not response:                    # if no response is received
                    # if aFlag is set, show all results
                    if self.aFlag:
                        self.resultsDict.setdefault(ip, []).append(
                            f"\033[38;5;87m[=] {ip} : {port} is filtered (silently dropped).\033[0m")
                        count += 1
                # if the response is received and the packet has a TCP layer
                elif response.haslayer(TCP):
                    # if the window size is 0 then the port is closed
                    if response.getlayer(TCP).window > 0:
                        self.resultsDict.setdefault(ip, []).append(
                            f"\033[38;5;82m[+] {ip} : {port} is open.\033")
                        count += 1
                        # sending a RST packet to close the connection
                        packet = IP(dst=ip)/TCP(sport=srcPort, dport=port, flags='R')
                        response = sr(packet, verbose=0, timeout=2)
                    # if the window size is not 0 then the port is closed
                    else:
                        # if aFlag is set, show all results
                        if self.aFlag:
                            self.resultsDict.setdefault(ip, []).append(
                                f"\033[38;5;196m[-] {ip} : {port} is closed.\033[0m")
                            count += 1
                # if the response is received and the packet has an ICMP layer
                elif response.haslayer(ICMP):
                    # if the response has the ICMP type 3 then the destination is unreachable
                    if int(response.getlayer(ICMP).type) == 3:
                        if self.aFlag:
                            # using the ICMPDICT to get the meaning of the ICMP code
                            self.resultsDict.setdefault(ip, []).append(
                                f"\033[38;5;196m[-] {ip} : {port} ICMP code: {int(response.getlayer(ICMP).code)} - {ICMPDICT.get(int(response.getlayer(ICMP).code), 'Please check the code with: https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages')}.\033[0m")
                            count += 1
            if count == 0 and not self.aFlag:
                self.resultsDict.setdefault(ip, []).append(
                    f"\033[38;5;87m[=] {ip} : No open ports found.\033[0m")
            # check for verbosity flag
            if self.vFlag:
                # clear the line and print the message
                print("\r" + " " * 100, end="", flush=True)
                print(f"\r\033[38;5;82m[+] {ip} Scanned\n\033[0m")

    def tcpACK(self) -> None:
        """
        TCP ACK Scan / TCP ACK Ping Scan
        """
        for ip in self.ipL:
            count = 0
            # check for verbosity flag
            if self.vFlag:
                # clear the line and print the message
                print("\r" + " " * 100, end="", flush=True)
                print(f"\r\033[38;5;228m[*] Scanning {ip}")
            # since first 1024 ports are reserved
            srcPort = random.randint(1025, 65534)
            for port in self.portL:
                # constructing the packet with the source port as a random port, and ACK flag set
                packet = IP(dst=ip)/TCP(sport=srcPort, dport=port, flags='A')
                # sending the packet and storing the response
                # verbose=0 to suppress the output
                # timeout=2 to wait for 2 seconds for the response
                # retry=2 to retry sending the packet 2 times if no response is received
                response = sr1(packet, verbose=0, timeout=2, retry=2)
                if not response:                    # if no response is received
                    # if aFlag is set, show all results
                    if self.aFlag:
                        self.resultsDict.setdefault(ip, []).append(
                            f"\033[38;5;87m[=] {ip} : {port} is filtered (silently dropped).\033[0m")
                        count += 1
                # if the response is received and the packet has a TCP layer
                elif response.haslayer(TCP):
                    # if the response has the RST flag set then the port is unfilitered
                    # 0x14 is the hex value of 10100 in binary, which is the value of the flags
                    # CWR, ECE, URG, ACK, PSH, RST, SYN, FIN
                    # 0    0    0    1    0    1    0    0
                    if response.getlayer(TCP).flags == 0x14:
                        self.resultsDict.setdefault(ip, []).append(
                            f"\033[38;5;82m[+] {ip} : {port} is unfiltered.\033")
                        count += 1
                        # sending a RST packet to close the connection
                        packet = IP(dst=ip)/TCP(sport=srcPort, dport=port, flags='R')
                        response = sr(packet, verbose=0, timeout=2)
                # if the response is received and the packet has an ICMP layer
                elif response.haslayer(ICMP):
                    # if the response has the ICMP type 3 then the destination is unreachable
                    if int(response.getlayer(ICMP).type) == 3:
                        if self.aFlag:
                            # using the ICMPDICT to get the meaning of the ICMP code
                            self.resultsDict.setdefault(ip, []).append(
                                f"\033[38;5;196m[-] {ip} : {port} ICMP code: {int(response.getlayer(ICMP).code)} - {ICMPDICT.get(int(response.getlayer(ICMP).code), 'Please check the code with: https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages')}.\033[0m")
                            count += 1
            if count == 0 and not self.aFlag:
                self.resultsDict.setdefault(ip, []).append(
                    f"\033[38;5;87m[=] {ip} : No open ports found.\033[0m")
            # check for verbosity flag
            if self.vFlag:
                # clear the line and print the message
                print("\r" + " " * 100, end="", flush=True)
                print(f"\r\033[38;5;82m[+] {ip} Scanned\n\033[0m")

    def udp(self) -> None:
        """
        UDP Scan / UDP Ping Scan
        """
        for ip in self.ipL:
            count = 0
            # check for verbosity flag
            if self.vFlag:
                # clear the line and print the message
                print("\r" + " " * 100, end="", flush=True)
                print(f"\r\033[38;5;228m[*] Scanning {ip}")
            # since first 1024 ports are reserved
            srcPort = random.randint(1025, 65534)
            for port in self.portL:
                # constructing the packet with the source port as a random port, and UDP flag set
                packet = IP(dst=ip)/UDP(sport=srcPort, dport=port)
                # sending the packet and storing the response
                # verbose=0 to suppress the output
                # timeout=2 to wait for 2 seconds for the response
                # retry=2 to retry sending the packet 2 times if no response is received
                response = sr1(packet, verbose=0, timeout=2, retry=2)
                if not response:                    # if no response is received
                    # if aFlag is set, show all results
                    if self.aFlag:
                        self.resultsDict.setdefault(ip, []).append(
                            f"\033[38;5;87m[=] {ip} : {port} is either open or filtered.\033[0m")
                        count += 1
                # if the response is received and the packet has a UDP layer
                elif response.haslayer(UDP):
                    self.resultsDict.setdefault(ip, []).append(
                        f"\033[38;5;82m[+] {ip} : {port} is open.\033")
                    count += 1
                # if the response is received and the packet has an ICMP layer
                elif response.haslayer(ICMP):
                    # if the response has the ICMP type 3 then the destination is unreachable
                    if int(response.getlayer(ICMP).type) == 3:
                        if self.aFlag:
                            # using the ICMPDICT to get the meaning of the ICMP code
                            self.resultsDict.setdefault(ip, []).append(
                                f"\033[38;5;196m[-] {ip} : {port} ICMP code: {int(response.getlayer(ICMP).code)} - {ICMPDICT.get(int(response.getlayer(ICMP).code), 'Please check the code with: https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages')}.\033[0m")

    def display(self):
        for k, v in self.resultsDict.items():
            print(f"\n{k}")
            for i in v:
                print(f"{i}")