# NetScanner
A basic network scanner for scanning IPs active on a subnet or scanning ports on a target.

This project is a network scanning tool that can scan a given IP address or range of addresses for active devices and open ports. It can also identify the manufacturer of the network interface using an external API. The tool is written in Python and uses various concepts such as modularity, object-oriented programming, threading, and regular expressions.

#### Features of this project:
* Taking user input via the command line using the argparse module to specify the target IP address or range of addresses and validating the input.
* Using the scapy library to send and receive ARP packets to identify the active devices on the network.
* Probing for open ports by setting flags in the TCP header as seen in common techniques such as TCP Connect Scan, Stealth Scan (TCP SYN Scan), TCP ACK Scan, TCP Window Scan and UDP Scan.
* Using an external API to identify the manufacturer of the network interface of the active devices.
* Using the threading module to run multiple threads to distribute the workload over multiple threads and speed up the scanning process.
* Usage of regular expressions to validate the user input.

#### Challenges faced in this project:
* Learning about the various network scanning techniques, how they work and how flags are set in a TCP packet header.
* Implementing multithreading and compiling the data receieved from each thread to display it to the user.
* How Class objects work in Python and how to use them to store data and methods.
* Exception Handling for the various errors that may occur during the network operations and due to faulty user input.

#### Learning Outcomes:
* Python programming, especially using the scapy, argparse, threading and re modules.
* Network scanning techniques and how to implement them using Python.
* Multithreading and how to use it to distribute workload.
* Modularity and how to use it to make the code more readable and maintainable.

# Usage
Linux:

```
chmod u+rwx netScan.py
```
^^only once^^
```
./netScan.py -h/--help
```

Windows:
```
python .\netScan.py -h/--help
```
# Dependencies
Scapy:
```
    pip3/pip install scapy
```
Windows:
   [winpcap](https://www.winpcap.org/install/default.htm) [deprecated] / [npcap](https://nmap.org/npcap/) [recommended]

Linux should have the pcap api pre installed but if it doesn't get that.

# OS Compatibility
Linux, Windows
