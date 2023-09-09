# NetScanner
A basic network scanner for scanning IPs active on a subnet or scanning ports on a target.

# Usage
python3 netScan.py 
-t/--target (Target IP Range / IP address)[Required] 
-p/--port (Target port to scan)[Optional] 
-s/--scan-type (the type of port scan to perform. DEFAULT: TCP Connect Scan)[Optional]
-d/--default (TCP Connect Scan of the first 1000 ports of the Target IP)[Optional]

# Dependencies
Scapy:
    pip3 install scapy
