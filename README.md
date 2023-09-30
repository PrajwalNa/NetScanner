# NetScanner
A basic network scanner for scanning IPs active on a subnet or scanning ports on a target.

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
Windows/ and if you're Linux distro doesn't already have npcap get that:

    [winpcap](https://www.winpcap.org/install/default.htm) [deprecated] / [npcap](https://nmap.org/npcap/) [recommended]

# OS Compatibility
Linux, Windows
