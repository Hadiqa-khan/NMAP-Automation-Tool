#!/usr/bin/python3
import nmap

scanner = nmap.PortScanner()
print("\n NMAP AUTOMATION TOOL")
print("-" * 60)
ip_addr = input("ENTER IP ADDRESS TO SCAN : ")
print("IP ADDRESS IS : ",ip_addr)
type(ip_addr)

resp = input("""\nSPECIFY TYPE OF SCAN 
                1) SYN ACK SCAN
                2) UDP SCAN
                3) COMPREHENSIVE SCAN 
CHOICE : """)
print("SELECTED SCAN : " , resp)
if resp == '1' :
    print("NMAP VERSION : " , scanner.nmap_version())
    print("""\nSYN ACK SCAN WORKING 
                It will send a SYN Packet in an attempt to open a Connection.    
                SYN/ACK Response indicate a open TCP PORT.
        """)
    print("[+] SCANNING PORT 1-1024 with FLAGS -v -sS")
    scanner.scan(ip_addr,'1-1024','-v -sS')
    print("-"*50)
    print("SCAN INFO ")
    print("-"*50)
    for k,v in scanner.scaninfo().items():
        # print(k.upper())
        for key,value in v.items():
            print(key.upper(),value)
    print("IP STATUS  " , scanner[ip_addr].state())
    print("\nPROTOCOL ")
    print(scanner[ip_addr].all_protocols()[0].upper())
    print("\nOPEN PORTS") 
    for k,v in scanner[ip_addr]['tcp'].items():
        print("Port " + str(k) +'\t State ' + scanner[ip_addr]['tcp'][k]['state'])
elif resp == '2':
    print("NMAP VERSION : " , scanner.nmap_version())
    print("""\nUDP SCAN WORKING 
                It will send a UDP Packet to every target.
        """)
    print("[+] SCANNING PORT 1-1024 with FLAGS -v -sU")
    scanner.scan(ip_addr,'1-1024','-v -sU')
    print("-"*50)
    print("SCAN INFO ")
    print("-"*50)
    for k,v in scanner.scaninfo().items():
        # print(k.upper())
        for key,value in v.items():
            print(key.upper(),value)
    print("IP STATUS  " , scanner[ip_addr].state())
    print("\nPROTOCOL ")
    print(scanner[ip_addr].all_protocols()[0].upper())
    print("\nOPEN PORTS") 
    for k,v in scanner[ip_addr]['tcp'].items():
        print("Port " + str(k) +'\t State ' + scanner[ip_addr]['tcp'][k]['state'])
elif resp == '3':
    print("NMAP VERSION : " , scanner.nmap_version())
    print("""\nA COMPREHENSIVE SCAN
                It will use TCP and perform a comprehensive 
                scan on target  """)
    print("\n[+] SCANNING PORT 1-1024 with FLAGS -v -sS -sV -sC -A -O")
    scanner.scan(ip_addr,'1-1024','-v -sS -sV -sC -A -O')
    print("-"*50)
    print("SCAN INFO ")
    print("-"*50)
    for k,v in scanner.scaninfo().items():
        # print(k.upper())
        for key,value in v.items():
            print(key.upper(),value)
    print("IP STATUS  " , scanner[ip_addr].state())
    print("\nPROTOCOL ")
    print(scanner[ip_addr].all_protocols()[0].upper())
    print("\nOPEN PORTS") 
    for k,v in scanner[ip_addr]['tcp'].items():
        print("Port " + str(k) +'\t State ' + scanner[ip_addr]['tcp'][k]['state'])
elif resp >='4':
    print("[-] ENTER A VALID INPUT !")