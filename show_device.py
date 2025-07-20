from scapy.all import ARP, Ether, srp
from mac_vendor_lookup import MacLookup
import socket
import time
from colorama import Fore

def scannet(ip_range, timeout=3):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=timeout, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc.lower()})
    return devices

def getname(ip):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except socket.herror:
        return "Name Unknow"

def mergehq(scans):
    merged = {}
    for scan in scans:
        for device in scan:
            key = device['mac']
            if key not in merged:
                merged[key] = device
    return list(merged.values())

if __name__ == "__main__":
    ip_range = "192.168.1.1/24" 
    scans_count = 3
    scans = []

    print(f"""
                                                                                        {Fore.WHITE}Crédit : #sendyourwomen

{Fore.RED}            ## ##   ###  ##   ## ##   ##   ##           ### ##   ### ###  ### ###    ####    ## ##   ### ###
            ##   ##   ##  ##  ##   ##  ##   ##            ##  ##   ##  ##   ##  ##     ##    ##   ##   ##  ##
            ####      ##  ##  ##   ##  ##   ##            ##  ##   ##       ##  ##     ##    ##        ##
            #####    ## ###  ##   ##  ## # ##            ##  ##   ## ##    ##  ##     ##    ##        ## ##
                ###   ##  ##  ##   ##  # ### #            ##  ##   ##       ### ##     ##    ##        ##
            ##   ##   ##  ##  ##   ##   ## ##             ##  ##   ##  ##    ###       ##    ##   ##   ##  ##
            ## ##   ###  ##   ## ##   ##   ##           ### ##   ### ###     ##      ####    ## ##   ### ###

    {Fore.RESET}""")

    print(f"{Fore.RED}[{Fore.RESET}+{Fore.RED}]{Fore.RED}{Fore.RESET} I scan your network, please wait...")

    for _ in range(scans_count):
        scan_result = scannet(ip_range, timeout=5)
        scans.append(scan_result)
        time.sleep(2)

    devices = mergehq(scans)

    if devices:
        print(f"\n{'IP':<16} {'MAC':<18} {'Name':<30}")
        print("-" * 65)
        for device in devices:
            hostname = getname(device['ip'])
            print(f"{device['ip']:<16} {device['mac']:<18} {hostname:<30}")
    else:
        print("Not found, please retry")
