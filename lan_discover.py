#!/usr/bin/python3

import arpreq
import ipaddress
from mac_vendor_lookup import MacLookup
import netifaces
import sys

def_gate = netifaces.gateways()['default'][netifaces.AF_INET]
dev = def_gate[1]

ip_info = netifaces.ifaddresses(dev)[netifaces.AF_INET]
addr = ip_info[0]["addr"]
netmask = ip_info[0]["netmask"]
network = ipaddress.ip_network("%s/%s" % (addr, netmask), strict=False)

start = network.network_address+1
end = network.broadcast_address
print("ARP scanning network %s (%s - %s)" %
    (network.network_address, start, end-1))

print("Downloading OUI list...")
maclookup = MacLookup()

for ipint in range(int(start), int(end)):
    ip = ipaddress.IPv4Address(ipint)
    mac = arpreq.arpreq(ip)
    if mac is not None:
        vendor = maclookup.lookup(mac)
        print("\t%s %s (%s)" % (ip, mac, vendor))
    else:
        print("\t%s <no host>" % ip)
