#!/usr/bin/python3

'''
After intruding into a (w)lan, this script
automates scanning the network for devices and
identifying what they are.
'''

import arpreq
import ipaddress
import json
from mac_vendor_lookup import MacLookup
import netifaces
import nmap
import pprint
from pyroute2 import IPRoute
import sys

hosts_info = {}

def_gate = netifaces.gateways()['default'][netifaces.AF_INET]
dev = def_gate[1]

'''
Need to run macchanger before scanning the network.
'''

# Linux rtnetlink protocol module used to disable
# network interface before changing MAC address.
print("[DBG] Looking up %s netlink attributes" % dev)
ip = IPRoute()
attrs = { 'IFLA_OPERSTATE': None,
          'IFLA_ADDRESS': None }
idx = ip.link_lookup(ifname=dev)[0]
link = ip.get_links(idx)[0]
for a in attrs.keys():
    attrs[a] = link.get_attr(a)

print(attrs)
if attrs['IFLA_OPERSTATE'] == 'UP':
    print("\t[*] %s found up, setting link down." % dev)
    #ip.link('set', index=idx, state='down')
sys.exit()

ip_info = netifaces.ifaddresses(dev)[netifaces.AF_INET]
addr = ip_info[0]["addr"]
netmask = ip_info[0]["netmask"]
network = ipaddress.ip_network("%s/%s" % (addr, netmask), strict=False)

start = network.network_address+1
end = network.broadcast_address

maclookup = MacLookup()
nmap = nmap.PortScanner()

#for ipint in range(int(start), int(end)):
for ipint in range(int(start), int(start)+1):
    ip = ipaddress.IPv4Address(ipint)
    ipstr = str(ip)
    hosts_info[ipstr] = {}
    mac = arpreq.arpreq(ip)
    vendor = None

    if mac is not None:
        vendor = maclookup.lookup(mac)
        scan_result = {}
        nmap.scan(hosts=ipstr, ports='1-1000', arguments='-sS -O')
        scan_result['os'] = nmap[ipstr]['osmatch'][0]['name']
        scan_result['open_tcp'] = [p for p in nmap[ipstr]['tcp']]
        #nmap.scan(hosts=ipstr, ports='1-1000', arguments='-sU')
        #print(nmap[ipstr]['udp'])

    hardware_info = [mac, vendor]
    hosts_info[ipstr]['hardware'] = hardware_info
    hosts_info[ipstr]['scan_result'] = scan_result

pprint.pprint(hosts_info)
