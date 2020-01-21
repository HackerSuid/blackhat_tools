#!/usr/bin/python3

import argparse
import os
from scapy.utils import RawPcapReader
from scapy.layers.dot11 import Dot11,RadioTap
import sys

def proc_pcap(filename):
    print('[*] Opening %s for analysis...' % filename)

    c = 0

    for (pkt_data, pkt_metadata,) in RawPcapReader(filename):
        c += 1
        dot11_layer = Dot11(pkt_data)
        pkt = RadioTap()/dot11_layer
        pdb.set_trace()
        print(pkt.mysummary())
        if c>1:
            break

    print('[*] %s contains %s packets.' % (filename, c))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PCAP reader')
    parser.add_argument('--pcap', metavar='<pcap filename>',
                       help='pcap file to parse', required=True)
    args = parser.parse_args()

    filename = args.pcap
    if not os.path.isfile(filename):
        print('%s does not exist.' % filename)
        sys.exit(-1)

    addr1='aa:aa:aa:aa:aa'
    addr2='bb:bb:bb:bb:bb'
    addr3='cc:cc:cc:cc:cc'
    dot11layer = Dot11(type=1, subtype=11, addr1=addr1, addr2=addr2, addr3=addr3, ID=0x99)
    pkt = RadioTap()/dot11layer
    import pdb; pdb.set_trace()

    proc_pcap(filename)
    sys.exit(0)

