#!/usr/bin/python3

import argparse
from datetime import datetime
from scapy.all import sniff, Dot11
from scapy.layers.dot11 import Dot11Beacon
from scapy.layers.dot11 import Dot11Elt
from scapy.layers.dot11 import Dot11ProbeReq
from scapy.layers.dot11 import Dot11ProbeResp
from scapy.layers.dot11 import RadioTap
import logging
import time

IGNORE_SET = set(['00:00:00:00:00:00', '01:01:01:01:01:01'])
PROBE_SET = set()
d = {'00:00:00:00:00:00':'Example MAC Address'}


def process_packet(pkt):
    if not pkt.haslayer(RadioTap):
        return
    if pkt.haslayer(Dot11ProbeReq):
        logging.info("Probe request received.")
    if pkt.haslayer(Dot11ProbeResp):
        logging.info("Probe response received.")
    if pkt.haslayer(Dot11Beacon):
        logging.info("Beacon frame received.")
        # Log access point addr, name, and some information
        ap_mac = pkt.addr2
        bcn = pkt.getlayer(Dot11Beacon, 1)
        ap_ssid = bcn.getlayer(Dot11Elt, 1).info
    #if pkt.type == 0 and pkt.subtype == 4: # management + probe request
    #    mac = pkt.addr2.upper()
    #    logging.debug('Probe request captured! '+mac)
    #    SEEN_DEVICES.add(mac)
    #    if mac not in IGNORE_SET:
    #        if mac not in d:
    #            logging.info('\033[92m' + 'Probe Recorded from MAC ' + pkt.addr2 + '\033[0m') #Log to file with green color
    #            print('\033[95m' + 'Device MAC: {pkt.addr2} '
    #                'with SSID: {pkt.info}'.format(pkt=pkt) + '\033[0m') #Print to command line with green color
    #        else:
    #            logging.info('\033[95m' + 'Probe Recorded from ' + '\033[93m' + d[curmac] + '\033[95m' + ' with MAC ' + curmac + '\033[0m') #Log to file with purple color
    #            print('\033[95m' + 'Probe MAC Address: ' + pkt.addr2 + ' from device ' + '\033[93m' + d[curmac] + '\033[0m')
    #                  #'with SSID: {pkt.info}'.format(pkt=pkt)) #Print to command line with purple color
    #        #print SEEN_DEVICES #Just for debug, prints all known devices
    #        #dump()
    #else:
    #    logging.debug('Type %s Subtype %s' % (pkt.type, pkt.subtype))

def main():
    logging.basicConfig(format='%(asctime)s %(message)s',
                        datefmt='%m/%d/%Y %I:%M:%S %p',
                        filename='dot11_watcher.log',
                        level=logging.DEBUG)
    logging.info('\n'+'\033[93m'+'Dot11 watcher starting'+'\033[0m'+'\n')
    
    parser = argparse.ArgumentParser()
    parser.add_argument('--interface', '-i', default='wlan0mon',
                        help='monitor mode enabled interface')
    args = parser.parse_args()
    logging.info('Sniffing packets on interface %s' % args.interface)
    sniff(iface=args.interface, prn=process_packet)
    while 1:
        time.sleep(1) # Supposed to make an infinite loop, but for some reason it stops after a while
if __name__ == '__main__':
    main()

