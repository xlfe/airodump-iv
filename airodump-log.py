"""
    airdump-log is a utility which sniffs 802.11X activity and logs interesting events
"""

import os
from datetime import datetime
import json
from optparse import OptionParser
from random import randint
from scapy.all import sniff
from scapy.layers.dot11 import Dot11
from scapy.layers.dot11 import Dot11Auth
from scapy.layers.dot11 import Dot11Beacon
from scapy.layers.dot11 import Dot11ProbeReq
from scapy.layers.dot11 import Dot11ProbeResp
from scapy.layers.dot11 import RadioTap
import scapy_ex
import logging

from we import WirelessExtension

BROADCAST_BSSID = 'ff:ff:ff:ff:ff:ff'

log = logging.getLogger('airodump')
log.setLevel(logging.DEBUG)

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

sh = logging.StreamHandler()
sh.setFormatter(formatter)
log.addHandler(sh)



class OUILookup(object):

    re = r'\w'

    def __init__(self):
        self.lookup = {}

        for p in ["/etc/aircrack-ng", "/usr/local/etc/aircrack-ng", "/usr/share/aircrack-ng"]:

            oui_library = os.path.join(p, 'airodump-ng-oui.txt')

            if os.path.exists(oui_library):

                with open(oui_library, 'r') as ol:

                    for line in ol:
                        msb,_, manuf = line.split('\t')

                        self.lookup[msb[:8]] = manuf.strip()

                return

        raise Exception('OUI library not found')

    def find(self, msb):
        lu = '-'.join(msb.split(':')[:3])
        try:
            return self.lookup[lu.upper()]
        except KeyError:
            return 'Unknown'



class Dot11ScannerOptions:
    """A collection of options to control how the script runs"""

    def __init__(self):
        self.iface = ''
        self.channel = -1
        self.channel_hop = True
        self.max_channel = -1

    @staticmethod
    def create_scanner_options():
        """A class factory which parses command line options and returns a Dot11ScannerOptions instance"""
        parser = OptionParser()
        parser.add_option('-i', '--iface', dest='iface', default='wlan0mon',
                          help='Interface to bind to')
        parser.add_option('-c', '--channel', dest='channel', default=-1, type='int',
                          help='Channel to bind to')
        parser.add_option('-v', '--verbose', dest='verbose', default=False, action='store_true',
                          help='Print verbose information')
        options, _ = parser.parse_args()

        scanner_options = Dot11ScannerOptions()
        scanner_options.iface = options.iface
        scanner_options.we = WirelessExtension(scanner_options.iface)
        scanner_options.channel = options.channel
        scanner_options.channel_hop = options.channel == -1
        scanner_options.max_channel = scanner_options.we.get_max_channel()

        return scanner_options

oui_lookup = OUILookup()

class Dot11Scanner:
    def __init__(self, scanner_options):
        self.scanner_options = scanner_options
        self.channel = None

    def parse_packet(self, packet):

        assert packet.haslayer(Dot11), packet.show()

        bssid = packet[Dot11].ap_bssid()

        if packet.haslayer(Dot11Beacon):
            #Beacon from Access Point

            assert bssid != BROADCAST_BSSID

            details = dict(
                type = 'ap_beacon',
                mac = bssid,
                ssid = packet[Dot11].essid(),
                channel = packet[Dot11].channel() or packet[RadioTap].Channel,
                power = packet[RadioTap].dBm_AntSignal,
                oui=oui_lookup.find(bssid)
            )

        elif packet.haslayer(Dot11ProbeReq):
            # Station looking for an Access Point
            assert bssid == BROADCAST_BSSID

            sta_bssid = packet[Dot11].sta_bssid()

            details = dict(
                type = 'sta_probe',
                mac = sta_bssid,
                ssid = packet[Dot11].essid(),
                channel = self.channel,
                power = packet[RadioTap].dBm_AntSignal,
                oui=oui_lookup.find(sta_bssid)
            )

        else:
            return False
            details = dict(
                unknown=packet.__class__.__name__
            )

        log.debug(json.dumps(details, sort_keys=True))

        return False


    def scan(self, window=None):

        if self.scanner_options.channel_hop:
            self.scanner_options.channel = randint(1, self.scanner_options.max_channel)
            self.set_channel(self.scanner_options.channel)
        elif -1 != self.scanner_options.channel:
            self.set_channel(self.scanner_options.channel)

        while True:
            sniff(
                    iface=self.scanner_options.iface,
                    store=False,
                    count=0,
                    offline=None,
                    timeout=3,
                    lfilter=self.parse_packet
            )

            if self.scanner_options.channel_hop:
                self.scanner_options.channel = ((
                                                self.scanner_options.channel + 3) % self.scanner_options.max_channel) + 1
                self.set_channel(self.scanner_options.channel)


    def set_channel(self, channel):
        self.scanner_options.we.set_channel(channel)
        self.channel = channel

if __name__ == '__main__':

    scanner_options = Dot11ScannerOptions.create_scanner_options()
    scanner = Dot11Scanner(scanner_options)
    scanner.scan()



