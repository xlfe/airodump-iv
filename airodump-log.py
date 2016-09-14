"""
    airdump-log is a utility which sniffs 802.11X activity and logs interesting events
"""

import os
from datetime import datetime, timedelta
import json
import collections
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
from threading import Timer


from we import WirelessExtension

BROADCAST_BSSID = 'ff:ff:ff:ff:ff:ff'

log = logging.getLogger('airodump')
log.setLevel(logging.INFO)
sh = logging.StreamHandler()
log.addHandler(sh)

Event = collections.namedtuple('event', field_names=['timestamp','power'])

class Observations(object):
    """
    Track observations
    Emit a event at least every TIME_PERIOD
    And if they deviate from 90% of their TIME_PERIOD average, emit an event straight away
    """
    TIME_PERIOD = 300

    KEYS = [
        'type',
        'mac',
        'ssid'
    ]

    TRACK = [
        'power'
    ]

    def __init__(self, details):
        self.details = details
        self.events = []
        self.timeout = None
        self.LAST_EMIT = None

    @classmethod
    def sig(cls, details):
        return '-'.join(details[k] for k in cls.KEYS)

    def emit(self):
        self.LAST_EMIT = datetime.now()
        d = self.details.copy()
        d['avg_power'] = '{:.2f}'.format(self.p_avg)
        d['count'] = len(self.events)
        print json.dumps(d, sort_keys=True)

    @property
    def p_avg(self):

        p_sum = sum(e.power for e in self.events)
        try:
            p_avg = (p_sum*1.0) / len(self.events)
        except ZeroDivisionError:
            p_avg = 0
        return p_avg

    def expire(self):

        self.purge()

        now = datetime.now()
        if self.LAST_EMIT is None:
            self.emit()
            return
        if (now - self.LAST_EMIT).total_seconds() > self.TIME_PERIOD:
            self.emit()

    def reset(self):

        if self.timeout:
            self.timeout.cancel()
        self.timeout = Timer(self.TIME_PERIOD, self.expire)
        self.timeout.start()

    def event(self, d):
        #remove old events
        self.purge()

        power = abs(int(d['power']))
        self.details['power'] = d['power']

        p_avg = self.p_avg
        diff = abs(p_avg - power)

        if diff > p_avg * 0.15:
            self.emit()

        self.events.append(Event(datetime.now(), power))
        self.reset()

    def purge(self):
        cutoff = datetime.now() - timedelta(seconds=self.TIME_PERIOD)
        self.events = filter(lambda e: e.timestamp > cutoff, self.events)


log_keeper = {}


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

            # assert bssid != BROADCAST_BSSID

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
        #     details = dict(
        #         unknown=packet.__class__.__name__
        #     )

        key = Observations.sig(details)
        if key not in log_keeper:
            log_keeper[key] = Observations(details)
        log_keeper[key].event(details)
        # log.debug(json.dumps(details, sort_keys=True))

        return False


    def scan(self, window=None):

        while True:
            self.scanner_options.channel = randint(1, self.scanner_options.max_channel)
            self.set_channel(self.scanner_options.channel)

            sniff(
                    iface=self.scanner_options.iface,
                    store=False,
                    count=0,
                    offline=None,
                    timeout=1,
                    lfilter=self.parse_packet
            )


    def set_channel(self, channel):
        self.scanner_options.we.set_channel(channel)
        self.channel = channel

if __name__ == '__main__':

    scanner_options = Dot11ScannerOptions.create_scanner_options()
    scanner = Dot11Scanner(scanner_options)
    scanner.scan()



