"""
A set of additions and modifications to scapy to assist in parsing dot11
"""
import scapy

from scapy.fields import *
from scapy.layers.dot11 import Dot11Elt
from scapy.layers.dot11 import Dot11ProbeReq
from scapy.packet import Packet
from collections import OrderedDict
from printer import Printer


class SignedByteField(Field):
	"""Fields for a signed byte"""
	def __init__(self, name, default):
		Field.__init__(self, name, default, '<b')


class LESignedShortField(Field):
	"""Field for a little-endian short"""
	def __init__(self, name, default):
		Field.__init__(self, name, default, '<h')

def scapy_flags_field_hasflag(self, pkt, x, val):
	return (1 << self.names.index([val])) & x

FlagsField.hasflag = scapy_flags_field_hasflag
del scapy_flags_field_hasflag

def scapy_packet_Packet_hasflag(self, field_name, value):
	"""Is the specified flag value set in the named field"""
	field, val = self.getfield_and_val(field_name)
	if isinstance(field, EnumField):
		if val not in field.i2s:
			return False
		return field.i2s[val] == value
	else:
		return (1 << field.names.index([value])) & self.__getattr__(field_name) != 0
scapy.packet.Packet.hasflag = scapy_packet_Packet_hasflag
del scapy_packet_Packet_hasflag

# fix scapy's endianness problem on big-endian host (make rev take effect)
def scapy_fields_BitField_getfield(self, pkt, s):
		if type(s) is tuple:
			s,bn = s
		else:
			bn = 0
		# we don't want to process all the string
		nb_bytes = (self.size+bn-1)/8 + 1
		w = s[:nb_bytes]

		# split the substring byte by byte
		bytes = struct.unpack('!%dB' % nb_bytes , w)

		if self.rev:
			bytes = list(reversed(bytes))

		b = 0L
		for c in range(nb_bytes):
			b |= long(bytes[c]) << (nb_bytes-c-1)*8

		# get rid of high order bits
		b &= (1L << (nb_bytes*8-bn)) - 1

		# remove low order bits
		b = b >> (nb_bytes*8 - self.size - bn)

		bn += self.size
		s = s[bn/8:]
		bn = bn%8
		b = self.m2i(pkt, b)
		if bn:
			return (s,bn),b
		else:
			return s,b
BitField.getfield = scapy_fields_BitField_getfield
del scapy_fields_BitField_getfield

def scapy_fields_FieldListField_i2repr(self, pkt, x):
	"""Return a list with the representation of contained fields"""
	return repr([self.field.i2repr(pkt, v) for v in x])
FieldListField.i2repr = scapy_fields_FieldListField_i2repr
del scapy_fields_FieldListField_i2repr


class ChannelFromMhzField(LEShortField):
	"""A little-endian short field that converts from mhz to channel"""
	def m2i(self, pkt, x):
		return min(14, max(1, (x - 2407) / 5))

# list of FlagsField
class PresentFlagsField(FieldListField):
	def __init__(self, name, default, field, length_from=None, count_from=None):
		FieldListField.__init__(self, name, default, field, length_from=None, count_from=None)

	def getfield(self, pkt, s):
		if self.length_from is not None or self.count_from is not None:
			# Printer.write("FieldListField.getfield called")
			return FieldListField.getfield(self, packet, s)
		# Printer.write("PresentFlagsField.getfield called")
		val=[]
		while s:
			s, v = self.field.getfield(pkt, s)
			# Printer.write('PresentFlagsField.getfield: {0:08X}'.format(v))
			val.append(v)
			if not self.field.hasflag(pkt, v, 'Ext'):
				break
		return s, val

	def hasflag(self, pkt, x, val, index = 0):
		return self.field.hasflag(pkt, x[index], val)

def packet_hasPresentFlag(self, val, index = 0):
	field, x = self.getfield_and_val('Present_flags')
	return field.hasflag(self, x, val, index)

# adjust offset to read field data when alignment required
class AlignedField:
	def __init__(self, fld, align=None):
		if align is None:
			align = fld.sz # TODO: round size to nature bound
		self.align = align
		self.fld = fld

	def getfield(self, pkt, s):
		remain = (pkt.pre_dissect_len - len(s)) % self.align
		if remain:
			s = s[self.align - remain:]
		return self.fld.getfield(pkt, s)

	def __getattr__(self, attr):
		return getattr(self.fld, attr)

class PresentField(ConditionalField):
	"""Utility field for use by RadioTap"""
	def __init__(self, field, flag_name, index = 0):
		ConditionalField.__init__(self, field, lambda pkt: packet_hasPresentFlag(pkt, flag_name, index))

class RTapFields(Field):
	def __init__(self, name, default, flds, index = 0):
		if default is None:
			default = []
		Field.__init__(self, name, default)
		self.index = index # position in all RTapFields List
		self.pairs = flds

	def getfield(self, pkt, s):
		val = dict()
		field, x = pkt.getfield_and_val('Present_flags')
		present_field = field.field
		x = x[self.index]

		for field, flag_name in self.pairs:
			if present_field.hasflag(pkt, x, flag_name):
				s,v = field.getfield(pkt, s)
				val[field.name] = v
		return s, val

	def i2repr(self, pkt, x):
		return dict((k, v) for k, v in x.items() if v is not None)

class RTapData(FieldListField):
	def __init__(self, name, default, fld_pairs, length_from=None, count_from=None):
		if count_from is None:
			count_from = lambda pkt: len(pkt.Present_flags)
		FieldListField.__init__(self, name, None, RTapFields('Radiotap_field', None, fld_pairs), length_from, count_from)
		self.fld_pairs = fld_pairs

	def getfield(self, pkt, s): #TODO
		c = l = None
		if self.length_from is not None:
			l = self.length_from(pkt)
		elif self.count_from is not None:
			c = self.count_from(pkt)

		val = []
		ret = ""
		index = 0
		self.flds = []
		if l is not None:
			s,ret = s[:l],s[l:]

		while s:
			if c is not None:
				if index >= c:
					break
			fld = RTapFields('Radiotap_field', None, self.fld_pairs, index)
			self.flds.append(fld)
			s,v = fld.getfield(pkt, s)
			val.append(v)
			index += 1
		return s+ret, val

# TODO(ivanlei): This fields_desc does not cover chained present flags decode will fail in this cases
scapy.layers.dot11.RadioTap.name = '802.11 RadioTap'

# Greatly improved fields_desc for RadioTap which parses known present flags
scapy.layers.dot11.RadioTap.fields_desc = [
	ByteField('version', 0),
	ByteField('pad', 0),
	LEShortField('RadioTap_len', 0),
	PresentFlagsField('Present_flags', None, FlagsField('present', None, -32, ['TSFT','Flags','Rate','Channel','FHSS','dBm_AntSignal',
									  'dBm_AntNoise','Lock_Quality','TX_Attenuation','dB_TX_Attenuation',
									  'dBm_TX_Power', 'Antenna', 'dB_AntSignal', 'dB_AntNoise',
									  'b14', 'b15','b16','b17','b18','b19','b20','b21','b22','b23',
									  'b24','b25','b26','b27','b28','b29','b30','Ext']), None, None),
	RTapData('Radiotap_data', None,
		[
			[AlignedField(LELongField('TSFT', 0), 8), 'TSFT'],
			[ByteField('Flags', 0), 'Flags'],
			[ByteField('Rate', 0), 'Rate'],
			[AlignedField(ChannelFromMhzField('Channel', 0), 2), 'Channel'],
			[LEShortField('Channel_flags', 0), 'Channel'],
			[ByteField('FHSS_hop_set', 0), 'FHSS'],
			[ByteField('FHSS_hop_pattern', 0), 'FHSS'],
			[SignedByteField('dBm_AntSignal', 0), 'dBm_AntSignal'],
			[SignedByteField('dBm_AntNoise', 0), 'dBm_AntNoise'],
			[AlignedField(LEShortField('Lock_Quality', 0)), 'Lock_Quality'],
			[AlignedField(LEShortField('TX_Attenuation', 0)), 'TX_Attenuation'],
			[AlignedField(LEShortField('db_TX_Attenuation', 0)), 'dB_TX_Attenuation'],
			[SignedByteField('dBm_TX_Power', 0), 'dBm_TX_Power'],
			[ByteField('Antenna', 0), 'Antenna'],
			[ByteField('dB_AntSignal', 0), 'dB_AntSignal'],
			[ByteField('dB_AntNoise', 0), 'dB_AntNoise'],
			[AlignedField(LEShortField('RX_Flags', 0)), 'b14'],
			[Field('MCS', 0, '3B'), 'b19'],
			[AlignedField(Field('A-MPDU', 0, '<IHBB'), 4), 'b20']
		])
]


def scapy_layers_dot11_RadioTap_extract_padding(self, s):
	"""Ignore any unparsed conditionally present fields

	If all fields have been parsed, the payload length should have decreased RadioTap_len bytes
	If it has not, there are unparsed fields which should be treated as padding
	"""
	padding = len(s) - (self.pre_dissect_len - self.RadioTap_len)
	if padding:
		return s[padding:], s[:padding]
	else:
		return s, None
scapy.layers.dot11.RadioTap.extract_padding = scapy_layers_dot11_RadioTap_extract_padding
del scapy_layers_dot11_RadioTap_extract_padding


def scapy_layers_dot11_RadioTap_pre_dissect(self, s):
	"""Cache to total payload length prior to dissection for use in finding padding latter"""
	self.pre_dissect_len = len(s)
	return s
scapy.layers.dot11.RadioTap.pre_dissect = scapy_layers_dot11_RadioTap_pre_dissect
del scapy_layers_dot11_RadioTap_pre_dissect

def scapy_layers_dot11_RadioTap_post_dissect(self, s):
	for k, v in self.Radiotap_data[0].items():
		setattr(self, k, v)
scapy.layers.dot11.RadioTap.post_dissection = scapy_layers_dot11_RadioTap_post_dissect
del scapy_layers_dot11_RadioTap_post_dissect

class Dot11EltRates(Packet):
	"""The rates member contains an array of supported rates"""

	name = '802.11 Rates Information Element'

	# Known rates come from table in 6.5.5.2 of the 802.11 spec
	known_rates = {
		  2 :  1,
		  3 :  1.5,
		  4 :  2,
		  5 :  2.5,
		  6 :  3,
		  9 :  4.5,
		 11 :  5.5,
		 12 :  6,
		 18 :  9,
		 22 : 11,
		 24 : 12,
		 27 : 13.5,
		 36 : 18,
		 44 : 22,
		 48 : 24,
		 54 : 27,
		 66 : 33,
		 72 : 36,
		 96 : 48,
		108 : 54
	}

	fields_desc = [
		ByteField('ID', 0),
		FieldLenField("len", None, "info", "B"),
		FieldListField('supported_rates', None, ByteField('', 0), count_from=lambda pkt: pkt.len),
	]

	def post_dissection(self, pkt):
		self.rates = []
		for supported_rate in self.supported_rates:
			# check the msb for each rate
			rate_msb = supported_rate & 0x80
			rate_value = supported_rate & 0x7F
			if rate_msb:
				# a value of 127 means HT PHY feature is required to join the BSS
				if 127 != rate_value:
					self.rates.append(rate_value/2)
			elif rate_value in Dot11EltRates.known_rates:
				self.rates.append(Dot11EltRates.known_rates[rate_value])


class Dot11EltExtendedRates(Dot11EltRates):
	"""The rates member contains an additional array of supported rates"""

	name = '802.11 Extended Rates Information Element'


class Dot11EltRSN(Packet):
	"""The enc, cipher, and auth members contain the decoded 'security' details"""

	name = '802.11 RSN Information Element'

	cipher_suites = { '\x00\x0f\xac\x00': 'GROUP',
					  '\x00\x0f\xac\x01': 'WEP',
					  '\x00\x0f\xac\x02': 'TKIP',
					  '\x00\x0f\xac\x04': 'CCMP',
					  '\x00\x0f\xac\x05': 'WEP' }

	auth_suites = { '\x00\x0f\xac\x01': 'MGT',
					'\x00\x0f\xac\x02': 'PSK' }

	fields_desc = [
		ByteField('ID', 0),
		FieldLenField("len", None, "info", "B"),
		LEShortField('version', 1),
		StrFixedLenField('group_cipher_suite', '', length=4),
		LEFieldLenField('pairwise_cipher_suite_count', 1, count_of='pairwise_cipher_suite'),
		FieldListField('pairwise_cipher_suite', None, StrFixedLenField('','', length=4), count_from=lambda pkt: pkt.pairwise_cipher_suite_count),
		LEFieldLenField('auth_cipher_suite_count', 1, count_of='auth_cipher_suite'),
		FieldListField('auth_cipher_suite', None, StrFixedLenField('','',length=4), count_from=lambda pkt: pkt.auth_cipher_suite_count),
		BitField('rsn_cap_pre_auth', 0, 1),
		BitField('rsn_cap_no_pairwise', 0, 1),
		BitField('rsn_cap_ptksa_replay_counter', 0, 2),
		BitField('rsn_cap_gtksa_replay_counter', 0, 2),
		BitField('rsn_cap_mgmt_frame_protect_required', 0, 1),
		BitField('rsn_cap_mgmt_frame_protect_capable', 0, 1),
		BitField('rsn_cap_reserved_1', 0, 1),
		BitField('rsn_cap_peer_key_enabled', 0, 1),
		BitField('rsn_cap_reserved_2', 0, 6),
	]

	def post_dissection(self, pkt):
		"""Parse cipher suites to determine encryption, cipher, and authentication methods"""

		self.enc = 'WPA2' # Everything is assumed to be WPA
		self.cipher = ''
		self.auth = ''

		ciphers = [self.cipher_suites.get(pairwise_cipher) for pairwise_cipher in self.getfieldval('pairwise_cipher_suite')]
		if 'GROUP' in ciphers:
			ciphers = [self.cipher_suites.get(group_cipher, '') for group_cipher in self.getfieldval('group_cipher_suite')]
		for cipher in ['CCMP', 'TKIP', 'WEP']:
			if cipher in ciphers:
				self.cipher = cipher
				break

		if 'WEP' == self.cipher:
			self.enc = 'WEP'

		for auth_cipher in self.getfieldval('auth_cipher_suite'):
			self.auth = self.auth_suites.get(auth_cipher, '')
			break


def scapy_layers_dot11_Dot11_elts(self):
	"""An iterator of Dot11Elt"""
	dot11elt = self.getlayer(Dot11Elt)
	while dot11elt and dot11elt.haslayer(Dot11Elt):
		yield dot11elt
		dot11elt = dot11elt.payload
scapy.layers.dot11.Dot11.elts = scapy_layers_dot11_Dot11_elts
del scapy_layers_dot11_Dot11_elts


def scapy_layers_dot11_Dot11_find_elt_by_id(self, id):
	"""Iterate over elt and return the first with a specific ID"""
	for elt in self.elts():
		if elt.ID == id:
			return elt
	return None
scapy.layers.dot11.Dot11.find_elt_by_id = scapy_layers_dot11_Dot11_find_elt_by_id
del scapy_layers_dot11_Dot11_find_elt_by_id


def scapy_layers_dot11_Dot11_essid(self):
	"""Return the payload of the SSID Dot11Elt if it exists"""
	elt = self.find_elt_by_id(0)
	return elt.info if elt else None
scapy.layers.dot11.Dot11.essid = scapy_layers_dot11_Dot11_essid
del scapy_layers_dot11_Dot11_essid


def scapy_layers_dot11_Dot11_rates(self, id=1):
	"""Return the payload of the rates Dot11Elt if it exists"""
	elt = self.find_elt_by_id(id)
	if elt:
		try:
			return Dot11EltRates(str(elt)).rates
		except Exception, e:
			Printer.error('Bad Dot11EltRates got[{0:s}]'.format(elt.info))
			Printer.exception(e)
	return []
scapy.layers.dot11.Dot11.rates = scapy_layers_dot11_Dot11_rates
del scapy_layers_dot11_Dot11_rates


def scapy_layers_dot11_Dot11_extended_rates(self):
	"""Return the payload of the extended rates Dot11Elt if it exists"""
	return scapy.layers.dot11.Dot11.rates(self, 50)
scapy.layers.dot11.Dot11.extended_rates = scapy_layers_dot11_Dot11_extended_rates
del scapy_layers_dot11_Dot11_extended_rates


def scapy_layers_dot11_Dot11_sta_bssid(self):
	"""Return the bssid for a station associated with the packet"""
	if self.haslayer(Dot11ProbeReq) or self.hasflag('FCfield', 'to-DS'):
		return self.addr2
	else:
		return self.addr1
scapy.layers.dot11.Dot11.sta_bssid = scapy_layers_dot11_Dot11_sta_bssid
del scapy_layers_dot11_Dot11_sta_bssid


def scapy_layers_dot11_Dot11_ap_bssid(self):
	"""Return the bssid for a access point associated with the packet"""
	if self.haslayer(Dot11ProbeReq) or self.hasflag('FCfield', 'to-DS'):
		return self.addr1
	else:
		return self.addr2
scapy.layers.dot11.Dot11.ap_bssid = scapy_layers_dot11_Dot11_ap_bssid
del scapy_layers_dot11_Dot11_ap_bssid


def scapy_layers_dot11_Dot11_channel(self):
	"""Return the payload of the channel Dot11Elt if it exists"""
	elt = self.find_elt_by_id(3)
	if elt:
		try:
			return int(ord(elt.info))
		except Exception, e:
			Printer.error('Bad Dot11Elt channel got[{0:s}]'.format(elt.info))
			Printer.exception(e)
	return None
scapy.layers.dot11.Dot11.channel = scapy_layers_dot11_Dot11_channel
del scapy_layers_dot11_Dot11_channel


def scapy_layers_dot11_Dot11_rsn(self):
	"""Return the payload of the RSN Dot11Elt as a Dot11EltRSN"""
	elt = self.find_elt_by_id(48)
	if elt:
		try:
			return Dot11EltRSN(str(elt))
		except Exception, e:
			Printer.error('Bad Dot11EltRSN got[{0:s}]'.format(elt.info))
			Printer.exception(e)
	return None
scapy.layers.dot11.Dot11.rsn = scapy_layers_dot11_Dot11_rsn
del scapy_layers_dot11_Dot11_rsn
