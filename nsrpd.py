#!/usr/bin/env python

import socket
import time
import re
import socket
import ethtool
import hashlib
import logging
import logging.handlers
import os
import json
import ipaddr
import atexit

try:
	import dnet
except ImportError:
	import dumbnet as dnet


# Configs
MCAST_LAPIS_IFACE = "il0"
IGNORE_IFACE = ["eth2", "eth3"]
MCAST_ANNOUNCE_TIME = 30
NET_CALC_TIME = 30
NET_GC_TIME = 30
STATIC_KEY = "STATICKEY"
SECURITY = 22

# Defines
MCAST_ALL_ROUTER = "224.0.0.2"
MCAST_LAPIS_PORT = 14915
MCAST_MAX_MESSAGE_SIZE = 8 * 1024

def addr2daddr (addr, maskbits):
	z = []
	for i in xrange (1, 5):
		z.append (str (int (addr [-2 * i] + addr [+1 + -2 * i], 16)))
	return (dnet.addr (".".join (z) + "/" + str (maskbits)))
def mask2bitnum (mask):
	z = ''
	for i in xrange (1, 5):
		z += mask [-2 * i] + mask [+1 + -2 * i]
	n = bin (int (z, 16)).lstrip ("0b")
	if len (n) != 32:
		return (32)
	n = n.rstrip ('0')
	if len (n.rstrip ('1')) != 0:
		return (32)
	else:
		return (len (n))


_route_match = re.compile ("^([\w:.]+)\t([A-F0-9]{8})\t([A-F0-9]{8})\t[A-F0-9]{4}\t\d+\t\d+\t\d+\t([A-F0-9]{8})\t\d+\t\d+\t\d+ *\n$")
def get_routes ():
	r = []
	route_file = open ("/proc/net/route", "r")
	lines = route_file.readlines ()
	for l in lines:
		obj = _route_match.match (l)
		if obj:
			iface = obj.groups () [0]
			dest = addr2daddr (obj.groups () [1], mask2bitnum (obj.groups () [3]))
			gate = addr2daddr (obj.groups () [2], 32)
			r.append ((iface, dest, gate))
	return r


def get_lapis_route (routes, gateway = None):
	if gateway:
		gateway = dnet.addr (str (gateway))
	for r in list (routes):
		if r [0] != MCAST_LAPIS_IFACE:
			routes.remove (r)
		elif gateway and r [2] != gateway:
			routes.remove (r)
	return (routes)


def get_local_routes (routes):
	for r in list (routes):
		if r [0] == MCAST_LAPIS_IFACE:
			routes.remove (r)
		elif r [0] in IGNORE_IFACE:
			routes.remove (r)
		elif str (r [2]) != "0.0.0.0":
			routes.remove (r)
	return routes


def agregate_network (networks):
	rsort = []
	for net in networks:
		rsort.append (ipaddr.IPv4Network (str (net)))
	rsort.sort ()
	restart = True
	while restart:
		restart = False
		for i in xrange (len (rsort) - 1):
			prevnet = rsort [i]
			prevset = set ()
			nextnet = rsort [i + 1]
			nextset = set ()
			if prevnet.overlaps (nextnet) and prevnet.prefixlen - nextnet.prefixlen < 0:
				rsort.pop (i + 1)
				restart = True
				break
			if prevnet.prefixlen != nextnet.prefixlen:
				continue
			prevsupernet = prevnet.Supernet ()
			prevsuperset = set ()
			if prevnet.network != prevsupernet.network:
				continue
			for fnet, fset in ((prevnet, prevset), (nextnet, nextset), (prevsupernet, prevsuperset)):
				fset.update (fnet.iterhosts ())
				fset.update ((fnet.broadcast, fnet.network))
			if prevsuperset.difference (prevset).difference (nextset):
				continue
			rsort.pop (i)
			rsort.pop (i)
			rsort.insert (i, prevsupernet)
			restart = True
			break
	nets = []
	for n in rsort:
		nets.append (str(n))
	return (nets)


def create_sock ():
	logger.info ("Creation du socket")
	sock = socket.socket (socket.AF_INET, socket.SOCK_DGRAM)
	sock.setsockopt (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	try:
		sock.setsockopt (socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
	except AttributeError:
		pass
	sock.bind (('', MCAST_LAPIS_PORT))
	sock.setsockopt (socket.SOL_IP, socket.IP_MULTICAST_TTL, 2)
	sock.setsockopt (socket.SOL_IP, socket.IP_MULTICAST_LOOP, 0)
	intf = ethtool.get_ipaddr (MCAST_LAPIS_IFACE)
	sock.setsockopt (socket.SOL_IP, socket.IP_MULTICAST_IF, socket.inet_aton (intf))
	sock.setsockopt (socket.SOL_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton (MCAST_ALL_ROUTER) + socket.inet_aton (intf))
	sock.settimeout (1)
	return (sock)


def get_network_to_announce ():
	routes = get_local_routes (get_routes ())
	nets = []
	for r in routes:
		nets.append (r[1])
	nets = agregate_network (nets)

	return (nets)


def hash_route (routes, addr):
	t = int (time.time ())
	tm = t % MCAST_ANNOUNCE_TIME
	if tm + MCAST_ANNOUNCE_TIME / 10 > MCAST_ANNOUNCE_TIME:
		t += MCAST_ANNOUNCE_TIME
	t = t / MCAST_ANNOUNCE_TIME * MCAST_ANNOUNCE_TIME
	
	x = (hashlib.sha1 (
		hashlib.sha512 (str (routes)).hexdigest () +
		hashlib.sha256 (addr).hexdigest () +
		STATIC_KEY
	).hexdigest ())
	return (x)


def route_announce (networks):
	hash = hash_route (networks, ethtool.get_ipaddr (MCAST_LAPIS_IFACE))
	jstr = json.dumps ({
		"len": len (networks),
		"networks": networks,
		"hash": hash,
		"announce_time": MCAST_ANNOUNCE_TIME,
		"localip": ethtool.get_ipaddr (MCAST_LAPIS_IFACE)
	})
	bytes_sent = sock.sendto (jstr, (MCAST_ALL_ROUTER, MCAST_LAPIS_PORT))
	return (len (jstr) == bytes_sent)


def route_decode (jdata, addr):
	data = json.loads (jdata)
	for net in list (data["networks"]):
		data ["networks"].remove (net)
		data ["networks"].append (str(net))
		
	if addr != data ["localip"]:
		logger.warn ("Pair %s annouunce route tagged as %s" % (addr, data ["localip"]))
	elif hash_route (data ["networks"], addr) != data ["hash"]:
		logger.warn ("Pair %s announce an invalid hash" % (addr))
	else:
		if not announcer.has_key (addr):
			announcer [addr] = {"announce_time": 0, "last_announce": 0}
		announcer [addr] ["announce_time"] = data ["announce_time"]
		announcer [addr] ["last_announce"] = int (time.time())
		gateway = dnet.addr (addr)
		routes = get_lapis_route (get_routes ())
		oldnets = {}
		for r in routes:
			oldnets [r [1]] = r [2]
		for n in data ["networks"]:
			net = dnet.addr (n)
			if net.bits < SECURITY:
				logger.warn ("Dropping net %s when adding by security flag" % n)
			elif net not in oldnets.keys ():
				logger.info ("Adding route %s to %s" % (n, addr))
				try:
					iR.add (net, gateway)
				except Exception:
					logger.exception ("Error when adding route")
			elif oldnets [net] != gateway:
				logger.info ("Replacing route %s (from %s to %s" % (n, oldnets[net], addr))
				try:
					iR.delete (net)
					iR.add (net, gateway)
				except Exception:
					logger.excepton("Error when replacing route")


def garbage_collector (RemoveAll = False):
	for addr, data in announcer.iteritems ():
		if 3 * data ["announce_time"] + data ["last_announce"] < int (time.time ()) or RemoveAll:
			for r in get_lapis_route (get_routes (), addr):
				if r [1].bits < SECURITY:
					logger.warn("Dropping net %s when deleting by security flag" % r[1])
				else:
					logger.info("Garbaging route %s (to %s, but unsure)" % (r[1], r[2]))
					try:
						iR.delete(r[1])		# FIXME #BUG #TODO l'interface de dnet ne permet pas de limiter la supression a une interface /!\ tres dangereux
					except Exception:
						logger.exception("Error when garbaging route")


if __name__ == "__main__":
	# Variables
	announcer = {}
	networks = []
	last_announce = last_calc = last_gc = 0
	flag_halt = False
	sock = None

	iR = dnet.route()

	# Creation du logger
	logger = logging.Logger("nsrpd", level=logging.DEBUG)

	try:
		logger.addHandler(logging.handlers.SysLogHandler(address="/dev/log", facility=logging.handlers.SysLogHandler.LOG_DAEMON))
		logger.handlers[-1].setFormatter(logging.Formatter("%(name)s: %(message)s"))
	except Exception:
		pass
	if True:
		logger.addHandler(logging.StreamHandler())
		logger.handlers[-1].setFormatter(logging.Formatter("%(asctime)s %(levelname)-8s %(message)s"))

	# Enregistrement des actions de garbage final
	atexit.register(garbage_collector, True)

	while not flag_halt:
		# Recreaction du socket s'il a été vidé
		if not sock:
			sock = create_sock ()
	
		# Reception des annonces
		try:
			data, (addr, _) = sock.recvfrom (MCAST_MAX_MESSAGE_SIZE)
		except socket.timeout:
			pass
		except KeyboardInterrupt:
			flag_halt = True
		else:
			try:
				route_decode (data, addr)
			except socket.error:
				logger.exception ("Major error when Reciveing")
				sock = None
				continue

		# Garbage collector
		if (last_gc - time.time() + NET_GC_TIME) < 0:
			last_gc = time.time()
			try:
				garbage_collector ()
			except Exception:
				logger.exception("Major error when Garbaging")

		# Calculs des reseaux
		if (last_calc - time.time () + NET_CALC_TIME) < 0:
			last_calc = time.time ()
			try:
				networks = get_network_to_announce ()
			except Exception:
				logger.exception ("Major error when Calculating")

		# Envoi des annonces
		if (last_announce - time.time () + MCAST_ANNOUNCE_TIME) < 0:
			last_announce = time.time ()
			if networks:
				try:
					route_announce (networks)
				except socket.error:
					sock = None
					logger.exception ("Major error when Announcing")
					continue
			else:
				logger.debug ("No networks, do not announce")