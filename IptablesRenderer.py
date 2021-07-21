import string, os

import operator

from Accesslist import *
from Interface import *
from Tuple import *
from Rule import *
from Util import *

FORWARD_INTRO = """# Rule to allow all established traffic through
# iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Drop TCP packets that aren't established and don't have SYN set
iptables -A FORWARD -p tcp ! --syn -j DROP

# Drop invalid packets, because they shouldn't be seen here
iptables -A FORWARD -m state --state INVALID -j DROP"""

FORWARD_FINISH = """
# Drop everything else
iptables -P FORWARD DROP"""

INPUT_INTRO = """
# Rules to allow all established traffic in
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Drop TCP packets that aren't established and don't have SYN set
iptables -A INPUT -p tcp ! --syn -j DROP

# Drop invalid packets, because they shouldn't be seen here
iptables -A INPUT -m state --state INVALID -j DROP"""

INPUT_FINISH = """
# Drop everything else
iptables -P INPUT DROP"""


def render(firewall):
	interfaces = firewall.getInterfaces()
	# interfaces.sort(lambda x, y: cmp(y.getSecuritylevel(), x.getSecuritylevel()))
	# interfaces.sort(key=methodcaller('getSecuritylevel'))
	print(FORWARD_INTRO)

	for incoming in interfaces:
		for outgoing in sorted(interfaces, key=operator.methodcaller('getSecuritylevel')):
			accesslist = firewall.getAccesslist(incoming,outgoing)
			if accesslist == None:
				continue;
			rules = accesslist.getRules()
			print("\n# From %s to %s" % (incoming.getName(), outgoing.getName()))
			for rule in rules:
				print("iptables -A FORWARD -i %s -o %s %s" % (incoming.getDevice(), outgoing.getDevice(), renderRule(rule)))
	
	for interface in interfaces:
		accesslist = firewall.getAccesslist(interface,firewall.WILDCARD)
		if accesslist != None:
			print("\n# From %s to *" % (interface.getName()))
			rules = accesslist.getRules()
			for rule in rules:
				print("iptables -A FORWARD -i %s %s" % (interface.getDevice(), renderRule(rule)))
		
		accesslist = firewall.getAccesslist(firewall.WILDCARD,interface)
		if accesslist != None:
			print("\n# From * to %s" % (interface.getName()))
			rules = accesslist.getRules()
			for rule in rules:
				print("iptables -A FORWARD -o %s %s" % (interface.getDevice(), renderRule(rule)))

	for incoming in interfaces:
		for outgoing in interfaces:
			if incoming.getSecuritylevel() > outgoing.getSecuritylevel():
				print("\n# Default from %s to %s" % (incoming.getName(), outgoing.getName()))
				print("iptables -A FORWARD -i %s -o %s -j ACCEPT" % (incoming.getDevice(), outgoing.getDevice()))


	print(FORWARD_FINISH)
	print(INPUT_INTRO)

	for interface in interfaces:
		accesslist = firewall.getAccesslist(interface, None)
		if accesslist != None:
			rules = accesslist.getRules()
			print("\n# Input from %s" % (interface.getName()))
			for rule in rules:
				print("iptables -A INPUT -i %s %s" % (interface.getDevice(), renderRule(rule))	)
					
		accesslist = firewall.getAccesslist(None, interface)
		if accesslist != None:
			rules = accesslist.getRules()
			print("\n# Output to %s" % (interface.getName()))
			for rule in rules:
				print("iptables -A INPUT -o %s %s" % (interface.getDevice(), renderRule(rule)))
	
	print(INPUT_FINISH)

def renderRule(rule):
	buf = ''
	
	source = rule.getSource()
	destination = rule.getDestination()
	
	if source != None:
		if source.getProtocol() != None:
			buf = buf + ' -p '
			buf = buf + source.getProtocol()
	if destination != None:
		if destination.getProtocol() != None:
			buf = buf + ' -p '
			buf = buf + destination.getProtocol()
		
	if source != None:
		if source.getAddress() != None:
			buf = buf + ' -s '
			buf = buf + source.getAddress()
		if source.getPort() != None:
			buf = buf + ' --sport '
			buf = buf + source.getPort()
	
	if destination != None:
		if destination.getAddress() != None:
			buf = buf + ' -d '
			buf = buf + destination.getAddress()
		if destination.getPort() != None:
			buf = buf + ' --dport '
			buf = buf + destination.getPort()
	
	if rule.getAction() == rule.ACTION_PERMIT:
		buf = buf + ' -j ACCEPT'
	elif rule.getAction() == rule.ACTION_DENY:
		buf = buf + ' -j DROP'
	else:
		print("Unknown action")
	
	return buf
