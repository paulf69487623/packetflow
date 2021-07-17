import string, os

from Accesslist import *
from Interface import *
from Tuple import *
from Rule import *
from Util import *

class Firewall:

	WILDCARD = Interface('*')

	def __init__(self):
		self.__interfaces = {}
		self.__accesslists = {}
	
	def addInterface(self, interface):
		#print "Firewall.addInterface"
		self.__interfaces[interface.getName()] = interface
	
	def getInterfaces(self):
		return self.__interfaces.values()
	
	def getInterface(self, name):
		#print "Getting key %s" % name
		interface = None
		try:
			interface = self.__interfaces[name]
		except:
			pass
		
		return interface

	def addAccesslist(self, accesslist):
		key = makeKey(accesslist.getIncoming(), accesslist.getOutgoing())
		self.__accesslists[key] = accesslist
		
	def getAccesslist(self, incoming, outgoing):
		key = makeKey(incoming, outgoing)
		try:
			accesslist = self.__accesslists[key]
		except KeyError:
			accesslist = None
		return accesslist
		
fw = Firewall()
iface1 = Interface("inside")
iface1.setSecuritylevel(100)
fw.addInterface(iface1)
iface2 = Interface("outside")
iface2.setSecuritylevel(0)
fw.addInterface(iface2)

al = Accesslist(iface1,iface2)
fw.addAccesslist(al)
r = Rule('accept')
t = Tuple();
t.setAddress("10.0.5.2");
t.setProtocol('tcp');
t.setPort('ssh')
r.setSource(Tuple())
r.setDestination(t)
al.addRule(r)

