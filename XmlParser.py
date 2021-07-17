import sys

import libxml2

from Firewall import *
from Accesslist import *
from Interface import *
from Tuple import *
from Rule import *
from Util import *

class XmlParser:
	def __init__(self):
		self.__firewall = None
		self.__interface = None
		self.__accesslist = None
		self.__rule = None
	
	def getChildren(self, node):
		children = []
		child = node.children
		while child != None:
			children.append(child)
			child = child.next
		return children
	
	def doRoot(self, node):
#		print "doRoot: %s" % node
		for child in self.getChildren(node):
			if child.name == "interfaces":
				self.doInterfaces(child)
			elif child.name == "access-lists":
				self.doAccesslists(child)
	
	def doInterfaces(self, node):
#		print "doInterfaces: %s" % node
		for child in self.getChildren(node):
			if child.name == "interface":
				self.__firewall.addInterface(self.doInterface(child))
	
	
	def doAccesslists(self, node):
#		print "doAccesslists: %s" % node
		for child in self.getChildren(node):
			if child.name == "access-list":
				self.__firewall.addAccesslist(self.doAccesslist(child))
	
	def doInterface(self, node):
#		print "doInterface: %s" % node
		interface = Interface(node.prop("name"))
		for child in self.getChildren(node):
			if child.name == "device":
				interface.setDevice(child.getContent())
			elif child.name == "securitylevel":
				interface.setSecuritylevel(int(child.getContent()))

		return interface
	
	def doTuple(self, node):
#		print "doTuple: %s" % node
		tupl = Tuple()
		tupl.setAddress(node.prop("address"))
		tupl.setProtocol(node.prop("protocol"))
		tupl.setPort(node.prop("port"))
		return tupl
	
	def doRule(self, node):
#		print "doRule: %s" % node

		action_name = node.prop("action")
		if action_name == "permit":
			action = Rule.ACTION_PERMIT
		elif action_name == "deny":
			action = Rule.ACTION_DENY

		rule = Rule(action)
		for child in self.getChildren(node):
			if child.name == "source":
				rule.setSource(self.doTuple(child))
			elif child.name == "destination":
				rule.setDestination(self.doTuple(child))
		
		return rule

	def doAccesslist(self, node):
#		print "doAccesslist: %s" % node
		incoming = None
		outgoing = None

		in_name = node.prop("incoming")
		out_name = node.prop("outgoing")

		if in_name == "*":
			incoming = self.__firewall.WILDCARD
		else:
			incoming = self.__firewall.getInterface(in_name)
		
		if out_name == "*":
			outgoing = self.__firewall.WILDCARD
		else:
			outgoing = self.__firewall.getInterface(out_name)
		
		if incoming == None and in_name != None:
			print "Unknown incoming interface %s" % in_name
		
		if outgoing == None and out_name != None:
			print "Unknown outgoing interface %s" % out_name
		
		accesslist = Accesslist(incoming, outgoing)
		
		for child in self.getChildren(node):
			if child.name == "rule":
				accesslist.addRule(self.doRule(child))
	
		return accesslist


	def parse(self, file):
		self.__firewall = Firewall()
		
		libxml2.loadCatalog("/usr/share/packetflow/PacketFlow.cat")

		parser = libxml2.createFileParserCtxt(file)
		parser.validate(1)	
			
		parser.parseDocument()
		if parser.isValid() != 1:
			print "Malformed document"
			sys.exit(1)
			
		doc = parser.doc()

		self.doRoot(doc.getRootElement())
		return self.__firewall	

