import sys

from xml.etree import ElementTree

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
	
	def doRoot(self, node):
#		print("doRoot: %s" % (node))
		for child in node:
			if child.tag == "interfaces":
				self.doInterfaces(child)
			elif child.tag == "access-lists":
				self.doAccesslists(child)
	
	def doInterfaces(self, node):
#		print("doInterfaces: %s" % (node))
		for child in node:
			if child.tag == "interface":
				self.__firewall.addInterface(self.doInterface(child))
	
	
	def doAccesslists(self, node):
#		print("doAccesslists: %s" % (node))
		for child in node:
			if child.tag == "access-list":
				self.__firewall.addAccesslist(self.doAccesslist(child))
	
	def doInterface(self, node):
#		print("doInterface: %s" % (node))
		interface = Interface(node.attrib['name'])
		for child in node:
			if child.tag == "device":
				interface.setDevice(child.text)
			elif child.tag == "securitylevel":
				interface.setSecuritylevel(int(child.text))

		return interface
	
	def doTuple(self, node):
		print("doTuple: %s" % (node))
		tupl = Tuple()
		if 'address' in node.attrib:
			tupl.setAddress(node.attrib['address'])
		if 'protocol' in node.attrib:
			tupl.setProtocol(node.attrib['protocol'])
		if 'port' in node.attrib:
			tupl.setPort(node.attrib['port'])
		return tupl
	
	def doRule(self, node):
#		print("doRule: %s" % (node))

		action_name = node.attrib['action']
		if action_name == "permit":
			action = Rule.ACTION_PERMIT
		elif action_name == "deny":
			action = Rule.ACTION_DENY

		rule = Rule(action)
		for child in node:
			if child.tag == "source":
				rule.setSource(self.doTuple(child))
			elif child.tag == "destination":
				rule.setDestination(self.doTuple(child))
		
		return rule

	def doAccesslist(self, node):
#		print("doAccesslist: %s" % (node))
		incoming = None
		outgoing = None

		in_name = None
		out_name = None
		if 'incoming' in node.attrib:
			in_name = node.attrib['incoming']
		if 'outgoing' in node.attrib:
			out_name = node.attrib['outgoing']

		if in_name == "*":
			incoming = self.__firewall.WILDCARD
		else:
			incoming = self.__firewall.getInterface(in_name)
		
		if out_name == "*":
			outgoing = self.__firewall.WILDCARD
		else:
			outgoing = self.__firewall.getInterface(out_name)
		
		if incoming == None and in_name != None:
			print("Unknown incoming interface %s" % in_name)
		
		if outgoing == None and out_name != None:
			print("Unknown outgoing interface %s" % out_name)
		
		accesslist = Accesslist(incoming, outgoing)
		
		for child in node:
			if child.tag == "rule":
				accesslist.addRule(self.doRule(child))
	
		return accesslist


	def parse(self, file):
		self.__firewall = Firewall()
		
		# libxml2.loadCatalog("/usr/share/packetflow/PacketFlow.cat")

		# parser = libxml2.createFileParserCtxt(file)
		# parser.validate(1)	
			
		# parser.parseDocument()
		# if parser.isValid() != 1:
		# 	print "Malformed document"
		# 	sys.exit(1)
			
		# doc = parser.doc()

		tree = ElementTree.parse(file)
		self.doRoot(tree.getroot())
		# self.doRoot(doc.getRootElement())
		return self.__firewall	

