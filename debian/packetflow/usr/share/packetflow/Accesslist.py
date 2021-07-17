import string, os

class Accesslist:

	def __init__(self, incoming, outgoing):
		#print "Accesslist.__init__"
		self.__incoming = incoming
		self.__outgoing = outgoing
		self.__rules = []
	
	def getIncoming(self):
		return self.__incoming
	
	def getOutgoing(self):
		return self.__outgoing
	
	def addRule(self, rule):
		self.__rules.append(rule)
	
	def getRules(self):
		return self.__rules
