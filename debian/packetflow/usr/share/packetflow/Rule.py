import string, os

class Rule:

	ACTION_PERMIT = 1
	ACTION_DENY = 2

	def __init__(self, action):
		self.__action = action
		self.__source = None
		self.__destination = None
	
	def getAction(self):
		return self.__action
	
	def setSource(self, source):
		if source == '':
			return
		self.__source = source
	
	def getSource(self):
		return self.__source
	
	def setDestination(self, destination):
		if destination == '':
			return
		self.__destination = destination;
	
	def getDestination(self):
		return self.__destination
