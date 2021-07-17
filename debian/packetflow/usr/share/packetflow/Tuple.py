import string, os

class Tuple:

	def __init__(self):
		self.__port = None
		self.__protocol = None
		self.__address = None
	
	def setPort(self, port):
		if port == '':
			return
		self.__port = port
	
	def getPort(self):
		return self.__port
	
	def setProtocol(self, protocol):
		if protocol == '':
			return
		self.__protocol = protocol
	
	def getProtocol(self):
		return self.__protocol
	
	def setAddress(self, address):
		if address == '':
			return
		self.__address = address
	
	def getAddress(self):
		return self.__address
