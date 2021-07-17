import string, os

class Interface:
	
	def __init__(self, name):
		self.__name = name
	
	def getName(self):
		return self.__name
	
	def setDevice(self, device):
		self.__device = device
	
	def getDevice(self):
		return self.__device
	
	def setSecuritylevel(self,level):
		self.__level = level
	
	def getSecuritylevel(self):
		return self.__level
