from Accesslist import *
from Interface import *

def makeKey(accesslist):
	return makeKey(accesslist.getIncoming(),access.getOutgoing())

def makeKey(incoming, outgoing):
	key = ""
	if incoming == None:
		key = key + '#'
	else:
		key = key + incoming.getName()
		key = key + "-"
	
	if outgoing == None:
		key = key + '#'
	else:
		key = key + outgoing.getName()
	
	return key
