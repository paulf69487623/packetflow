# PacketFlow

## What is PacketFlow?
PacketFlow is a utility that takes an XML definition of a set of firewall rules
and generates iptables commands to implement this policy.

## Why would I want to use this kind of utility?
PacketFlow makes common firewall configurations very simple.  A very common goal of a firewall is to allow connections to go from one network to another, but not vice-versa.  PacketFlow simplifies this construct greatly.  More on this soon.

## What is the working concept of PacketFlow?
PacketFlow deals with the flow of connections.  Connections that are established are always allowed.  PacketFlow controls the initiation of those connections.

The basic concept of PacketFlow is that of "security levels."  They are associated with interfaces, and indicate how much that interface is trusted.  By default connections may made from a high security interface to a low security interface.  By default, connections may not be made from a low security interface to a high security interface.  Both may be overridden with access lists.

## Why don't you have a (GTK|Qt|Swing|HTML) GUI?
A previous incarnation did use a GUI, but it was found to actually make maintaining firewalls more difficult.  I would need to make a quick change, but I didn't feel like opening the GUI, making the changes, saving the rule set, and then transfering it to the firewall.  Also, I didn't always have the application conveniently available.

For this reason, I've moved to a command line utility that uses an XML configuration file.  This is intended to be installed directly on the firewall.  If you are going to be making changes to the configuration of the firewall, what better place to keep the configuration and the application itself?

## Why did you use Python?
The prototype for this application was actually written in Java.  This worked very well, but I realized that it would require installing the JRE on the firewall.  Not only is the JRE fairly large, most packages for it require the X libraries.  Once everything is added up, it makes for a large amount of overhead.

## How do I use PacketFlow?
The first thing to do is evaluate what you need your firewall to do.  This is probably the most important part.  Once you know what you are trying to accomplish, study the samples in the samples directory of this distribution.  There are several configurations, and one is likely to give you a place to start.

Once you have a configuration, you need to generate the rules from it.  This is done by running the packetflow program with the file name as its argument.  For now, it sends the rules to STDOUT, so you probably want to redirect them into a file.
