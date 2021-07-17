%define release	1
%define version	1.0



Summary:	An XML based firewall rule generator
Name:		packetflow
Version:	%{version}
Release:	1
License:	GPL
Group:		Applications/Firewall
Source:		packetflow-%{version}.tar.gz
Url:		http://packetflowfw.sourceforge.net
Packager:	Paul Frieden <pfrieden@users.sourceforge.net>
BuildRoot:	%{_builddir}/packetflow-%{version}-root
Requires:	libxml2-python
BuildArchitectures: noarch
%description
PacketFlow is a utility that takes an XML definition of a set of firewall
rules and generates iptables commands to implement this policy. It is
intended mostly for machines that are dedicated firewalls, but it can be
used in other scenarios as well.

%prep
%setup

%build

%install
mkdir -p $RPM_BUILD_ROOT/usr/bin/
mkdir -p $RPM_BUILD_ROOT/usr/share/packetflow
mkdir -p $RPM_BUILD_ROOT/usr/share/doc/packetflow-%{version}

cp packetflow $RPM_BUILD_ROOT/usr/bin/
cp PacketFlow.cat $RPM_BUILD_ROOT/usr/share/packetflow
cp PacketFlow.dtd $RPM_BUILD_ROOT/usr/share/packetflow
cp *.py $RPM_BUILD_ROOT/usr/share/packetflow
cp README TODO $RPM_BUILD_ROOT/usr/share/doc/packetflow-%{version}
cp -r samples $RPM_BUILD_ROOT/usr/share/doc/packetflow-%{version}

%clean
rm -rf $RPM_BUILD_ROOT

%files
/usr/bin/packetflow
/usr/share/packetflow
/usr/share/doc/packetflow-%{version}
