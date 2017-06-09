#!/usr/bin/python

import argparse
import chardet
import dns.resolver
import os
import re
import requests
import socket
import sys

class Site(object):
    def __init__(self, name):
        self.name = name
        self.dnstype = None
        self.dnsrecord = None
        self.ip = None
        self.ports = None
        self.encoding = None
        self.location = None
	
    def get_ports(self):
        if self.ip is None:
            sys.stderr.write("Error: Must get IP first\n")
            return
        ports = []
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4.0)
        r = s.connect_ex((self.name, 80))
        if r == 0:
            ports.append(80)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4.0)
        r = s.connect_ex((self.name, 443))
        if r == 0:
            ports.append(443)
        if len(ports) > 0:
            self.ports = ports
        return
        
    def get_dnstype(self):
        retval = None
        try:
            a = dns.resolver.query(self.name)
        except dns.resolver.NoAnswer:
            sys.stderr.write("warning: no response\n\n")
            return
        except dns.resolver.NXDOMAIN:
            sys.stderr.write("warning: no record for cname\n\n")
            return
        if re.search("CNAME",a.response.answer[0].__str__(), flags=re.IGNORECASE):
            self.dnstype = "CNAME"
            self.dnsrecord = ""
	    for val in a.response.answer:
		self.dnsrecord += val.to_text()
		self.dnsrecord += "\n"
        else:
            self.dnstype = "A"
            self.dnsrecord = a.response.answer.__str__()
        return
        
    def get_ip(self):
        retval = []
        resolver = dns.resolver.Resolver()
        try:
            response = resolver.query(self.name, "A")
        except dns.resolver.NXDOMAIN:
            sys.stderr.write("Warning: Could not resolve name: \"%s\". No IP set." % (self.name))
            return
        except dns.resolver.NoAnswer:
            sys.stderr.write("Warning: The DNS response does not contain an answer to the question\n")
            return
        for value in response:
            retval.append(str(value))
        # This is a bodge for the meantime
        if len(retval) > 1:
            sys.stderr.write("Warning: Multiple IPs returned, using the first only\n")
        self.ip = retval[0]
        
    def get_encoding(self):
        if self.ip is None:
            return
        if (self.ports is None) or (not 80 in self.ports):
            return
        target_url = "http://" + self.ip + "/"
        try:
            response = requests.get(target_url, allow_redirects=False, headers = {"host": self.name})
        except requests.exceptions.ConnectionError:
#           # port is open but not accepting connections, so remove port
#           if 443 in self.ports:
#               self.ports = [443]
#           else:
#               self.ports = None
            return
        match = re.search("charset=([a-zA-Z0-9_-]+)", response._content)
        if match:
            self.encoding = match.groups()[0]
        else:
            self.encoding = chardet.detect(response._content)['encoding']
        
    def get_geolocation(self):
	if self.ip is None:
            return
	a = requests.get("http://freegeoip.net/csv/%s" % self.ip)
	if a.ok is False:
		sys.stderr.write("Warning: No geo location found\n")
		return
	self.location = a.content.split(",").__str__()
	
    def run_all(self):
        print "Running %s\n" % (self.name)
        self.get_dnstype()
        self.get_ip()
        self.get_ports()
        self.get_encoding()
	self.get_geolocation()
        
    def to_csv(self):
        return "\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"" % (self.name,self.dnstype,self.dnsrecord,self.ip,self.ports,self.encoding,self.location)

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Check supplied domains for Redshield compatability.")
	parser.add_argument('-f', required=True, help="File containing list of domain names")
	args = parser.parse_args()
	sourcefile = os.path.abspath(args.f)
	
	if not os.path.isfile(sourcefile):
		sys.stderr.write("Error: file not found: \"%s\"" % (sourcefile))
		sys.exit(1)
	    
	targets_list = open(sourcefile, "r").read().split("\n")
	
	sites = []
	
	for name in targets_list:
		if (len(name) == 0):
			continue
		sys.stderr.write("info: %s\n" % (name))
		s = Site(name)
		sites.append(s)
		s.run_all()
	
	print "\"Name\",\"DNS Record Type\",\"DNS Record\",\"IP Address\",\"Ports\",\"Encoding\""
	for site in sites:
		print site.to_csv()
