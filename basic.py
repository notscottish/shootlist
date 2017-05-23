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
		self.ip = None
		self.encoding = None
		self.cert = None
		self.redirect = None
		self.ports = None
		self.recordtype = None
	
	def __str__(self):
		return self.name, self.ip, self.ports, self.encoding, self.redirect
	
	def discover_ip(self):
		retval = []
		resolver = dns.resolver.Resolver()
		try:
			response = resolver.query(self.name, "A")
		except dns.resolver.NXDOMAIN:
			sys.stderr.write("Warning: Could not resolve name: \"%s\". No IP set." % (self.name))
			return
		for value in response:
			retval.append(str(value))
		self.ip = retval
	
	def discover_encoding(self):
		if self.ip is None:
			return
		target_url = "http://" + self.ip[0] + "/"
		response = requests.get(target_url, allow_redirects=False, headers = {"host": self.name})
		self.encoding = chardet.detect(response._content)
	
	def discover_redirect(self):
		if self.ip is None:
			return
		target_url = "http://" + self.ip[0] + "/"
		response = requests.get(target_url, allow_redirects=False, headers = {"host": self.name})
		if response.status_code == 301 or response.status_code == 302:
			self.redirect = (response.status_code, response.headers['Location'])
		return
	
	def discover_ports(self):
		if self.ip is None:
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
	
	def discover_recordtype(self):
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
			retval = ("CNAME", [])
		else:
			retval = ("A", [])
		for record in a.response.answer:
			retval[1].append(record.__str__())
		self.recordtype = retval
	
	def dump_csv(self, filename):
		f = open(filename, "w")
		f.write("\"Name\",\"IP\",\"Encoding\",\"Cert\",\"Redirect\",\"Ports\",\"RecordType\"\n")
		f.write("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"" % (
			self.name, self.ip, self.encoding, self.cert, self.redirect, self.ports, self.recordtype))
		f.close()

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
		s.discover_ip()
		s.discover_redirect()
		s.discover_encoding()

	for k in sites:
		print k.__str__()
