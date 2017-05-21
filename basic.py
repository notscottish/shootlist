#!/usr/bin/python

import argparse
import chardet
import dns.resolver
import os
import requests
import sys

def check_dns(target_name):
	retval = []
	resolver = dns.resolver.Resolver()
	try:
		response = resolver.query(target_name, "A")
	except dns.resolver.NXDOMAIN:
		sys.stderr.write("warning: could not resolve name: \"%s\"" % (target_name))
		return retval
	for value in response:
		retval.append(str(value))
	return retval

def check_encoding(ip, target_name):
	target_url = "http://" + ip + "/"
	repsonse = requests.get(target_url, allow_redirects=False, headers = {"host": target_name})
	return chardet.detect(response._content)

def check_status(ip, target_name):
	target_url = "http://" + ip + "/"
	response = requests.get(target_url, allow_redirects=False, headers = {"host": target_name})
	if response.status_code == 200:
		return (200, None)
	if response.status_code == 301 or response.status_code == 302:
		return (response.status_code, response.headers['Location'])
	if response.status_code == 404:
		return (404, None)

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Check supplied domains for Redshield compatability.")
	parser.add_argument('-f', required=True, help="File containing list of domain names")
	args = parser.parse_args()
	sourcefile = os.path.abspath(args.f)

	if not os.path.isfile(sourcefile):
		sys.stderr.write("Error: file not found: \"%s\"" % (sourcefile))
		sys.exit(1)
	
	targets_list = open(sourcefile, "r").read().split("\n")

	for name in targets_list:
		if (len(name) == 0):
			continue
		print name, check_encoding(name)
