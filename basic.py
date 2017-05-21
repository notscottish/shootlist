#!/usr/bin/python

import argparse
import chardet
import dns
import os
import requests
import sys
import urllib

def check_encoding(target_name):
	target_url = "http://" + target_name
	data = urllib.urlopen(target_url).read()
	return chardet.detect(data)

def check_status(target_name):
	target_url = "http://" + target_name
	response = requests.get(target_url, allow_redirects=False)
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
