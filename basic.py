#!/usr/bin/python

import argparse
import chardet
import dns
import os
import sys
import urllib

def check_encoding(target_name):
	target_url = "http://" + target_name
	data = urllib.urlopen(target_url).read()
	return chardet.detect(data)

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
