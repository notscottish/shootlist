# About
This script will take as input a list of FQDNs.

For each FQDN, the script will:
* Get the DNS record type (CNAME or A record)
* Get the DNS response
* Get the IP
* Get the encoding type (UTF-8, ASCII...) (Note: If the encoding is in the HTTP response, uses this. Otherwise, it parse the response using the chardet package to make a guess)

Output is in comma separated values (CSV) format.

# Setup

On OSX, make sure the dependencies are installed using the following terminal commands:
* sudo easy_install pip
* sudo pip install requests chardet argparse

# Usage
`python shootlist.py -f fqdn_list_filename`
