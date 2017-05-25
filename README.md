# About
This script will take as input a list of FQDNs.

For each FQDN, the script will:
* Get the DNS record type (CNAME or A record)
* Get the DNS response
* Get the IP
* Get the encoding type (UTF-8, ASCII...)

# Usage
`python shootlist.py -f fqdn_list_filename`
