# About
This script will take as input a list of FQDNs and outputs a comma separated values document (`output.csv`) with the DNS, IP, hosting location, encoding and TLS certificate attributes able to be discovered.

For each FQDN, the script will:
* Perform a DNS lookup
* Parse the response for DNS record type and IP address
* Get the encoding type (UTF-8, ASCII...) (Note: If the encoding is in the HTTP response, uses this, otherwise parses the response using the chardet package to make a guess)
* Does a Geo IP lookup
* Calls the external "certdump.sh" bash script, which grabs the cert and parses out the CN, SAN, and serial number
* Outputs all discovered information to "output.csv".

Note: The encoding discovery is rubbish. Basically, if it doesn't report Windows-1252 (ANSI), ISO-8859, or a language specific one (e.g. GBK), it is probably UTF-8.

# Setup

On OSX, make sure the dependencies are installed using the following terminal commands:
* `sudo easy_install pip`
* `sudo pip install requests chardet argparse dnspython`

On Ubuntu, make sure the dependencies are installed using the following commands:
* `apt-get install python-chardet python-requests python-argparse python-dnspython`

Grab the `certdump.sh` script from the [certdump](https://github.com/notscottish/certdump) repo and make sure it is in the same directory as the `shootlist.py` script

# Usage
`python shootlist.py -f fqdn_list_filename`
