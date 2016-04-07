#!/usr/bin/env python
# Copyright (c) 2016, Jeff McCutchan [jamcut]
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""Script to pull information from PassiveTotal.org using their API"""
import argparse
from os import mkdir
from os.path import exists
import sys
import time

import lib.passive as passive
import lib.printer as p

# Hardcode your creds if you are inclined
USERNAME = None
API_KEY = None

def check_resp_for_errors(loaded_content, sp):
    """Check API responses for errors"""
    errors = True
    if 'error' in loaded_content.iterkeys():
        if loaded_content['error'] != None:
            error_message = loaded_content['error']['message']
            sp.print_error('Message from PassiveTotal: {0}'.format(error_message))
            return errors
        errors = False
        return errors

def get_args():
    """Get arguments from the command line"""
    parser = argparse.ArgumentParser(description='Script to leverage the Passive Total API for target profiling and recon.')
    parser.add_argument('enum', choices=['all', 'dns', 'subdomains', 'metadata', 'attributes'],
    default='all', help='info to enumerate for target IP or domain.')
    meg = parser.add_mutually_exclusive_group()
    meg.add_argument('-d', '--domain', help='domain to enumerate')
    meg.add_argument('-i', '--ipaddress', help='IP address to enumerate')
    parser.add_argument('-u', '--username', help='PassiveTotal username')
    parser.add_argument('-a', '--apikey', help='PassiveTotal API key')
    parser.add_argument('-v', '--verbose', help='enable verbose output', action='store_true')
    args = parser.parse_args()
    return args

def passive_dns(sp, pt):
    """Get, parse, and print passive DNS records"""
    passive_dns = pt.get_passive_dns()
    if not check_resp_for_errors(passive_dns, sp):
        sp.print_good('Total records for "{0}": {1}'.format(domain, passive_dns['totalRecords']))
        results = passive_dns['results']
    for result in results:
        if not 'resolve' in result:
            # this critical piece of info is missing so skip this result
            if verbose == True:
                sp.print_warn("Record skipped because it did not include an IP address.")
        continue
        sp.print_status('IP Address: {0}'.format(result['resolve']))
        sources = ''
        for source in result['source']:
            sources += source + ', '
            print('Sources: {0}'.format(sources))
            print('First Seen: {0}'.format(result['firstSeen']))
            print('Last Seen: {0}'.format(result['lastSeen']))

def subdomains(sp, pt):
    """Get, Parse, and print subdomains"""
    subdomains = pt.get_subdomains()
    if not check_resp_for_errors(subdomains, sp):
        results = subdomains['subdomains']
    sp.print_good('Subdomains for *.{0}:'.format(domain))
    for sub in subdomains['subdomains']:
        print('{0}.{1}').format(sub, domain)

def metadata(sp, pt):
    """Get, parse, and print metadata information for a domain"""
    domain_metadata = pt.get_enrichment()
    if not check_resp_for_errors(domain_metadata, sp):
        # pull and print interesting info
        sp.print_good('Primary Domain: {0}'.format(domain_metadata['primaryDomain']))
        if len(domain_metadata['subdomains']) > 0:
            sp.print_status('Additional Subdomains: {0}')
            for subdomain in domain_metadata['subdomains']:
                print('{0}.{1}').format(subdomain, domain)
                sp.print_status('Ever Compromised: {0}'.format(domain_metadata['everCompromised']))
                sp.print_status('Tags:')
                for tag in domain_metadata['tags']:
                    print(tag)

def host_attributes(sp, pt):
    """Get, parse, and print host attributes"""
    host_attributes = pt.get_host_attributes()
    if not check_resp_for_errors(host_attributes, sp):
        # pull and print interesting info
        hostnames = set()
        attributes = ['Operating System', 'Server', 'Framework', 'CMS']
        results = host_attributes['results']
        # ugly and cumbersome but it works...
        for record in results:
            hostnames.add(record['hostname'])
            for hostname in hostnames:
                hostname_dict = {}
                os = set()
                server = set()
                framework = set()
                cms = set()
                for record in results:
                    if record['hostname'] == hostname:
                        if record['category'] == attributes[0]:
                            os.add(record['label'])
                        elif record['category'] == attributes[1]:
                            server.add(record['label'])
                        elif record['category'] == attributes[2]:
                            framework.add(record['label'])
                        elif record['category'] == attributes[3]:
                            cms.add(record['label'])
                    sp.print_good('Attributes for {0}'.format(hostname))
                    if len(os) > 0:
                        hostname_dict['Operating Systems'] = os
                    elif len(server) > 0:
                        hostname_dict['Servers'] = server
                    elif len(framework) > 0:
                        hostname_dict['Frameworks'] = framework
                    elif len(cms) > 0:
                        hostname_dict['CMS'] = cms
                    for k, v in hostname_dict.iteritems():
                        if len(v) > 0:
                            print('{0}:'.format(k))
                            for item in v:
                                print(item)

def ip_metadata(sp, pt):
    """Get, parse, and print metadata information for an IP"""
    ip_metadata = pt.get_enrichment()
    if not check_resp_for_errors(ip_metadata, sp):
        # pull and print interesting info
        sp.print_good('CIDR Network: {0}'.format(ip_metadata['network']))
        sp.print_status('Country: {0}'.format(ip_metadata['country']))
        sp.print_status('Latitude: {0}'.format(ip_metadata['latitude']))
        sp.print_status('Longitude: {0}'.format(ip_metadata['longitude']))
        sp.print_status('Sinkhole: {0}'.format(ip_metadata['sinkhole']))
        sp.print_status('Ever Compromised: {0}'.format(ip_metadata['everCompromised']))
        if ip_metadata['tags'] > 0:
            sp.print_status('Tags')
            for tag in ip_metadata['tags']:
                print(tag)

args = get_args()

# create printer object
sp = p.StatusPrinter()

enum = args.enum
verbose = False
if args.verbose:
    verbose = True

# make sure we have at least a domain or an IP to query
domain = args.domain
ip = args.ipaddress
if all(q == None for q in (domain, ip)):
    sp.print_error('Either a domain (-d) or an IP (-i) is required.')
    sys.exit(1)

# make sure the enum option is compatible with our target type
if ip != None:
    if enum != 'metadata':
        sp.print_warn('Currently the "-i" switch is only compatible with the "metadata" option.')
        authorize_switch = raw_input('Do you want to retrieve metadata for {0}? (y/n) '.format(ip)).lower()
        if authorize_switch == 'y':
            enum = 'metadata'
        else:
            sp.print_status('Exiting due to incompatible options!')
            sys.exit(1)

# create authentiction object
if args.username == None:
    if USERNAME == None:
        sp.print_error('A username must be defined. This can be done with the "-u" flag or on line 33.')
        sys.exit(1)
    else:
        user = USERNAME
else:
    user = args.username

if args.apikey == None:
    if API_KEY == None:
        sp.print_error('An API key must be defined. This can be done with the "-a" flag or on line 34.')
        sys.exit(1)
    else:
        key = API_KEY
else:
    key = args.apikey
auth = (user, key)

# create PassiveTotal object
pt = passive.PassiveTotal(auth, domain, ip, verbose)

# verify authentication is working with supplied creds
auth_response = pt.verify_account()
auth_errors = check_resp_for_errors(auth_response, sp)
if not auth_errors:
    if verbose:
        sp.print_status('Successfully authenticated as: {0}'.format(user))
    else:
        sp.print_error('Authentication failed for {0}'.format(user))
        sys.exit(1)

# enumerate all the things
if enum == 'all':
    passive_dns(sp, pt)
    subdomains(sp, pt)
    metadata(sp, pt)
    host_attributes(sp, pt)
elif enum == 'dns':
    passive_dns(sp, pt)
elif enum == 'subdomains':
    subdomains(sp, pt)
elif enum == 'metadata':
    if ip == None:
        metadata(sp, pt)
    else:
        ip_metadata(sp, pt)
elif enum == 'attributes':
    host_attributes(sp, pt)
