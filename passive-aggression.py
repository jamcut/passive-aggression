#!/usr/bin/env python
"""Script to pull information from PassiveTotal.org using their API"""
import argparse
import json
from os import mkdir
from os.path import exists
import sys
import time

import lib.passive as pt
import lib.printer

# Hardcode your creds if you are inclined
USERNAME = None
API_KEY = None

def check_resp_for_errors(loaded_content, printer):
  """Check API responses for errors"""
  errors = True
  if 'error' in loaded_content.iterkeys():
    if loaded_content['error'] != None:
      error_message = loaded_content['error']['message']
      printer.print_error('Message from PassiveTotal: {0}'.format(error_message))
      return errors
  errors = False
  return errors

def get_args():
  """Get arguments from the command line"""
  parser = argparse.ArgumentParser(description='Test script to check out some of the abilities of PassiveTotal')
  parser.add_argument('enum', choices=['all', 'dns', 'subdomains', 'metadata', 'attributes'],
    default='all', help='info to enumerate for target IP or domain.')
  meg = parser.add_mutually_exclusive_group()
  meg.add_argument('-d', '--domain', help='domain to query for', default=None)
  meg.add_argument('-i', '--ipaddress', help='IP address to query for', default=None)
  parser.add_argument('-u', '--username', help='PassiveTotal username', default=None)
  parser.add_argument('-a', '--apikey', help='PassiveTotal API key', default=None)
  parser.add_argument('-v', '--verbose', help='show verbose output', action='store_true')
  args = parser.parse_args()
  return args

def passive_dns(printer, pt):
  """Get, parse, and print passive DNS records"""
  passive_dns = pt.get_passive_dns()
  if check_resp_for_errors(passive_dns, printer) == False:
    printer.print_good('Total records for "{0}": {1}'.format(domain, passive_dns['totalRecords']))
  results = passive_dns['results']
  for result in results:
    if not 'resolve' in result:
      # this critical piece of info is missing so skip this result
      if verbose == True:
        printer.print_warn("Record skipped because it did not include an IP address.")
      continue
    printer.print_status('IP Address: {0}'.format(result['resolve']))
    sources = ''
    for source in result['source']:
      sources += source + ', '
    print('Sources: {0}'.format(sources))
    print('First Seen: {0}'.format(result['firstSeen']))
    print('Last Seen: {0}'.format(result['lastSeen']))

def subdomains(printer, pt):
  """Get, Parse, and print subdomains"""
  subdomains = pt.get_subdomains()
  if check_resp_for_errors(subdomains, printer) == False:
    results = subdomains['subdomains']
    printer.print_good('Subdomains for *.{0}:'.format(domain))
    for sub in subdomains['subdomains']:
      print('{0}.{1}').format(sub, domain)

def metadata(printer, pt):
  """Get, parse, and print metadata information for a domain"""
  domain_metadata = pt.get_enrichment()
  if check_resp_for_errors(domain_metadata, printer) == False:
    # pull and print interesting info
    printer.print_good('Primary Domain: {0}'.format(domain_metadata['primaryDomain']))
    if len(domain_metadata['subdomains']) > 0:
      printer.print_status('Additional Subdomains: {0}')
      for subdomain in domain_metadata['subdomains']:
        print('{0}.{1}').format(subdomain, domain)
    printer.print_status('Ever Compromised: {0}'.format(domain_metadata['everCompromised']))
    printer.print_status('Tags:')
    for tag in domain_metadata['tags']:
      print(tag)

def host_attributes(printer, pt):
  """Get, parse, and print host attributes"""
  host_attributes = pt.get_host_attributes()
  if check_resp_for_errors(host_attributes, printer) == False:
    # pull and print interesting info
    hostnames = set()
    attributes = ['Operating System', 'Server', 'Framework', 'CMS']
    results = host_attributes['results']
    for result in results:
      hostnames.add(result['hostname'])
      os = set()
      server = set()
      framework = set()
      cms = set()
      hostname_dict = {}
      for hostname in hostnames:
        if result['hostname'] == hostname:
          printer.print_good('{0}'.format(hostname))
          if result['category'] == attributes[0]:
            os.add(result['label'])
          elif result['category'] == attributes[1]:
            server.add(result['label'])
          elif result['category'] == attributes[2]:
            framework.add(result['label'])
          elif result['category'] == attributes[3]:
            cms.add(result['label'])
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
          for item in v:
            print(item)

def ip_metadata(printer, pt):
  """Get, parse, and print metadata information for an IP"""
  ip_metadata = pt.get_enrichment()
  if check_resp_for_errors(ip_metadata, printer) == False:
    # pull and print interesting info
    printer.print_good('CIDR Network: {0}'.format(ip_metadata['network']))
    printer.print_status('Country: {0}'.format(ip_metadata['country']))
    printer.print_status('Latitude: {0}'.format(ip_metadata['latitude']))
    printer.print_status('Longitude: {0}'.format(ip_metadata['longitude']))
    printer.print_status('Sinkhole: {0}'.format(ip_metadata['sinkhole']))
    printer.print_status('Ever Compromised: {0}'.format(ip_metadata['everCompromised']))
    if ip_metadata['tags'] > 0:
      printer.print_status('Tags')
      for tag in ip_metadata['tags']:
        print(tag)

if __name__ == '__main__':
 args = get_args()

# create printer object
printer = StatusPrinter()

enum = args.enum
verbose = False
if args.verbose:
  verbose = True

# make sure we have at least a domain or an IP to query
domain = args.domain
ip = args.ipaddress
if all(q == None for q in (domain, ip)):
  printer.print_error('Either a domain (-d) or an IP (-i) is required.')
  sys.exit(1)

# make sure the enum option is compatible with our target type
if ip != None:
  if enum != 'metadata':
    printer.print_warn('Currently the "-i" switch is only compatible with the "metadata" option.')
    authorize_switch = raw_input('Do you want to retrieve metadata for {0}? (y/n) '.format(ip)).lower()
    if authorize_switch == 'y':
      enum = 'metadata'
    else:
      printer.print_status('Exiting due to incompatible options!')
      sys.exit(1)

# create authentiction object
if args.username == None:
  if USERNAME == None:
    printer.print_error('A username must be defined.  This can be done with the "-u" flag or on line 14.')
    sys.exit(1)
  else:
    user = USERNAME
else:
  user = args.username

if args.apikey == None:
  if API_KEY == None:
    printer.print_error('An API key must be defined.  This can be done with the "-a" flag or on line 15.')
    sys.exit(1)
  else:
    key = API_KEY
else:
  key = args.apikey
auth = (user, key)

# create PassiveTotal object
pt = PassiveTotal(auth, domain, ip, verbose)

# verify authentication is working with supplied creds
auth_response = pt.verify_account()
auth_errors = check_resp_for_errors(auth_response, printer)
if not auth_errors:
  if verbose:
    printer.print_status('Successfully authenticated as: {0}'.format(user))
else:
  printer.print_error('Authentication failed for {0}'.format(user))
  sys.exit(1)

# enumerate all the things
if enum == 'all':
  passive_dns(printer, pt)
  subdomains(printer, pt)
  metadata(printer, pt)
  host_attributes(printer, pt)
elif enum == 'dns':
  passive_dns(printer, pt)
elif enum == 'subdomains':
  subdomains(printer, pt)
elif enum == 'metadata':
  if ip == None:
    metadata(printer, pt)
  else:
    ip_metadata(printer, pt)
elif enum == 'attributes':
  host_attributes(printer, pt)
