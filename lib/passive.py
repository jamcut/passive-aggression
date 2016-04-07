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

import json

try:
  import requests
except ImportError:
  print('[-] Could not import requests.  Please run')
  print('pip install requests')
  sys.exit(1)

class PassiveTotal():
  """Class to provide access to various functionality exposed through the PassiveTotal.org API"""

  def __init__(self, auth, domain, ip, verbose):
    """Initialize a new instance of the PassiveTotal class"""
    self.auth = auth
    self.api_base_url = 'https://api.passivetotal.org/v2/'
    self.domain = domain
    if not self.domain == None:
      self.wildcard_domain = '*.' + self.domain
    self.ip = ip
    self.verbose = verbose

  def send_request_v2(self, url, params):
    """Send a request to the v2 API"""
    response = requests.get(url, auth=self.auth, params=params)
    loaded_content = json.loads(response.content)
    return loaded_content

  def verify_account(self):
    """Confirm that the specified Passive Total account is valid"""
    successful_auth = False
    url = self.api_base_url + 'account'
    loaded_content = self.send_request_v2(url, params=None)
    return loaded_content

  def get_passive_dns(self):
    """Get passive DNS records for the specified domain"""
    url = self.api_base_url + 'dns/passive'
    params = {'query': self.domain}
    loaded_content = self.send_request_v2(url, params)
    return loaded_content

  def get_subdomains(self):
    """Get the subdomains for the specified domain using the enrichment API"""
    url = self.api_base_url + 'enrichment/subdomains'
    params = {'query': self.wildcard_domain}
    loaded_content = self.send_request_v2(url, params)
    return loaded_content

  def get_enrichment(self):
    """Get enrichment data for specified domain or IP address"""
    url = self.api_base_url + 'enrichment'
    if self.domain == None:
      query = self.ip
    else:
      query = self.domain
    params = {'query': query}
    loaded_content = self.send_request_v2(url, params)
    return loaded_content

  def get_host_attributes(self):
    """Get host attributes for specified domain)"""
    url = self.api_base_url + 'host-attributes/components'
    params = {'query': self.domain}
    loaded_content = self.send_request_v2(url, params)
    return loaded_content
