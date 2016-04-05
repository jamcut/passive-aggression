try:
  import requests
except ImportError:
  print('[-] Could not import requests.  Please run')
  print('pip install requests')
  sys.exit(1)

class PassiveTotal():
  """Class to organize various functions exposed through the PassiveTotal.org API"""

  def __init__(self, auth, domain, ip, verbose):
    """Initialize a new instance of the PassiveTotal class"""
    self.auth = auth
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
    url = 'https://api.passivetotal.org/v2/account'
    loaded_content = self.send_request_v2(url, params=None)
    return loaded_content

  def get_passive_dns(self):
    """Get passive DNS records for the specified domain"""
    url = 'https://api.passivetotal.org/v2/dns/passive'
    params = {'query': self.domain}
    loaded_content = self.send_request_v2(url, params)
    return loaded_content

  def get_subdomains(self):
    """Get the subdomains for the specified domain using the enrichment API"""
    url = 'https://api.passivetotal.org/v2/enrichment/subdomains'
    params = {'query': self.wildcard_domain}
    loaded_content = self.send_request_v2(url, params)
    return loaded_content

  def get_enrichment(self):
    """Get enrichment data for specified domain or IP address"""
    url = 'https://api.passivetotal.org/v2/enrichment'
    if self.domain == None:
      query = self.ip
    else:
      query = self.domain
    params = {'query': query}
    loaded_content = self.send_request_v2(url, params)
    return loaded_content

  def get_host_attributes(self):
    """Get host attributes for specified domain)"""
    url = 'https://api.passivetotal.org/v2/host-attributes/components'
    params = {'query': self.domain}
    loaded_content = self.send_request_v2(url, params)
    return loaded_content
