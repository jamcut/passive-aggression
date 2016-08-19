# Passive Aggression

This script is designed to leverage the [Passive Total API](https://api.passivetotal.org/api/docs/) for enumerating information for a target domain which could be useful in target profiling and recon.  It should go without saying that, at minimum, a free account for Passive Total will need to be created to obtain an API key.

## Arguments:
One positional argument is required to dictate the type of information requested from the API.  Available options for this argument include:

Option | Description | Link
-------|-------------|-----
dns | passive dns information organized by record and source |https://api.passivetotal.org/api/docs/#api-DNS
subdomains | list of associated subdomains from the "Enrichment API" | https://api.passivetotal.org/api/docs/#api-Enrichment-GetV2EnrichmentQuery
metadata | metadata for a given IP address (only compatible with "-i") | https://api.passivetotal.org/api/docs/#api-Enrichment-GetV2EnrichmentQuery
attributes | enumerates subdomains and displays certain attributes for each | https://api.passivetotal.org/api/docs/#api-Host_Attributes-GetV2HostAttributesComponentsQuery
all | all of the above | n/a


## Other options:
* -d, --domain, the domain to enumerate
* -i, --ipaddress, IP address to enumerate
* -u, --username, Passive Total username
* -a, --apikey, Passive Total API key
* -v, --verbose, enable verbose output

### Note:
The username and api key can be configured within environment the environment variables - PT_USER and PT_API_KEY, respectively.  However, if passed as options they will take precedence.

## Installation:
<pre>git clone https://github.com/jamcut/passive-aggression.git && cd passive-aggression/ && pip install -r requirements.txt</pre>
## Usage:

With a domain target:
<pre>./passive-aggression.py {dns,subdomains,attributes,all} -u user@domain.com -a apikey -d domain.com</pre>
With an IP target:
<pre>./passive-aggression.py metadata -u user@domain.com -a apikey -i 127.0.0.1</pre>

## Misc:
This was written mainly as a learning experience and for the purpose of checking out what capabilities are provided through Passive Total.  Obviously there are other implementations available which may be more full featured, or better in some way.  If this program does not meet your needs, I suggest checking out the [package provided by Passive Total](https://pypi.python.org/pypi/passivetotal). 
