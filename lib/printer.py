try:
  from termcolor import colored
  COLORS = True
except ImportError:
  print('[-] Could not import termcolor.  For colored output, please run')
  print('pip install termcolor')

class StatusPrinter():
  """Class for accessing status printing functions"""

  def print_status(self, msg):
    """Print a message using the status format"""
    status_prefix = '[*] '
    if COLORS:
      status_prefix = colored(status_prefix, 'blue', attrs=['bold'])
    print(status_prefix + msg)

  def print_good(self, msg):
    """Print a message using the good format"""
    status_prefix = '[+] '
    if COLORS:
      status_prefix = colored(status_prefix, 'green', attrs=['bold'])
    print(status_prefix + msg)

  def print_error(self, msg):
    """Print a message using the error format"""
    status_prefix = '[-] '
    if COLORS:
      status_prefix = colored(status_prefix, 'red', attrs=['bold'])
    print(status_prefix + msg)

  def print_warn(self, msg):
    """Print a message using the warn format"""
    status_prefix = '[!] '
    if COLORS:
      status_prefix = colored(status_prefix, 'yellow', attrs=['bold'])
    print(status_prefix + msg)
