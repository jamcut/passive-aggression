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

COLORS = False
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
