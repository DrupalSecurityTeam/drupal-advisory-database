#!/usr/bin/env python

"""
Lists links to the advisories that have been changed according to git
"""

import re
import subprocess

output = subprocess.check_output(['git', 'status', '--porcelain'], text=True)

for line in output.split('\n'):
  match = re.match(r'.. advisories/\w+/(DRUPAL-.*)', line)
  if match:
    sa = match[1].replace('DRUPAL-', 'SA-').removesuffix('.json')
    print(f'- https://www.drupal.org/{sa}')
