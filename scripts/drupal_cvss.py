"""
Map a Drupal SA risk string to a CVSS v3.1 base vector.

Port of Drupal\SaCvssMap\Mapper\DrupalToCvss31Mapper and CvssV31Calculator:
https://gitlab.com/mcdruid/drupal-sa-cvss-map

The CVSS vector is derived from the Drupal risk metrics plus the vulnerability
type. It is an approximation, not a manually scored CVSS assessment.
"""

import math
import re

# Points from drupalorg_security_risk_metrics().
# https://www.drupal.org/drupal-security-team/security-risk-levels-defined
DRUPAL_RISK_POINTS = {
  'AC:None': 4, 'AC:Basic': 2, 'AC:Complex': 1,
  'A:None': 4, 'A:User': 2, 'A:Admin': 1,
  'CI:All': 5, 'CI:Some': 3, 'CI:None': 0,
  'II:All': 5, 'II:Some': 3, 'II:None': 0,
  'E:Exploit': 4, 'E:Proof': 2, 'E:Theoretical': 1,
  'TD:All': 3, 'TD:Default': 2, 'TD:Uncommon': 1,
}

# CVSS v3.1 weights. https://www.first.org/cvss/v3.1/specification-document
_AV = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.20}
_AC = {'L': 0.77, 'H': 0.44}
_UI = {'N': 0.85, 'R': 0.62}
_CIA = {'H': 0.56, 'L': 0.22, 'N': 0.00}
_PR = {
  'U': {'N': 0.85, 'L': 0.62, 'H': 0.27},
  'C': {'N': 0.85, 'L': 0.68, 'H': 0.50},
}


def parse_drupal_risk(criticality: str | dict | list | None) -> dict | None:
  """
  Parse field_sa_criticality.

  The stored value is the terse calculator string, for example
  "AC:Basic/A:User/CI:Some/II:Some/E:Theoretical/TD:Default".
  The displayed "13 / 25" label is the sum of those six metrics.
  A rendered string ("Critical 16 / 25 AC:...") is also accepted.
  """
  if isinstance(criticality, list):
    criticality = criticality[0] if criticality else None
  if isinstance(criticality, dict):
    criticality = criticality.get('value') or criticality.get('safe_value')
  if not criticality or not isinstance(criticality, str):
    return None

  raw = criticality.strip()
  found = re.findall(r'(AC|A|CI|II|E|TD):([A-Za-z]+)', raw)
  metrics: dict[str, str] = {}
  score = 0
  for code, value in found:
    if code in metrics:
      continue
    points = DRUPAL_RISK_POINTS.get(f'{code}:{value}')
    if points is None:
      continue
    metrics[code] = value
    score += points

  if len(metrics) != 6:
    return None

  if score <= 4:
    level = 'NOT_CRITICAL'
  elif score <= 9:
    level = 'LESS_CRITICAL'
  elif score <= 14:
    level = 'MODERATELY_CRITICAL'
  elif score <= 19:
    level = 'CRITICAL'
  else:
    level = 'HIGHLY_CRITICAL'

  return {
    'score': score,
    'level': level,
    'metrics': metrics,
    'raw': raw,
  }


def _as_text(value: str | dict | list | None) -> str:
  if isinstance(value, list):
    value = value[0] if value else None
  if isinstance(value, dict):
    value = value.get('value') or value.get('safe_value')
  return value.strip() if isinstance(value, str) else ''


def _matches(haystack: str, needles: tuple[str, ...]) -> bool:
  return any(needle in haystack for needle in needles)


def cvss31_base_score(metrics: dict[str, str]) -> float:
  """CVSS v3.1 base score, rounded up to one decimal, as in the spec."""
  iss = 1 - (
    (1 - _CIA[metrics['C']])
    * (1 - _CIA[metrics['I']])
    * (1 - _CIA[metrics['A']])
  )
  if metrics['S'] == 'U':
    impact = 6.42 * iss
  else:
    impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

  if impact <= 0:
    return 0.0

  exploitability = (
    8.22
    * _AV[metrics['AV']]
    * _AC[metrics['AC']]
    * _PR[metrics['S']][metrics['PR']]
    * _UI[metrics['UI']]
  )
  raw = (
    min(impact + exploitability, 10)
    if metrics['S'] == 'U'
    else min(1.08 * (impact + exploitability), 10)
  )
  return math.ceil(raw * 10) / 10


def cvss31_severity(score: float) -> str:
  if score == 0.0:
    return 'None'
  if score < 4.0:
    return 'Low'
  if score < 7.0:
    return 'Medium'
  if score < 9.0:
    return 'High'
  return 'Critical'


def map_drupal_to_cvss31(
  metrics: dict[str, str] | None,
  vuln_type: str | dict | list | None = '',
) -> dict | None:
  """
  Map Drupal risk metrics and the SA vulnerability type to CVSS v3.1.

  Baseline is AV:N / S:U / no impact. Drupal's AC maps to CVSS AC only;
  UI:R is set by vulnerability-type overrides (XSS, CSRF, open redirect),
  not by AC. E and TD are not base-score metrics.

  Returns None when the six Drupal metrics are not available.
  """
  if not metrics:
    return None

  notes: list[str] = []
  vuln = _as_text(vuln_type).lower()
  mapped = {
    'AV': 'N',
    'AC': 'H' if metrics.get('AC') == 'Complex' else 'L',
    'PR': {'None': 'N', 'User': 'L', 'Admin': 'H'}.get(metrics.get('A', ''), 'N'),
    'UI': 'N',
    'S': 'U',
    'C': {'All': 'H', 'Some': 'L'}.get(metrics.get('CI', ''), 'N'),
    'I': {'All': 'H', 'Some': 'L'}.get(metrics.get('II', ''), 'N'),
    'A': 'N',
  }

  if _matches(vuln, ('cross-site scripting', 'cross site scripting', 'xss')):
    mapped['S'] = 'C'
    mapped['UI'] = 'R'
    if mapped['C'] == 'N':
      mapped['C'] = 'L'
    if mapped['I'] == 'N':
      mapped['I'] = 'L'
    notes.append('XSS: S:C, UI:R applied; C/I bumped to L if N')
  elif _matches(vuln, ('remote code execution', 'arbitrary php code', 'arbitrary code execution')):
    mapped['S'] = 'C'
    mapped['C'] = mapped['I'] = mapped['A'] = 'H'
    notes.append('RCE: S:C, C:H, I:H, A:H applied')
  elif _matches(vuln, ('php object injection', 'insecure deserialization', 'unsafe deserialization')):
    mapped['S'] = 'C'
    mapped['C'] = mapped['I'] = mapped['A'] = 'H'
    notes.append('PHP Object Injection: treated as RCE (S:C, C:H, I:H, A:H)')
  elif _matches(vuln, ('gadget chain',)):
    mapped['AC'] = 'H'
    mapped['PR'] = 'H'
    mapped['S'] = 'U'
    mapped['C'] = mapped['I'] = mapped['A'] = 'H'
    notes.append('Gadget Chain: AC:H, PR:H, S:U, C:H, I:H, A:H applied')
  elif _matches(vuln, ('sql injection',)):
    mapped['C'] = mapped['I'] = mapped['A'] = 'H'
    notes.append('SQLi: C:H, I:H, A:H applied')
  elif _matches(vuln, ('server-side request forgery', 'server side request forgery', 'ssrf')):
    mapped['S'] = 'C'
    if mapped['C'] == 'N':
      mapped['C'] = 'L'
    notes.append('SSRF: S:C applied; C bumped to L if N')
  elif _matches(vuln, ('cross-site request forgery', 'cross site request forgery', 'csrf')):
    mapped['UI'] = 'R'
    if mapped['I'] == 'N':
      mapped['I'] = 'L'
    notes.append('CSRF: UI:R applied; I bumped to L if N')
  elif _matches(vuln, ('denial of service',)):
    mapped['A'] = 'H'
    notes.append('DoS: A:H applied')
  elif _matches(vuln, ('access bypass', 'information disclosure', 'sensitive data')):
    if mapped['C'] == 'N':
      mapped['C'] = 'L'
    notes.append('Access Bypass/Disclosure: C bumped to L if N')
  elif _matches(vuln, ('open redirect',)):
    mapped['S'] = 'C'
    mapped['UI'] = 'R'
    notes.append('Open Redirect: S:C, UI:R applied')
  elif _matches(vuln, ('unsupported',)):
    mapped['AC'] = 'L'
    mapped['PR'] = 'L'
    mapped['UI'] = 'N'
    mapped['C'] = mapped['I'] = mapped['A'] = 'H'
    notes.append('Unsupported: AC:L/PR:L/UI:N/C:H/I:H/A:H applied')

  vector = 'CVSS:3.1/AV:{AV}/AC:{AC}/PR:{PR}/UI:{UI}/S:{S}/C:{C}/I:{I}/A:{A}'.format(**mapped)
  score = cvss31_base_score(mapped)
  return {
    'metrics': mapped,
    'vector': vector,
    'score': score,
    'severity': cvss31_severity(score),
    'notes': notes,
  }
