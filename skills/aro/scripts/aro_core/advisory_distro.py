"""Distribution-qualified OSV coordinates; never interpret backports as SemVer."""
from __future__ import annotations
import re


def distro_coordinate(component,inventory,options=None):
    meta=component.get('metadata') or {};host=inventory.get('host') or {}
    # A binary name/version cannot be silently substituted for a source package.
    name=meta.get('source_package');version=meta.get('source_version')
    distribution=str(meta.get('distribution') or '').lower()
    release=str(meta.get('distribution_version') or '')
    if not isinstance(name,str) or not re.fullmatch(r'[a-z0-9][a-z0-9+.-]*',name): return None
    if not isinstance(version,str) or not re.fullmatch(r'(?:\d+:)?[0-9][A-Za-z0-9.+:~\-]*',version): return None
    if distribution=='debian' and re.fullmatch(r'\d+(?:\.\d+)?',release):
        ecosystem='Debian:'+release.split('.')[0]
    elif distribution=='ubuntu' and re.fullmatch(r'\d{2}\.\d{2}',release):
        text=str(meta.get('distribution_release') or host.get('release') or '')
        suffix=':LTS' if 'LTS' in text.upper() else ''
        # Missing LTS evidence for an April even-year release is an unmapped coordinate.
        if int(release[:2])%2==0 and release.endswith('.04') and not suffix: return None
        ecosystem='Ubuntu:'+('Pro:' if 'esm' in version.lower() else '')+release+suffix
    else: return None
    return dict(ecosystem=ecosystem,name=name,version=version)
