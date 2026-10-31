"""Read-only distro ownership evidence for runtime banners that omit backports."""
from __future__ import annotations
from functools import lru_cache
from pathlib import Path
import os
import re
import shutil
import subprocess


@lru_cache(maxsize=64)
def _dpkg_owns(path):
    executable=shutil.which('dpkg-query')
    if not executable or not str(Path(executable).resolve()).startswith(('/usr/bin/','/bin/')): return None
    if not re.fullmatch(r'/(?:usr/)?(?:bin|sbin|lib|lib64)/[A-Za-z0-9_+./-]+',path): return None
    env={k:v for k,v in os.environ.items() if not k.startswith('DPKG_')}
    try:
        result=subprocess.run([executable,'-S',path],capture_output=True,text=True,timeout=3,env=env,check=False)
        if len(result.stdout)>1024*1024: return None
        if result.returncode==0 and any(': '+path in line for line in result.stdout.splitlines()): return True
        return False if result.returncode==1 else None
    except (OSError,subprocess.TimeoutExpired): return None


def distro_owned_runtime(component,inventory):
    meta=component.get('metadata') or {}
    if meta.get('distribution_owned') is True or meta.get('distro_package'): return True
    path=component.get('path')
    if not isinstance(path,str): return False
    host=inventory.get('host') or {}
    distribution=str(host.get('id') or '').lower()
    if distribution in ('debian','ubuntu'):
        owned=_dpkg_owns(path)
        if owned is True: return True
        # An unresolved ownership check on a system runtime is not proof of an upstream build.
        if owned is None and path.startswith(('/usr/bin/','/bin/')): return True
    elif distribution and path.startswith(('/usr/bin/','/bin/')):
        return True
    return False
