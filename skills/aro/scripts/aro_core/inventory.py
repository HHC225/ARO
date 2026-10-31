"""Read-only, bounded software inventory. Missing evidence is recorded as coverage."""
from __future__ import annotations
from datetime import datetime, timezone
from email.parser import Parser
import json
import os
from pathlib import Path
import platform
import re
import sys

from .inventory_parsers import LANGUAGES, LOCKS, MANIFESTS, component, parse_lock, parse_sbom
from .inventory_host import collect_host, collect_docker

SKIP_DIRS={'.git','.hg','.svn','node_modules','vendor','__pycache__','.cache','.npm','.cargo','target','dist','build','coverage','.next','.nuxt','Secrets','secrets','.ssh','.aws','.azure','.kube'}
SKIP_FILES={'.env','.npmrc','.pypirc','credentials','id_rsa','id_ed25519'}


def _coverage(result,collector,status,detail,scope=None):
    entry={'collector':collector,'status':status,'detail':detail}
    if scope is not None: entry['scope']=str(scope)
    result['coverage'].append(entry)


def _read(path,limit):
    if path.is_symlink(): raise ValueError('symlink')
    # O_NOFOLLOW prevents swapping a file into a symbolic link between discovery and open.
    fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0))
    try:
        import stat
        if not stat.S_ISREG(os.fstat(fd).st_mode): raise ValueError('not regular')
        with os.fdopen(fd,'rb',closefd=False) as stream: data=stream.read(limit+1)
        if len(data)>limit: raise ValueError('size limit')
        return data.decode('utf-8',errors='replace')
    finally: os.close(fd)


def _discover(root,options,result):
    max_files=options['max_files']; max_depth=options['max_depth']
    count=0; skipped=0; failed=0; bounded=False
    excluded=Path(options['state_dir']).expanduser().resolve() if options.get('state_dir') else None
    if excluded and (root==excluded or excluded in root.parents):
        _coverage(result,'discovery','ok',f'{root}: ARO state directory intentionally excluded',scope=root);return
    stack=[(root,0)]
    while stack:
        directory,depth=stack.pop()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    count+=1
                    if count>max_files: bounded=True; break
                    try:
                        if entry.is_symlink(): skipped+=1; continue
                        if entry.is_dir(follow_symlinks=False):
                            if excluded and (Path(entry.path)==excluded or excluded in Path(entry.path).parents):skipped+=1;continue
                            if entry.name in SKIP_DIRS: skipped+=1; continue
                            if depth>=max_depth: skipped+=1; bounded=True; continue
                            stack.append((Path(entry.path),depth+1))
                        elif entry.is_file(follow_symlinks=False):
                            if entry.name in SKIP_FILES or entry.name.startswith('.env') or entry.name.endswith(('.pem','.key','.p12','.pfx')):
                                skipped+=1; continue
                            yield Path(entry.path)
                    except OSError: failed+=1
                if bounded and count>max_files: break
        except OSError: failed+=1
    status='partial' if bounded or failed else 'ok'
    _coverage(result,'discovery',status,f'{root}: examined {min(count,max_files)} entries; skipped {skipped} secret/generated/symlink/depth entries; inaccessible directories/entries {failed}; max_files={max_files}, max_depth={max_depth}'+('; discovery limit reached' if bounded else ''),scope=root)


def _projects(roots,options,result):
    projects={}; manifests=[]; locks=set(); seen_files=set(); all_components=[]
    for root in roots:
        for path in _discover(root,options,result):
            key=str(path)
            if key in seen_files: continue
            seen_files.add(key)
            directory=str(path.parent)
            language=LANGUAGES.get(path.suffix)
            if language:
                p=projects.setdefault(directory,{'path':directory,'languages':set(),'manifests':[]})
                p['languages'].add(language)
            is_lock=path.name in LOCKS or (path.suffix=='.lockfile' and path.parent.name=='dependency-locks') or (path.name.startswith('requirements') and path.suffix=='.txt')
            is_manifest=path.name in MANIFESTS or path.suffix in {'.csproj','.fsproj','.vbproj'}
            is_metadata=path.name in {'METADATA','PKG-INFO'} and path.parent.name.endswith(('.dist-info','.egg-info'))
            if is_manifest:
                manifests.append(path)
                projects.setdefault(directory,{'path':directory,'languages':set(),'manifests':[]})['manifests'].append(path.name)
            if not (is_lock or is_metadata): continue
            try:
                content=_read(path,options['max_file_bytes'])
                if is_metadata:
                    meta=Parser().parsestr(content,headersonly=True)
                    c=component(meta.get('Name',''),meta.get('Version',''),'PyPI','package','python-metadata',str(path.parent),'pip',metadata={'evidence':'installed metadata','environment':str(path.parent.parent)})
                    if c: all_components.append(c)
                    else: _coverage(result,'python-metadata','partial',f'{path}: metadata has no usable name/version')
                else:
                    components,warnings=parse_lock(path,content)
                    for c in components:
                        c.setdefault('metadata',{})['project_path']=directory
                        # Native patch adapters must separately verify the project's install manager/context.
                    all_components.extend(components)
                    locks.add((directory,path.name))
                    projects.setdefault(directory,{'path':directory,'languages':set(),'manifests':[]})['manifests'].append(path.name)
                    _coverage(result,'lockfile','partial' if warnings else 'ok',f'{path}: {len(components)} resolved coordinates'+('; '+ '; '.join(warnings) if warnings else ''),scope=path)
            except (OSError,ValueError,TypeError,KeyError,AttributeError,RecursionError) as exc:
                _coverage(result,'lockfile' if is_lock else 'python-metadata','error',f'{path}: unreadable or invalid data ({type(exc).__name__}); max_file_bytes={options["max_file_bytes"]}',scope=path)
    related={'package.json':{'package-lock.json','npm-shrinkwrap.json'},'pyproject.toml':{'poetry.lock','uv.lock'},'Pipfile':{'Pipfile.lock'},'Cargo.toml':{'Cargo.lock'},'composer.json':{'composer.lock'},'Gemfile':{'Gemfile.lock'},'go.mod':{'go.mod'},'build.gradle':{'gradle.lockfile'},'build.gradle.kts':{'gradle.lockfile'},'pom.xml':set()}
    for path in manifests:
        expected=related.get(path.name,{'packages.lock.json','project.assets.json'})
        has_legacy_gradle_lock=path.name in {'build.gradle','build.gradle.kts'} and any(Path(directory)==path.parent/'gradle'/'dependency-locks' for directory,_ in locks)
        if not has_legacy_gradle_lock and not any((str(path.parent),name) in locks for name in expected):
            _coverage(result,'manifest','partial',f'{path}: unresolved manifest; exact installed versions unavailable')
    for p in projects.values():
        p['languages']=sorted(p['languages']); p['manifests']=sorted(set(p['manifests']))
    result['projects']=sorted(projects.values(),key=lambda p:p['path'])
    result['components'].extend(all_components)


def _python_origins(result,options):
    """Read PEP 610 metadata; never import installed or discovered packages.

    Active-interpreter components point at site-packages; discovered components
    already point at dist-info/egg-info. Unknown/direct origins stay visible but
    cannot be matched or patched as an assumed public PyPI installation.
    """
    normalize=lambda name:re.sub(r'[-_.]+','-',str(name)).lower()
    active_roots={}
    def annotate(component,info):
        origin=info/'direct_url.json'
        if not origin.exists() and not origin.is_symlink():return
        reason='installed Python direct_url origin is not verified public PyPI provenance'
        try:
            document=json.loads(_read(origin,options['max_file_bytes']))
            if not isinstance(document,dict) or not isinstance(document.get('url'),str):reason='installed Python direct_url metadata is invalid or unverified'
        except (OSError,ValueError,TypeError,RecursionError):reason='installed Python direct_url metadata is inaccessible or unverified'
        component.setdefault('metadata',{}).update({'selected':False,'provenance':'unverified','provenance_reason':reason})
        _coverage(result,'python-metadata','partial',f'{info}: {reason}',scope=info)
    for c in result['components']:
        if c.get('source')!='python-metadata' or not c.get('path'):continue
        info=Path(c['path'])
        if info.name.endswith(('.dist-info','.egg-info')):annotate(c,info)
        else:active_roots.setdefault(info,[]).append(c)
    for site,components in active_roots.items():
        wanted={(normalize(c['name']),str(c['version'])):c for c in components}
        try:
            if any(p.is_symlink() for p in (site,*site.parents)):
                for c in components:c.setdefault('metadata',{}).update({'selected':False,'provenance_reason':'installed Python metadata provenance requires symlink traversal'})
                _coverage(result,'python-metadata','partial','Active metadata provenance scope is a symlink; public origin unverified');continue
            with os.scandir(site) as entries:
                for index,entry in enumerate(entries):
                    if index>=options['max_files']:
                        for c in components:c.setdefault('metadata',{}).update({'selected':False,'provenance_reason':'installed Python provenance metadata discovery exceeded limit'})
                        _coverage(result,'python-metadata','partial',f'{site}: provenance metadata discovery limit reached');break
                    if not entry.name.endswith(('.dist-info','.egg-info')) or entry.is_symlink() or not entry.is_dir(follow_symlinks=False):continue
                    info=Path(entry.path)
                    if not (info/'direct_url.json').exists() and not (info/'direct_url.json').is_symlink():continue
                    try:
                        path=info/('METADATA' if entry.name.endswith('.dist-info') else 'PKG-INFO')
                        meta=Parser().parsestr(_read(path,options['max_file_bytes']),headersonly=True)
                        c=wanted.get((normalize(meta.get('Name','')),meta.get('Version','')))
                        if c:annotate(c,info)
                    except (OSError,ValueError,TypeError):
                        _coverage(result,'python-metadata','partial',f'{info}: direct-origin package identity unreadable')
        except OSError:
            for c in components:c.setdefault('metadata',{}).update({'selected':False,'provenance_reason':'installed Python origin metadata scope inaccessible'})
            _coverage(result,'python-metadata','partial',f'{site}: active origin metadata scope inaccessible')



def collect_inventory(roots: list[str], options: dict | None = None) -> dict:
    """Inventory visible installations; every collector is read-only and bounded.

    Options: include_system, include_docker, enable_syft, discover_services,
    command_timeout (seconds), max_files (per root), max_depth, max_file_bytes,
    max_processes, max_containers, max_command_bytes. ``host``/``docker`` aliases
    support callers that explicitly disable native collectors.
    """
    options=dict(options or {})
    defaults={'command_timeout':20,'max_files':100000,'max_depth':12,'max_file_bytes':2*1024*1024,'max_processes':4096,'max_process_fds':1024,'max_roots':32,'max_containers':256,'max_command_bytes':8*1024*1024}
    for key,value in defaults.items():
        options[key]=max(1,min(int(options.get(key,value)),value*10))
    result={'schema_version':1,'scanned_at':datetime.now(timezone.utc).isoformat(),'host':{'os':platform.system().lower(),'id':platform.system().lower(),'version':platform.release(),'architecture':platform.machine()},'roots':[],'components':[],'projects':[],'containers':[],'network':{'listeners':[],'addresses':[],'tunnels':[]},'coverage':[]}
    observed_roots=[]
    if options.get('include_system',options.get('host',True)):
        try: observed_roots=collect_host(result,options) or []
        except Exception as exc: _coverage(result,'host','error',f'Host collector failed ({type(exc).__name__}); remaining collectors continue')
    else: _coverage(result,'host','skipped','Native host inventory disabled by options')
    if options.get('include_docker',options.get('docker',True)):
        try: collect_docker(result,options)
        except Exception as exc: _coverage(result,'docker','error',f'Docker collector failed ({type(exc).__name__})')
    else: _coverage(result,'docker','skipped','Docker inventory disabled by options')
    selected=list(roots or [])
    if not selected:
        selected=[str(Path.cwd())]
        selected.extend(p for p in ('/opt','/srv','/var/www','/app','/workspace',str(Path.home())) if Path(p).is_dir())
    if options.get('discover_services',True): selected.extend(observed_roots)
    else: _coverage(result,'service-roots','skipped','Process service-root discovery disabled by options')
    if len(selected)>options.get('max_roots',32):
        _coverage(result,'roots','partial',f"Root limit reached: max_roots={options.get('max_roots',32)}")
        selected=selected[:options.get('max_roots',32)]
    unique=[]
    for raw in selected:
        path=Path(raw).expanduser()
        if any(part.name in SKIP_DIRS for part in (path,*path.parents)):
            _coverage(result,'roots','skipped',f'{path}: secret/generated directory scope skipped'); continue
        if any(part.is_symlink() for part in (path,*path.parents)):
            _coverage(result,'roots','skipped',f'{path}: symlink root skipped'); continue
        try: path=path.resolve(strict=True)
        except (OSError,RuntimeError):
            _coverage(result,'roots','unavailable',f'{path}: root unavailable'); continue
        if not path.is_dir():
            _coverage(result,'roots','skipped',f'{path}: root is not a directory'); continue
        if path==Path(path.anchor):
            _coverage(result,'roots','skipped',f'{path}: filesystem root requires narrower explicit scope'); continue
        if any(path==existing or existing in path.parents for existing in unique): continue
        # If a broad root arrives later, replace earlier nested roots.
        unique=[existing for existing in unique if path not in existing.parents]
        unique.append(path)
    result['roots']=[str(p) for p in sorted(unique)]
    _projects(sorted(unique),options,result)
    _python_origins(result,options)
    sbom_files=options.get('sbom_files',[])
    if not isinstance(sbom_files,list):sbom_files=[];_coverage(result,'local-sbom','error','sbom_files must be a list of local paths')
    for raw in sbom_files[:options.get('max_roots',32)]:
        try:
            path=Path(raw).expanduser().absolute()
            if any(part.is_symlink() or part.name in SKIP_DIRS for part in (path,*path.parents)):raise ValueError('excluded scope')
            components,skipped=parse_sbom(json.loads(_read(path,options['max_file_bytes'])),str(path))
            result['components'].extend(components)
            _coverage(result,'local-sbom','partial',f'{path}: {len(components)} snapshot coordinates, {skipped} omitted; SBOM freshness/current installation not independently verified',scope=path)
        except (OSError,ValueError,TypeError,AttributeError,RecursionError):
            _coverage(result,'local-sbom','error','Local SBOM unreadable, unsupported or exceeds configured file limit')
    if len(sbom_files)>options.get('max_roots',32):_coverage(result,'local-sbom','partial','SBOM file count exceeded max_roots')
    dedup={c['id']:c for c in result['components'] if c}
    result['components']=sorted(dedup.values(),key=lambda c:(c['kind'],c['name'],c['id']))
    _coverage(result,'scope','ok','Inventory covers visible supported metadata only; custom binaries, inaccessible files, remote services and external firewall/router policy may be absent. No claim of complete host coverage.')
    return result
