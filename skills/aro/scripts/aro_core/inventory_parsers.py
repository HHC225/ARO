"""Read resolved dependency coordinates without executing project code."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
import tomllib
from urllib.parse import urlsplit

MANIFESTS = {'package.json','pyproject.toml','Pipfile','Cargo.toml','composer.json','Gemfile','go.mod','pom.xml','build.gradle','build.gradle.kts'}
LOCKS = {'package-lock.json','npm-shrinkwrap.json','Pipfile.lock','poetry.lock','uv.lock','Cargo.lock','go.mod','go.sum','composer.lock','Gemfile.lock','packages.lock.json','project.assets.json','gradle.lockfile'}
LANGUAGES = {'.py':'Python','.js':'JavaScript','.jsx':'JavaScript','.ts':'TypeScript','.tsx':'TypeScript','.go':'Go','.rs':'Rust','.php':'PHP','.rb':'Ruby','.cs':'C#','.java':'Java','.kt':'Kotlin','.c':'C','.cpp':'C++','.swift':'Swift'}

def _public_url(value,hosts,paths=None):
    if not isinstance(value,str):return False
    try:
        u=urlsplit(value)
        return (u.scheme=='https' and u.hostname in hosts and not u.username and not u.password
                and u.port in (None,443) and not u.query and not u.fragment
                and (paths is None or u.path.rstrip('/') in paths))
    except ValueError:return False


def _unverified(reason):
    return {'selected':False,'provenance':'unverified','provenance_reason':reason}


def _npm_origin(record,workspace=False):
    if record.get('link') or workspace:return _unverified('npm local link or workspace origin')
    origin=record.get('resolved')
    if origin is None:return {'provenance':'unspecified'}
    if _public_url(origin,{'registry.npmjs.org'}):return {'provenance':'official npm registry'}
    return _unverified('npm resolved origin is not the verified official registry')



def component(name, version, ecosystem, kind, source, path=None, manager=None, scope=None, metadata=None, identity=None):
    name, version = str(name).strip(), str(version).strip()
    if not name or not version or len(name)>512 or len(version)>512:
        return None
    # Coordinates never include credentials or direct source URLs.
    if any(ch in name+version for ch in '\r\n\x00') or '://' in name+version or '@git' in version:
        return None
    stable = '\0'.join(str(x or '') for x in (kind,ecosystem,name,path,scope,identity))
    result={'id':'cmp-'+hashlib.sha256(stable.encode()).hexdigest()[:24], 'name':name,'version':version,'ecosystem':ecosystem,'kind':kind,'source':source,'collector':{'runtime-version':'runtime-'+name,'python-metadata':'python-metadata','docker':'docker-image'}.get(source,source),'path':str(path) if path else None}
    if manager: result['manager']=manager
    if scope: result['scope']=scope
    if metadata: result['metadata']=metadata
    return result

def parse_lock(path: Path, content: str):
    """Return (components, warnings); source/path only describe local evidence."""
    name=path.name
    found=[]; warnings=[]
    def add(n,v,eco,manager,scope='',metadata=None):
        if not isinstance(n,str) or not isinstance(v,(str,int,float)):
            warnings.append('invalid coordinate'); return
        v=str(v)
        if any(ch in v for ch in '^~*<>=| ') or v.startswith(('git:','file:','link:','workspace:','http:','https:')) or not v:
            warnings.append('unresolved or non-registry coordinate'); return
        c=component(n,v,eco,'package','lockfile',str(path),manager,scope or None,metadata)
        if c:
            found.append(c)
            if (metadata or {}).get('selected') is False:warnings.append('Public package matching suppressed: '+metadata.get('provenance_reason','unselected evidence'))
        else: warnings.append('unsafe or unresolved coordinate omitted')
    if name in {'package-lock.json','npm-shrinkwrap.json'}:
        doc=json.loads(content)
        if isinstance(doc.get('packages'),dict):
            for key,value in doc['packages'].items():
                if key and isinstance(value,dict):
                    n=value.get('name') or key.rsplit('node_modules/',1)[-1]
                    if value.get('version'): add(n,value['version'],'npm','npm',key,_npm_origin(value,workspace='node_modules/' not in key))
                    else: warnings.append('unresolved npm link or workspace')
        else:
            def nested(deps,prefix='node_modules/'):
                for n,v in deps.items():
                    scope=prefix+n
                    if isinstance(v,dict):
                        if v.get('version'): add(n,v['version'],'npm','npm',scope,_npm_origin(v))
                        else: warnings.append('npm dependency missing resolved version')
                        nested(v.get('dependencies',{}),scope+'/node_modules/')
            nested(doc.get('dependencies',{}))
    elif name=='Pipfile.lock':
        doc=json.loads(content)
        sources={x.get('name'):x.get('url') for x in doc.get('_meta',{}).get('sources',[]) if isinstance(x,dict)}
        for group in ('default','develop'):
            for n,v in doc.get(group,{}).items():
                version=v.get('version','');metadata={'provenance':'unspecified'}
                if any(key in v for key in ('git','path','file','editable')):metadata=_unverified('Pipfile direct/local/VCS origin')
                elif v.get('index') and not _public_url(sources.get(v['index']),{'pypi.org','pypi.python.org'},{'/simple'}):metadata=_unverified('Pipfile explicit custom or unknown index')
                elif not v.get('index') and sources and any(not _public_url(u,{'pypi.org','pypi.python.org'},{'/simple'}) for u in sources.values()):metadata=_unverified('Pipfile custom index context')
                if re.fullmatch(r'==[^=<>!~*\s]+',version): add(n,version[2:],'PyPI','pipenv',group,metadata)
                else: warnings.append('unresolved Pipfile dependency')
    elif name in {'poetry.lock','uv.lock','Cargo.lock'}:
        doc=tomllib.loads(content)
        eco,manager=('crates.io','cargo') if name=='Cargo.lock' else ('PyPI','uv' if name=='uv.lock' else 'poetry')
        for p in doc.get('package',[]):
            source=p.get('source');metadata={'provenance':'unspecified'}
            if name=='Cargo.lock':
                if source in ('registry+https://github.com/rust-lang/crates.io-index','sparse+https://index.crates.io/'):metadata={'provenance':'official crates.io registry'}
                else:metadata=_unverified('Cargo alternate registry, local or VCS origin')
            elif source is not None:
                if not isinstance(source,dict):metadata=_unverified('Python lock origin is not a recognized registry')
                elif name=='uv.lock':
                    if _public_url(source.get('registry'),{'pypi.org','pypi.python.org'},{'/simple'}):metadata={'provenance':'official PyPI registry'}
                    else:metadata=_unverified('uv explicit custom registry, local or direct origin')
                elif source.get('type') in {'git','directory','file','url'}:metadata=_unverified('Poetry local or direct/VCS origin')
                elif source.get('url') and _public_url(source['url'],{'pypi.org','pypi.python.org'},{'/simple'}):metadata={'provenance':'official PyPI registry'}
                elif source:metadata=_unverified('Poetry explicit custom or unknown registry')
            if p.get('version'): add(p.get('name',''),p['version'],eco,manager,metadata=metadata)
            else: warnings.append('lock entry lacks version')
    elif name.startswith('requirements') and path.suffix=='.txt':
        # pip index options apply to the entire requirements invocation, regardless of order.
        custom_context=any(re.match(r'^(?:--(?:extra-index-url|index-url|no-index|find-links|requirement)|-[ifr])(?:[=\s]|$)',line.strip()) for line in content.splitlines())
        metadata=_unverified('requirements index/include options leave public PyPI origin unverified') if custom_context else {'provenance':'unspecified'}
        for line in content.splitlines():
            line=line.strip()
            if not line or line.startswith('#') or line.startswith('--hash='): continue
            match=re.match(r'^([A-Za-z0-9_.-]+)(?:\[[A-Za-z0-9_,.-]+\])?==([^\s;=<>!*]+)(?:\s|;|$)',line)
            if match: add(match[1],match[2],'PyPI','pip',metadata=metadata.copy())
            else: warnings.append('requirements entry is not an exact registry pin')
    elif name=='gradle.lockfile' or (path.suffix=='.lockfile' and path.parent.name=='dependency-locks'):
        for line in content.splitlines():
            line=line.strip()
            if not line or line.startswith('#') or line.startswith('empty='):continue
            coordinate,_,configurations=line.partition('=')
            parts=coordinate.split(':')
            if len(parts)==3 and all(parts) and re.fullmatch(r'[A-Za-z0-9_.-]+',parts[0]) and re.fullmatch(r'[A-Za-z0-9_.-]+',parts[1]) and not re.search(r'[+*\[\](){}$]',parts[2]):
                add(parts[0]+':'+parts[1],parts[2],'Maven','gradle',metadata={'provenance':'unspecified','evidence':'resolved Gradle dependency lock','configurations':[x for x in configurations.split(',') if re.fullmatch(r'[A-Za-z0-9_.-]+',x)]})
            else:warnings.append('unresolved or invalid Gradle lock coordinate')
    elif name=='go.mod':
        in_require=False; replacements=False
        # Replacement directives can change module provenance; suppress affected coordinates.
        replacements_map=set()
        in_replace=False
        for line in content.splitlines():
            line=line.split('//',1)[0].strip()
            if line.startswith('replace '):
                rest=line[8:].strip()
                if rest=='(': in_replace=True
                elif rest: replacements_map.add(rest.split()[0])
            elif in_replace:
                if line==')': in_replace=False
                elif line: replacements_map.add(line.split()[0])
        for line in content.splitlines():
            line=line.split('//',1)[0].strip()
            if line=='require (': in_require=True; continue
            if line==')': in_require=False; continue
            target=line[8:].strip() if line.startswith('require ') else line if in_require else ''
            parts=target.split()
            if len(parts)>=2:
                if parts[0] in replacements_map: warnings.append('Go replacement requires provenance review')
                else: add(parts[0],parts[1],'Go','go',metadata={'evidence':'selected go.mod requirement'})
        if replacements_map: warnings.append('Go replace directives are not treated as upstream package matches')
    elif name=='go.sum':
        # go.sum retains historical checksums; presence is evidence, not proof of a selected installation.
        for line in content.splitlines():
            parts=line.split()
            if len(parts)==3 and not parts[1].endswith('/go.mod'):
                add(parts[0],parts[1],'Go','go','checksum',{'evidence':'checksum only','selected':False})
        warnings.append('go.sum may include historical unselected module versions')
    elif name=='composer.lock':
        doc=json.loads(content)
        for group in ('packages','packages-dev'):
            for p in doc.get(group,[]): add(p.get('name',''),p.get('version','').removeprefix('v'),'Packagist','composer',group)
    elif name=='Gemfile.lock':
        in_specs=False; in_gem=False
        for line in content.splitlines():
            if line and not line.startswith(' '):
                in_gem=line=='GEM'; in_specs=False
            if line=='  specs:': in_specs=in_gem
            match=re.match(r'^    ([A-Za-z0-9_.-]+) \(([^ )]+)\)$',line)
            if in_specs and match: add(match[1],match[2],'RubyGems','bundler')
        if 'GIT\n' in content or 'PATH\n' in content: warnings.append('Git/path gems need manual provenance review')
    elif name=='packages.lock.json':
        doc=json.loads(content)
        for framework,deps in doc.get('dependencies',{}).items():
            for n,p in deps.items():
                if p.get('resolved'): add(n,p['resolved'],'NuGet','nuget',framework)
                else: warnings.append('NuGet project dependency has no registry version')
    elif name=='project.assets.json':
        doc=json.loads(content)
        for key,p in doc.get('libraries',{}).items():
            if p.get('type')=='package' and '/' in key:
                n,v=key.rsplit('/',1); add(n,v,'NuGet','nuget')
    return found, sorted(set(warnings))


def parse_sbom(doc,source_path,source='local-sbom',image_id=None):
    """Parse Syft JSON and common CycloneDX/SPDX package coordinates only.

    The SBOM is evidence about its stated scope, never a live-host installation claim.
    """
    eco_by_type={'npm':'npm','python':'PyPI','pypi':'PyPI','maven':'Maven','java-archive':'Maven','golang':'Go','go-module':'Go','cargo':'crates.io','rust-crate':'crates.io','gem':'RubyGems','php-composer':'Packagist','composer':'Packagist','dotnet':'NuGet','nuget':'NuGet'}
    found=[]; skipped=0; positions={}
    if 'artifacts' in doc: entries=doc['artifacts'];format_name='Syft'
    elif doc.get('bomFormat')=='CycloneDX':entries=doc.get('components',[]);format_name='CycloneDX'
    elif 'spdxVersion' in doc:entries=doc.get('packages',[]);format_name='SPDX'
    else:raise ValueError('unsupported SBOM format')
    for entry in entries:
        if not isinstance(entry,dict):skipped+=1;continue
        typ=entry.get('type','');n=entry.get('name','');v=entry.get('version',entry.get('versionInfo',''))
        purl=entry.get('purl')
        if not purl:
            purl=next((x.get('referenceLocator') for x in entry.get('externalRefs',[]) if isinstance(x,dict) and x.get('referenceType')=='purl'),None)
        if isinstance(purl,str) and purl.startswith('pkg:'):typ=purl[4:].split('/',1)[0]
        if entry.get('group') and typ in {'maven','npm','composer'}:n=str(entry['group'])+(':' if typ=='maven' else '/')+n
        locations=entry.get('locations',[])
        paths=sorted(str(x.get('path','')) for x in locations if isinstance(x,dict))
        position='|'.join(paths) or typ
        slot=(n,position);positions[slot]=positions.get(slot,0)+1
        scope=position+':'+str(positions[slot])
        meta={'package_type':typ,'sbom_format':format_name,'evidence':'image SBOM' if image_id else 'local SBOM snapshot; current installation unverified','scope':'image' if image_id else 'sbom'}
        if image_id:meta.update({'container_image':image_id,'image_id':image_id})
        c=component(n,v,eco_by_type.get(typ),'container-package' if image_id else 'sbom-package',source,source_path,scope=scope,metadata=meta)
        if c:
            if isinstance(purl,str) and re.fullmatch(r'pkg:[A-Za-z0-9.+_/%@:-]+',purl):c['purl']=purl
            found.append(c)
        else:skipped+=1
    return found,skipped
