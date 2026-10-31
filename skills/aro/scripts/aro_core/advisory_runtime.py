"""Official runtime records. Archives are read in memory and never extracted."""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import io
import json
import tarfile
from urllib.parse import quote
from .advisory_matching import fixed_from_expression, normalized, osv_evidence, release, version_range

PYTHON_SNAPSHOT='https://codeload.github.com/psf/advisory-database/tar.gz/refs/heads/main'
NODE_SNAPSHOT='https://codeload.github.com/nodejs/security-wg/tar.gz/refs/heads/main'
RUNTIME_REPOS={'python':'python/cpython','node':'nodejs/node','php':'php/php-src',
               'ruby':'ruby/ruby','dotnet':'dotnet/runtime','rust':'rust-lang/rust'}
ALIASES={'python':{'python','python3','cpython'},'node':{'node','nodejs','node.js'},
         'go':{'go','golang'},'php':{'php'},'ruby':{'ruby'},
         'dotnet':{'dotnet','.net','.net runtime'},'rust':{'rust','rustc'}}


def runtime_name(component):
    if component.get('kind') not in ('runtime','toolchain'): return None
    name=str(component.get('name','')).lower()
    return next((key for key,names in ALIASES.items() if name in names),name)


def archive_records(data, prefix, limit):
    if not isinstance(data,bytes): raise ValueError('Official source snapshot is not an archive')
    records=[];total=0
    with tarfile.open(fileobj=io.BytesIO(data),mode='r|gz') as archive:
        for entry in archive:
            # Never extract; also bound unrelated archive content before decompression advances.
            total+=max(entry.size,0)
            if total>96*1024*1024: raise ValueError('Snapshot uncompressed size limit exceeded')
            relative=entry.name.split('/',1)[-1]
            if not entry.isfile() or not relative.startswith(prefix) or not relative.endswith('.json'): continue
            if relative.rsplit('/',1)[-1]=='index.json': continue
            if entry.size>2*1024*1024: raise ValueError('Advisory record size limit exceeded')
            if len(records)>=limit: raise ValueError('Runtime record budget exceeded')
            stream=archive.extractfile(entry)
            value=json.loads(stream.read())
            if not isinstance(value,dict): raise ValueError('Invalid official advisory record')
            records.append((relative,value))
    return sorted(records,key=lambda row:row[0])


def query_python(components, client, options):
    findings=[];gaps=[]
    try: records=archive_records(client.fetch(PYTHON_SNAPSHOT),'advisories/python/', min(int(options.get('max_runtime_records',1000)),2000))
    except Exception: return [],['Official PSF snapshot unavailable or invalid']
    if not records: return [],['Official PSF snapshot contains no advisory records']
    def imported(row):
        path,source=row
        identifier=source.get('id')
        if not isinstance(identifier,str) or not identifier.startswith('PSF-'): return path,None
        try:
            record=client.fetch('https://api.osv.dev/v1/vulns/'+quote(identifier,safe=''))
            return path,record if isinstance(record,dict) and record.get('id')==identifier else None
        except Exception: return path,None
    # OSV imports resolve PSF Git ranges into affected release tags. Original commit hashes are not releases.
    original=dict(records)
    with ThreadPoolExecutor(max_workers=4) as pool:
        expanded=list(pool.map(imported,[row for row in records if not row[1].get('withdrawn')]))
    for path,record in expanded:
        if not isinstance(record,dict): gaps.append('PSF record import unavailable');continue
        if record.get('withdrawn'): continue
        source_modified=original[path].get('modified');import_modified=record.get('modified')
        if source_modified:
            try:
                source_date=datetime.fromisoformat(source_modified.replace('Z','+00:00'))
                import_date=datetime.fromisoformat(import_modified.replace('Z','+00:00'))
                if import_date<source_date: gaps.append('PSF OSV import is older than official source record')
            except (AttributeError,TypeError,ValueError):
                gaps.append('PSF import modification freshness cannot be established')
        if not any(r.get('repo','').rstrip('/')=='https://github.com/python/cpython'
                   for affected in record.get('affected',[]) for r in affected.get('ranges',[])):
            gaps.append('PSF import lacks CPython repository/version evidence');continue
        for component in components:
            affected,uncertain,fixed=osv_evidence(record,None,None,component.get('version'),python_runtime=True)
            if uncertain: gaps.append('PSF import lacks affected release-tag evidence')
            if affected:
                findings.append(normalized(record,component,'python-psf',
                    'https://github.com/psf/advisory-database/blob/main/'+path,affected,fixed))
    return findings,sorted(set(gaps))


def query_node(components, client, options):
    findings=[];gaps=[]
    try: records=archive_records(client.fetch(NODE_SNAPSHOT),'vuln/core/',min(int(options.get('max_runtime_records',1000)),2000))
    except Exception: return [],['Official Node.js snapshot unavailable or invalid']
    if not records: return [],['Official Node.js snapshot contains no core advisory records']
    for path,record in records:
        if record.get('withdrawn'): continue
        for component in components:
            vulnerable=version_range(component.get('version'),record.get('vulnerable'))
            patched_expression=record.get('patched','')
            patched=version_range(component.get('version'),patched_expression) if patched_expression else False
            if vulnerable is None or patched is None:
                gaps.append('Node.js record has unsupported or missing affected-range evidence');continue
            if not vulnerable or patched: continue
            cves=record.get('cve',[])
            if isinstance(cves,str): cves=[cves]
            converted=dict(record,id=cves[0] if cves else 'NODE-'+path.rsplit('/',1)[1][:-5],aliases=cves,
                           references=[{'url':record['ref']}] if isinstance(record.get('ref'),str) else [])
            evidence=[dict(vulnerable=record.get('vulnerable'),patched=patched_expression)]
            findings.append(normalized(converted,component,'nodejs-security-wg',
                'https://github.com/nodejs/security-wg/blob/main/'+path,evidence,fixed_from_expression(patched_expression)))
    return findings,sorted(set(gaps))


def query_github(runtime,components,client,options):
    repo=RUNTIME_REPOS[runtime];findings=[];gaps=[]
    max_pages=min(max(int(options.get('max_pages',20)),1),100)
    names=ALIASES[runtime]
    for page in range(1,max_pages+1):
        url='https://api.github.com/repos/'+repo+'/security-advisories?state=published&per_page=100&page='+str(page)
        try:
            records=client.fetch(url)
            if not isinstance(records,list): raise ValueError('Expected advisory array')
        except Exception:
            gaps.append('Public repository advisory request failed');break
        for record in records:
            if not isinstance(record,dict): gaps.append('Malformed repository advisory');continue
            if record.get('withdrawn_at') or record.get('withdrawn'): continue
            for component in components:
                entries=[];fixed=[]
                for item in record.get('vulnerabilities',[]):
                    package=item.get('package') or {}
                    if str(package.get('name','')).lower() not in names:
                        gaps.append('Repository advisory package identity not mapped to runtime');continue
                    affected=version_range(component.get('version'),item.get('vulnerable_version_range'))
                    if affected is None:
                        gaps.append('Repository advisory range syntax unsupported');continue
                    if affected:
                        entries.append(item)
                        fixed.extend(fixed_from_expression(item.get('patched_versions','')))
                if entries:
                    converted=dict(record,id=record.get('ghsa_id'),aliases=[x for x in [record.get('cve_id')] if x])
                    findings.append(normalized(converted,component,'github-'+repo,
                        record.get('html_url') or 'https://github.com/'+repo+'/security/advisories/'+str(record.get('ghsa_id')),
                        entries,list(dict.fromkeys(fixed))))
        if len(records)<100: break
    else: gaps.append('Repository advisory pagination limit reached')
    if runtime not in ('python','node'):
        gaps.append('Public repository advisories do not assure complete historical vendor runtime coverage')
    return findings,sorted(set(gaps))
