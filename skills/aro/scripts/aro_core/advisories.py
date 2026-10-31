"""Deterministic, exact-coordinate advisory sources with explicit coverage gaps.

The only outbound package payload is {ecosystem,name,version}. The HTTP boundary is
injectable as requester(method, url, payload=None, timeout=seconds) for offline tests.
"""
from __future__ import annotations
import fnmatch
import json
import re
from pathlib import Path
from urllib.parse import quote
from .advisory_distro import distro_coordinate
from .advisory_http import AdvisoryHTTP
from .advisory_ownership import distro_owned_runtime
from .advisory_windows import query_windows_updates
from .advisory_matching import normalized, osv_evidence, release
from .advisory_runtime import (PYTHON_SNAPSHOT,NODE_SNAPSHOT,RUNTIME_REPOS,
                               query_python,query_node,query_github,runtime_name)
from .advisory_trivy import is_distro,windows_host,query_trivy

KEV_MIRROR='https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json'
KEV_URL='https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
OSV_URL='https://api.osv.dev/v1/querybatch'
# Deliberately mapped application ecosystems; distro coordinates use vendor-aware Trivy.
ECOSYSTEMS={'PyPI','npm','Go','crates.io','Packagist','RubyGems','NuGet','Maven',
            'Hex','Pub','Hackage','SwiftURL','ConanCenter','CRAN','GHC','Julia'}


def _excluded(component,options):
    name=str(component.get('name',''));ecosystem=str(component.get('ecosystem') or '')
    source_name=str((component.get('metadata') or {}).get('source_package') or '')
    return any(fnmatch.fnmatchcase(value,pattern) for pattern in options.get('exclude_packages',[])
               if isinstance(pattern,str) for value in (name,ecosystem+':'+name,source_name))


def _eligible(inventory,options):
    return [c for c in inventory.get('components',[]) if isinstance(c,dict)
            and not _excluded(c,options) and (c.get('metadata') or {}).get('selected') is not False]


def build_source_plan(inventory,config=None):
    options=config or {};components=_eligible(inventory,options)
    coordinates={};distro_coordinates={};runtimes={};distro=[];unsupported=[]
    for component in components:
        name=component.get('name');version=component.get('version');identifier=component.get('id')
        if (not isinstance(name,str) or not isinstance(version,str) or not version.strip()
            or len(name)>500 or len(version)>200 or name.startswith(('/',chr(92)))
            or version.lower().startswith(('file:','git:','git+','http:','https:','ssh:','/',chr(92)))
            or re.search(r'[\x00-\x20]',name+version)):
            unsupported.append(identifier);continue
        if is_distro(component):
            coordinate=distro_coordinate(component,inventory,options)
            if coordinate:
                key=(coordinate['ecosystem'],coordinate['name'],coordinate['version'])
                distro_coordinates.setdefault(key,[]).append(identifier)
            else: distro.append(identifier)
            continue
        runtime=runtime_name(component)
        if runtime:
            if runtime=='go':
                if release(version) is None: unsupported.append(identifier);continue
                version=version.removeprefix('go').removeprefix('v')
                for package in ('stdlib','toolchain'):
                    coordinates.setdefault(('Go',package,version),[]).append(identifier)
            else: runtimes.setdefault(runtime,[]).append(identifier)
            continue
        ecosystem=component.get('ecosystem')
        if ecosystem in ECOSYSTEMS:
            coordinates.setdefault((ecosystem,name,version),[]).append(identifier)
        elif component.get('kind') not in ('container-image','process','listener','os'):
            unsupported.append(identifier)
    plan=[]
    if coordinates:
        plan.append(dict(source='osv',url=OSV_URL,component_ids=sorted(set(i for ids in coordinates.values() for i in ids)),
            queries=[dict(ecosystem=e,name=n,version=v,component_ids=sorted(set(ids)))
                     for (e,n,v),ids in sorted(coordinates.items())],required=True))
    if distro_coordinates:
        plan.append(dict(source='osv-distro',url=OSV_URL,
            component_ids=sorted(set(i for ids in distro_coordinates.values() for i in ids)),
            queries=[dict(ecosystem=e,name=n,version=v,component_ids=sorted(set(ids)))
                     for (e,n,v),ids in sorted(distro_coordinates.items())],required=True))
    for runtime,ids in sorted(runtimes.items()):
        if runtime=='python': plan.append(dict(source='python-psf',url=PYTHON_SNAPSHOT,component_ids=sorted(ids),runtime=runtime,required=True))
        if runtime=='node': plan.append(dict(source='nodejs-security-wg',url=NODE_SNAPSHOT,component_ids=sorted(ids),runtime=runtime,required=True))
        if runtime in RUNTIME_REPOS:
            repo=RUNTIME_REPOS[runtime]
            plan.append(dict(source='github-'+repo,url='https://api.github.com/repos/'+repo+'/security-advisories',
                component_ids=sorted(ids),runtime=runtime,required=True))
        else:
            unsupported.extend(ids)
    if (distro or inventory.get('containers') or options.get('trivy_targets') or options.get('trivy_reports')
        or any(c.get('kind')=='container-image' for c in components)):
        plan.append(dict(source='trivy',url='https://trivy.dev/',component_ids=sorted(distro),required=True))
    if windows_host(inventory): plan.append(dict(source='windows-update-agent',url='https://msrc.microsoft.com/update-guide',
                                                component_ids=[c['id'] for c in components if c.get('kind')=='os'],required=True,supported=True))
    if unsupported: plan.append(dict(source='unmapped',url=None,component_ids=sorted(set(unsupported)),required=True,supported=False))
    if components: plan.append(dict(source='cisa-kev',url=KEV_URL,component_ids=[],required=True))
    return plan


def _status(source,url,events,gaps=(),fallback='ok'):
    ranking={'ok':0,'skipped':0,'not_applicable':0,'partial':1,'stale':2,'unavailable':3,'error':4}
    status=max([e['status'] for e in events]+(['partial'] if gaps else [fallback]),key=lambda x:ranking.get(x,4))
    dates=[e['fetched_at'] for e in events if e.get('fetched_at')]
    details=sorted(set([e['detail'] for e in events if e.get('status')!='ok']+list(gaps)))
    return dict(source=source,id=source,url=url,status=status,fetched_at=min(dates) if dates else None,
                detail='; '.join(details) if details else ('All matching records checked' if status=='ok' else 'No applicable CVE findings to enrich'),
                urls=sorted({e['url'] for e in events} | ({url} if url else set())))


def _query_osv(plan,components,client,options):
    findings=[];gaps=[];queries=plan['queries'];records={};ids_for={}
    max_pages=min(max(int(options.get('max_pages',20)),1),100)
    max_records=min(max(int(options.get('max_advisories',2000)),1),10000)
    for start in range(0,len(queries),100):
        active=[(i,dict(package=dict(ecosystem=q['ecosystem'],name=q['name']),version=q['version']))
                for i,q in enumerate(queries[start:start+100],start)]
        seen={}
        for page in range(max_pages):
            try:
                result=client.fetch(OSV_URL,{'queries':[q for _,q in active]})
                entries=result.get('results') if isinstance(result,dict) else None
                if not isinstance(entries,list) or len(entries)!=len(active): raise ValueError('Batch shape mismatch')
            except Exception:
                gaps.append('OSV batch request failed or returned invalid shape');break
            next_active=[]
            for (index,query),entry in zip(active,entries):
                if not isinstance(entry,dict) or entry.get('error'):
                    gaps.append('OSV returned an individual query error');continue
                for short in entry.get('vulns',[]):
                    identifier=short.get('id') if isinstance(short,dict) else None
                    if not isinstance(identifier,str) or not identifier or len(identifier)>200:
                        gaps.append('Invalid OSV advisory identifier');continue
                    ids_for.setdefault(index,set()).add(identifier)
                token=entry.get('next_page_token')
                if token:
                    if not isinstance(token,str) or len(token)>4096 or token in seen.setdefault(index,set()):
                        gaps.append('OSV pagination token repeated or invalid');continue
                    seen[index].add(token);next_active.append((index,dict(query,page_token=token)))
            active=next_active
            if not active: break
        else: gaps.append('OSV pagination limit reached before all historical results were read')
    all_ids=sorted(set(identifier for ids in ids_for.values() for identifier in ids))
    if len(all_ids)>max_records: gaps.append('OSV full-record budget exceeded')
    for identifier in all_ids[:max_records]:
        try:
            record=client.fetch('https://api.osv.dev/v1/vulns/'+quote(identifier,safe=''))
            if not isinstance(record,dict) or record.get('id')!=identifier: raise ValueError('OSV identifier mismatch')
            records[identifier]=record
        except Exception: gaps.append('OSV full advisory fetch failed')
    for index,identifiers in sorted(ids_for.items()):
        coordinate=queries[index]
        for identifier in sorted(identifiers):
            record=records.get(identifier)
            if record is None or record.get('withdrawn'): continue
            affected,uncertain,fixed=osv_evidence(record,coordinate['name'],coordinate['ecosystem'],coordinate['version'],authoritative_query=True)
            if uncertain or not affected:
                gaps.append('OSV record has missing or unmatched package/version evidence')
            if not affected: continue
            for cid in coordinate['component_ids']:
                component=components.get(cid)
                if component:
                    finding=normalized(record,component,plan['source'],'https://osv.dev/vulnerability/'+quote(identifier,safe=''),affected,fixed,
                        'vendor-source-package' if plan['source']=='osv-distro' else 'confirmed')
                    if plan['source']=='osv-distro':
                        finding['fixed_versions_kind']='source-package'
                        finding['source_package']=dict(ecosystem=coordinate['ecosystem'],name=coordinate['name'],version=coordinate['version'])
                        binary_fixes=[entry.get('binary_version') for row in affected
                            for entry in (row.get('ecosystem_specific') or {}).get('binaries',[])
                            if entry.get('binary_name')==component.get('name') and entry.get('binary_version')]
                        if binary_fixes:
                            finding['fixed_versions_kind']='binary-package'
                            finding['source_fixed_versions']=fixed
                            finding['fixed_versions']=list(dict.fromkeys(binary_fixes))
                    findings.append(finding)
    return findings,sorted(set(gaps))


def query_advisories(inventory,cache_dir:Path,options=None):
    options=options or {};client=AdvisoryHTTP(cache_dir,options)
    plan=build_source_plan(inventory,options);components={c['id']:c for c in _eligible(inventory,options) if c.get('id')}
    findings=[];sources=[];coverage=[]
    for item in plan:
        source=item['source'];before=len(client.events);gaps=[]
        if source=='cisa-kev': continue
        if source=='unmapped':
            sources.append(_status(source,None,[],['Components have missing versions or unsupported advisory ecosystems/runtimes'],'unavailable'))
            sources[-1]['status']='unavailable';continue
        if source=='windows-update-agent':
            result=query_windows_updates(dict(inventory,components=list(components.values())),options)
            findings.extend(result['advisories']);sources.extend(result['sources']);coverage.extend(result['coverage'])
            continue
        if source=='trivy':
            # Exclusions also apply to imported scanner matching and scanner-derived outputs.
            safe_inventory=dict(inventory,components=list(components.values()))
            try: rows,states,gap_rows=query_trivy(safe_inventory,options,client.now)
            except Exception:
                rows=[];states=[_status('trivy',item['url'],[],['Malformed local scanner output'])];gap_rows=[]
            findings.extend(rows);sources.extend(states);coverage.extend(gap_rows);continue
        selected=[components[cid] for cid in item.get('component_ids',[]) if cid in components]
        try:
            if source in ('osv','osv-distro'): rows,gaps=_query_osv(item,components,client,options)
            elif source=='python-psf': rows,gaps=query_python(selected,client,options)
            elif source=='nodejs-security-wg': rows,gaps=query_node(selected,client,options)
            elif source.startswith('github-'): rows,gaps=query_github(item['runtime'],selected,client,options)
            else: rows=[];gaps=['Unsupported source adapter']
        except Exception:
            rows=[];gaps=['Source response is malformed or unsupported; matching did not complete']
        for row in rows:
            component=components.get(row['component_id'],{})
            if runtime_name(component):
                row['fixed_versions_kind']='upstream-runtime'
                if distro_owned_runtime(component,inventory):
                    row['match_confidence']='upstream-version'
                    row['applicability_note']='Upstream runtime version match; distributor backports require vendor package verification'
                    gaps.append('Distro-owned runtime banner omits vendor backports; upstream findings require vendor review')
        findings.extend(rows)
        sources.append(_status(source,item['url'],client.events[before:],gaps))
    kev_plan=next((item for item in plan if item['source']=='cisa-kev'),None)
    if kev_plan:
        before=len(client.events);gaps=[]
        cves={alias for row in findings for alias in [row['id']]+row['aliases'] if alias.startswith('CVE-')}
        if cves:
            try:
                try: data=client.fetch(KEV_URL)
                except Exception:
                    gaps.append('Primary CISA feed failed; checked official CISA GitHub mirror')
                    data=client.fetch(KEV_MIRROR)
                if not isinstance(data,dict) or not isinstance(data.get('vulnerabilities'),list): raise ValueError('Invalid KEV feed')
                known={entry.get('cveID'):entry for entry in data['vulnerabilities'] if isinstance(entry,dict)}
                for row in findings:
                    matches=sorted(set([row['id']]+row['aliases'])&known.keys())
                    row['known_exploited']=bool(matches)
                    if matches: row['kev']=[known[key] for key in matches]
            except Exception: gaps.append('CISA KEV exploitation context could not be checked')
            sources.append(_status('cisa-kev',KEV_URL,client.events[before:],gaps))
        else:
            sources.append(_status('cisa-kev',KEV_URL,[],fallback='not_applicable'))
    unique={}
    for row in findings:
        key=(row['component_id'],row['id'],row['source'])
        if key in unique:
            existing=unique[key]
            for field in ('fixed_versions','references','aliases'):
                existing[field]=list(dict.fromkeys(existing.get(field,[])+row.get(field,[])))
            if isinstance(existing.get('affected_range'),list) and isinstance(row.get('affected_range'),list):
                for evidence in row['affected_range']:
                    if evidence not in existing['affected_range']: existing['affected_range'].append(evidence)
        else: unique[key]=row
    coverage.extend(dict(collector=s['source'],status=s['status'],detail=s['detail']) for s in sources
                    if s['source'] not in ('trivy','windows-update-agent'))
    excluded=sum(_excluded(c,options) for c in inventory.get('components',[]) if isinstance(c,dict))
    if excluded: coverage.append(dict(collector='package-exclusions',status='skipped',detail=f'{excluded} components excluded by local privacy configuration'))
    selection_reasons={}
    for component in inventory.get('components',[]):
        metadata=component.get('metadata') or {}
        if metadata.get('selected') is not False: continue
        if metadata.get('provenance_reason'): reason='unverified package provenance'
        elif 'checksum' in str(metadata.get('evidence','')).lower(): reason='checksum-only evidence'
        else: reason='unselected evidence'
        selection_reasons[reason]=selection_reasons.get(reason,0)+1
    coverage.extend(dict(collector='component-selection',status='skipped',reason=reason,
                         detail=f'{count} coordinates excluded from public advisory queries: {reason}')
                    for reason,count in sorted(selection_reasons.items()))
    return dict(advisories=[unique[key] for key in sorted(unique)],sources=sorted(sources,key=lambda s:(s['source'],s.get('url') or '',s['status'])),
                coverage=sorted(coverage,key=lambda c:(c['collector'],c['status'],c['detail'])),source_plan=plan)
