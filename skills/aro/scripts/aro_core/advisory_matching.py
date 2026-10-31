"""Conservative version evidence normalization. Distribution versions are excluded."""
from __future__ import annotations
import re


def release(value):
    """Only final numeric upstream releases; unknown syntax never sorts as a version."""
    if not isinstance(value,str): return None
    match=re.fullmatch(r'(?:v|go)?(\d+)\.(\d+)(?:\.(\d+))?',value.strip())
    return tuple(int(x or 0) for x in match.groups()) if match else None


def version_range(version, expression):
    """A bounded subset of npm/GH ranges. None means unsupported evidence."""
    value=release(version)
    if value is None or not isinstance(expression,str) or not expression.strip(): return None
    outcomes=[]
    for alternative in expression.split('||'):
        text=alternative.strip().replace(',',' ')
        if not text: return None
        hyphen=re.fullmatch(r'(\d+\.\d+\.\d+)\s+-\s+(\d+\.\d+\.\d+)',text)
        if hyphen:
            outcomes.append(release(hyphen[1])<=value<=release(hyphen[2]));continue
        tokens=re.findall(r'(?:>=|<=|>|<|=|\^|~)?\s*(?:v?\d+(?:\.(?:\d+|x|X|\*)){0,2}|\*)',text)
        if not tokens or re.sub(r'\s+','', ''.join(tokens)) != re.sub(r'\s+','',text):
            outcomes.append(None);continue
        conditions=[]
        for token in tokens:
            token=re.sub(r'\s+','',token)
            matched=re.fullmatch(r'(>=|<=|>|<|=|\^|~)?v?(\d+(?:\.(?:\d+|x|X|\*)){0,2}|\*)',token)
            if not matched: conditions.append(None);continue
            op,raw=matched.groups();op=op or '='
            if raw=='*': conditions.append(True);continue
            parts=raw.split('.')
            wildcard=any(x.lower()=='x' or x=='*' for x in parts) or len(parts)<3
            if wildcard:
                prefix=[]
                for part in parts:
                    if not part.isdigit(): break
                    prefix.append(int(part))
                lower=tuple(prefix+[0]*(3-len(prefix)))
                upper=list(lower)
                if prefix:
                    upper[len(prefix)-1]+=1
                    for index in range(len(prefix),3): upper[index]=0
                if op=='=': condition=value[:len(prefix)]==tuple(prefix)
                elif op=='>=': condition=value>=lower
                elif op=='>': condition=value>=tuple(upper)
                elif op=='<': condition=value<lower
                elif op=='<=': condition=value<tuple(upper)
                else: condition=None
                conditions.append(condition);continue
            other=release(raw)
            if other is None: conditions.append(None);continue
            if op=='=': condition=value==other
            elif op=='>=': condition=value>=other
            elif op=='<=': condition=value<=other
            elif op=='>': condition=value>other
            elif op=='<': condition=value<other
            elif op=='~': condition=other<=value<(other[0],other[1]+1,0)
            else:
                upper=(other[0]+1,0,0) if other[0] else ((0,other[1]+1,0) if other[1] else (0,0,other[2]+1))
                condition=other<=value<upper
            conditions.append(condition)
        outcomes.append(False if False in conditions else (None if None in conditions else True))
    return True if True in outcomes else (None if None in outcomes else False)


def fixed_from_expression(expression):
    if not isinstance(expression,str): return []
    return list(dict.fromkeys(re.findall(r'(?:\^|~|>=|=)?\s*(\d+\.\d+\.\d+)(?![\w.-])',expression)))


def _numeric_semver_range(value, item):
    """OSV event evaluation for final releases; other syntax remains source-validated."""
    version=release(value)
    if version is None: return None
    events=item.get('events')
    if not isinstance(events,list): return None
    converted=[];limits=[]
    for event in events:
        if not isinstance(event,dict) or len(event)!=1: return None
        kind,text=next(iter(event.items()))
        if kind=='limit' and text=='*': limits.append(None);continue
        point=(0,0,0) if kind=='introduced' and text=='0' else release(text)
        if point is None: return None
        if kind=='limit': limits.append(point)
        elif kind in ('introduced','fixed','last_affected'): converted.append((point,kind))
        else: return None
    if limits and not any(point is None or version<point for point in limits): return False
    affected=False
    for point,kind in sorted(converted):
        if kind=='introduced' and version>=point: affected=True
        elif kind=='fixed' and version>=point: affected=False
        elif kind=='last_affected' and version>point: affected=False
    return affected


def osv_evidence(record, name, ecosystem, version, authoritative_query=False, python_runtime=False):
    """Return matching affected entries, uncertainty, fixed releases with no branch selection."""
    matched=[];uncertain=False;fixed=[]
    affected_items=record.get('affected',[])
    if not isinstance(affected_items,list): return [],True,[]
    for affected in affected_items:
        if not isinstance(affected,dict): uncertain=True;continue
        package=affected.get('package') or {}
        if not isinstance(package,dict): uncertain=True;continue
        if not isinstance(affected.get('ranges',[]),list) or not isinstance(affected.get('versions',[]),list):
            uncertain=True;continue
        if python_runtime:
            if not any(r.get('repo','').rstrip('/')=='https://github.com/python/cpython'
                       for r in affected.get('ranges',[])): continue
            tags=affected.get('versions',[])
            if not tags:
                uncertain=True;continue
            if not any(release(tag)==release(version) and release(version) is not None for tag in tags): continue
        elif package.get('name')!=name or package.get('ecosystem')!=ecosystem:
            continue
        elif not authoritative_query:
            if version not in affected.get('versions',[]):
                uncertain=True;continue
        if not python_runtime and affected.get('versions') and not affected.get('ranges') and version not in affected['versions']:
            uncertain=True;continue
        if not python_runtime and version not in affected.get('versions',[]):
            ranges=affected.get('ranges',[])
            if ranges and all(isinstance(item,dict) and item.get('type')=='SEMVER' for item in ranges):
                verdicts=[_numeric_semver_range(version,item) for item in ranges]
                if verdicts and all(verdict is False for verdict in verdicts):
                    uncertain=True;continue
        # Exact coordinate/version query is OSV's range proof, including non-semver ecosystems.
        if not python_runtime and not affected.get('versions') and not affected.get('ranges'):
            uncertain=True;continue
        matched.append(affected)
        for value in affected.get('ranges',[]):
            if value.get('type')=='GIT': continue
            for event in value.get('events',[]):
                if 'fixed' in event and isinstance(event['fixed'],str): fixed.append(event['fixed'])
    return matched,uncertain,list(dict.fromkeys(fixed))


def normalized(record, component, source, source_url, affected, fixed, confidence='confirmed'):
    aliases=sorted(set(str(x) for x in record.get('aliases',[]) if isinstance(x,str)) |
                   {x for x in record.get('upstream',[]) if isinstance(x,str) and re.fullmatch(r'CVE-\d{4}-\d{4,}',x)})
    score=None;vector='unknown'
    severity=str((record.get('database_specific') or {}).get('severity',record.get('severity','UNKNOWN'))).upper()
    if severity not in ('LOW','MODERATE','MEDIUM','HIGH','CRITICAL'): severity='UNKNOWN'
    if severity=='UNKNOWN' and isinstance(record.get('severity'),list):
        for item in record['severity']:
            candidate=str(item.get('score','')).upper() if isinstance(item,dict) else ''
            if candidate in ('LOW','MODERATE','MEDIUM','HIGH','CRITICAL'):
                severity=candidate;break
    cvss=record.get('cvss') or {}
    if isinstance(cvss,dict):
        score=cvss.get('score'); cvss_text=cvss.get('vector_string') or ''
    else: cvss_text=''
    for item in record.get('severity',[]) if isinstance(record.get('severity'),list) else []:
        if isinstance(item,dict): cvss_text+=' '+str(item.get('score',''))
    for key,label in [('N','network'),('A','adjacent'),('L','local'),('P','physical')]:
        if '/AV:'+key in cvss_text: vector=label;break
    if not isinstance(score,(int,float)) or not 0<=score<=10: score=None
    references=[]
    for item in record.get('references',[]):
        url=item.get('url') if isinstance(item,dict) else item
        if isinstance(url,str) and url.startswith(('https://','http://')): references.append(url)
    return dict(id=str(record.get('id') or record.get('ghsa_id') or ''),aliases=aliases,
                component_id=component['id'],source=source,source_url=source_url,
                summary=str(record.get('summary') or record.get('description') or record.get('details') or 'No summary supplied')[:2000],
                severity=severity,cvss_score=score,attack_vector=vector,fixed_versions=fixed,
                affected_range=affected,published=record.get('published') or record.get('published_at'),
                modified=record.get('modified') or record.get('updated_at'),known_exploited=False,
                match_confidence=confidence,references=sorted(set(references)),fixed_versions_kind='upstream-package')
