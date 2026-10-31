"""Optional local-only distro scanner; no tool installation or remote image sources."""
from __future__ import annotations
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from .advisory_matching import normalized

DISTRO_MANAGERS={'dpkg','apt','apt-get','rpm','dnf','yum','apk','pacman'}


def is_distro(component):
    return (str(component.get('manager','')).lower() in DISTRO_MANAGERS
            or str(component.get('source','')).lower() in DISTRO_MANAGERS
            or str(component.get('purl','')).startswith(('pkg:deb/','pkg:rpm/','pkg:apk/','pkg:alpm/'))
            or str((component.get('metadata') or {}).get('package_type','')) in ('deb','rpm','apk','alpm')
            or component.get('kind') in ('os-package','os_package','system-package')
            or str(component.get('ecosystem','')).split(':')[0] in ('Debian','Ubuntu','Alpine','Red Hat','Rocky Linux','AlmaLinux','SUSE'))


def windows_host(inventory):
    host=inventory.get('host') or {}
    return 'windows' in ' '.join(str(host.get(k,'')) for k in ('os','id','system','platform')).lower()


def _epoch(value):
    try: return datetime.fromisoformat(value.replace('Z','+00:00')).timestamp()
    except (AttributeError,ValueError,TypeError): return None


def _source(status,detail,fetched_at=None):
    return dict(source='trivy',id='trivy',url='https://trivy.dev/',status=status,detail=detail,fetched_at=fetched_at)


def _trusted_scanner(executable):
    path=Path(executable)
    if not path.is_absolute(): return False
    text=str(path.resolve()).replace(chr(92),'/').lower()
    if os.name=='nt': return text.startswith(('c:/windows/','c:/program files/','c:/program files (x86)/'))
    return text.startswith(('/usr/bin/','/usr/local/bin/','/bin/','/opt/codex/runtimes/'))


def query_trivy(inventory,options,now):
    findings=[];sources=[];coverage=[]
    reports=list(options.get('trivy_reports') or [])
    targets=options.get('trivy_targets')
    candidates=[c for c in inventory.get('components',[]) if is_distro(c)]
    known_images=set()
    for container in inventory.get('containers',[]):
        for value in (container.get('image_id'),container.get('image'),(container.get('metadata') or {}).get('image_id')):
            if isinstance(value,str) and re.fullmatch(r'sha256:[0-9a-f]{64}',value): known_images.add(value)
    for component in inventory.get('components',[]):
        meta=component.get('metadata') or {}
        values=[meta.get('image_id')]
        if component.get('kind')=='container-image': values.extend([component.get('name'),component.get('version')])
        for value in values:
            if isinstance(value,str) and re.fullmatch(r'sha256:[0-9a-f]{64}',value): known_images.add(value)
    if not reports and targets is None:
        targets=[]
        if any((c.get('metadata') or {}).get('image_id') is None and c.get('kind')!='sbom-package' for c in candidates) and not windows_host(inventory):
            targets.append({'kind':'rootfs','target':'/'})
        targets.extend({'kind':'image','target':image} for image in sorted(known_images))
    target_limit=min(max(int(options.get('max_trivy_targets',8)),1),64)
    if len(targets or [])>target_limit:
        sources.append(_source('partial','Local Trivy target budget exceeded; some images were not scanned'))
    for target in (targets or [])[:target_limit]:
        kind=target.get('kind');value=target.get('target')
        valid=(kind=='rootfs' and value=='/' and not windows_host(inventory)
               or kind=='image' and value in known_images)
        if not valid:
            coverage.append(dict(collector='trivy',status='unavailable',detail='Requested Trivy target is not a mapped local host root or immutable local image ID'))
            sources.append(_source('unavailable','Unmapped target was not scanned'));continue
        executable=shutil.which('trivy')
        if not executable or not _trusted_scanner(executable):
            sources.append(_source('unavailable','Optional Trivy executable is absent or outside trusted system tool directories'));continue
        env={k:v for k,v in os.environ.items() if not k.upper().startswith('TRIVY_')}
        try:
            with tempfile.TemporaryDirectory(prefix='aro-trivy-') as working:
                args=[executable,kind,'--scanners','vuln','--pkg-types','os','--format','json',
                      '--offline-scan','--skip-java-db-update','--skip-check-update',
                      '--db-repository','ghcr.io/aquasecurity/trivy-db:2',
                      '--skip-version-check','--skip-vex-repo-update','--disable-telemetry',
                      '--timeout','60s','--quiet']
                if options.get('offline') or options.get('trivy_skip_db_update'):
                    args+=['--skip-db-update']
                if kind=='image': args+=['--image-src','docker']
                if options.get('trivy_cache_dir'): args+=['--cache-dir',str(Path(options['trivy_cache_dir']).resolve())]
                args+=[value]
                completed=subprocess.run(args,capture_output=True,text=True,timeout=75,cwd=working,env=env,check=False)
                if completed.returncode: raise RuntimeError('Trivy scan failed')
                if len(completed.stdout)>32*1024*1024: raise ValueError('Scanner output limit exceeded')
                report=json.loads(completed.stdout)
                version_args=[executable,'--version','--format','json']
                if options.get('trivy_cache_dir'): version_args+=['--cache-dir',str(Path(options['trivy_cache_dir']).resolve())]
                version=subprocess.run(version_args,capture_output=True,text=True,
                     timeout=10,cwd=working,env=env,check=False)
                db=json.loads(version.stdout) if version.returncode==0 else {}
            metadata=db.get('VulnerabilityDB') or db.get('vulnerabilityDB') or {}
            reports.append(dict(report=report,scope=target.get('scope'),image_id=value if kind=='image' else None,
                                db_updated_at=metadata.get('UpdatedAt') or options.get('trivy_db_updated_at')))
        except Exception:
            sources.append(_source('error','Trivy unavailable, timed out, or failed with local database; no tool installation or remote target pull attempted'))
    for wrapper in reports:
        report=wrapper.get('report') or {}
        db_date=wrapper.get('db_updated_at');epoch=_epoch(db_date)
        status='ok';details=[]
        if epoch is None:
            status='partial';details.append('Trivy database age unknown')
        elif now-epoch>max(0,float(options.get('trivy_db_max_age_hours',24)))*3600 or epoch>now+300:
            status='stale';details.append('Trivy database is stale or timestamp is in the future')
        report_os=((report.get('Metadata') or {}).get('OS') or {})
        if not report_os.get('Family'):
            details.append('Distribution identity unavailable in scanner report')
            if status=='ok': status='partial'
        if report_os.get('EOSL'): details.append('Distribution is end of life; vendor coverage may be limited');status='partial'
        image_id=wrapper.get('image_id')
        scope=wrapper.get('scope')
        for section in report.get('Results',[]):
            if section.get('Class')!='os-pkgs': continue
            for vulnerability in section.get('Vulnerabilities') or []:
                name=vulnerability.get('PkgName');version=vulnerability.get('InstalledVersion')
                def same_scope(component):
                    meta=component.get('metadata') or {}
                    family=str(report_os.get('Family') or '').lower()
                    expected=str(meta.get('distribution') or ('' if image_id else (inventory.get('host') or {}).get('id')) or '').lower()
                    expected_version=meta.get('distribution_version')
                    if family and expected and family!=expected:
                        details.append('Scanner distribution does not match inventoried package distribution')
                        return False
                    if expected_version and report_os.get('Name') and str(expected_version)!=str(report_os['Name']):
                        details.append('Scanner distribution version does not match inventoried package distribution')
                        return False
                    c_image=meta.get('image_id') or component.get('image_id')
                    c_scope=component.get('scope')
                    if image_id: return c_image==image_id or (scope is not None and c_scope==scope)
                    if c_image is not None or meta.get('scope') in ('image','sbom'): return False
                    return (scope is None and (component.get('kind')=='os-package' or c_scope in (None,'host','system'))) or scope==c_scope
                matches=[c for c in candidates if c.get('name')==name and c.get('version')==version and same_scope(c)]
                if not matches:
                    details.append('Scanner findings could not be mapped to an exact local package and scope')
                    if status=='ok': status='partial'
                for component in matches:
                    cvss={}
                    for entry in (vulnerability.get('CVSS') or {}).values():
                        if isinstance(entry,dict) and entry.get('V3Score') is not None:
                            cvss=dict(score=entry.get('V3Score'),vector_string=entry.get('V3Vector'));break
                    record=dict(id=vulnerability.get('VulnerabilityID'),summary=vulnerability.get('Title'),
                        severity=vulnerability.get('Severity'),cvss=cvss,aliases=[],
                        published=vulnerability.get('PublishedDate'),modified=vulnerability.get('LastModifiedDate'),
                        references=vulnerability.get('References') or [])
                    fixed=[x.strip() for x in str(vulnerability.get('FixedVersion') or '').split(',') if x.strip()]
                    finding=normalized(record,component,'trivy',vulnerability.get('PrimaryURL') or 'https://trivy.dev/',
                        [dict(distribution=report_os,installed_version=version,fixed_versions=fixed,
                              vendor_source=vulnerability.get('DataSource') or {})],fixed,'vendor-package')
                    finding['fixed_versions_kind']='binary-package'
                    findings.append(finding)
        sources.append(_source(status,'; '.join(sorted(set(details))) or 'Distribution-aware local scanner report',db_date))
    if not sources and (candidates or inventory.get('containers')):
        sources.append(_source('unavailable','No mapped local Trivy targets or usable imported scanner reports'))
    coverage.extend(dict(collector='trivy',status=s['status'],detail=s['detail']) for s in sources)
    return findings,sources,coverage
