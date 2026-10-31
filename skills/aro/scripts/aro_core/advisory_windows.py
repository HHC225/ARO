"""Read applicable missing Windows security updates through Windows Update Agent.

This module searches only. It never downloads, installs, accepts license terms,
changes update sources, or reboots. WUA evaluates local applicability against the
machine's configured update service; it is not a complete third-party CVE feed.
"""
from __future__ import annotations
from datetime import datetime, timezone
import json
import platform
import re
import shutil
import uuid
from urllib.parse import urlsplit
from .inventory_host import run, _trusted_tool

SOURCE='windows-update-agent'
DOCUMENTATION='https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-iupdatesearcher-search'
SECURITY_CLASSIFICATION='0fa1201d-4330-4fa8-8ae9-b877473b6441'

# Only two trusted literals (boolean and bounded integer) replace placeholders.
# None of the host names, inventory strings, titles or package metadata enter PS.
SEARCH_SCRIPT=r'''
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
try {
    $session = New-Object -ComObject Microsoft.Update.Session
    $session.ClientApplicationID = 'ARO read-only security check'
    $searcher = $session.CreateUpdateSearcher()
    $searcher.CanAutomaticallyUpgradeService = $false
    $searcher.Online = __ONLINE__
    $search = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
    function Strings($values) {
        $out = @()
        if ($null -ne $values) { for ($j=0; $j -lt $values.Count; $j++) { $out += [string]$values.Item($j) } }
        return ,$out
    }
    $updates = @()
    $limit = [Math]::Min($search.Updates.Count, __LIMIT__)
    for ($i=0; $i -lt $limit; $i++) {
        $u = $search.Updates.Item($i)
        $cats = @()
        for ($j=0; $j -lt $u.Categories.Count; $j++) {
            $c = $u.Categories.Item($j)
            $cats += @{id=[string]$c.CategoryID; name=[string]$c.Name; type=[string]$c.Type}
        }
        $cves = @(); $reboot = $null
        try { $cves = Strings $u.CveIDs } catch { }
        try { $reboot = [bool]$u.RebootRequired } catch { }
        $changed = $null
        try { $changed = $u.LastDeploymentChangeTime.ToUniversalTime().ToString('o') } catch { }
        $updates += @{
            update_id=[string]$u.Identity.UpdateID; revision=[int]$u.Identity.RevisionNumber
            title=[string]$u.Title; kb_article_ids=(Strings $u.KBArticleIDs)
            msrc_severity=[string]$u.MsrcSeverity; categories=@($cats)
            support_url=[string]$u.SupportUrl; security_bulletin_ids=(Strings $u.SecurityBulletinIDs)
            cve_ids=@($cves); reboot_required=$reboot; eula_accepted=[bool]$u.EulaAccepted
            type=[int]$u.Type; is_installed=[bool]$u.IsInstalled; is_hidden=[bool]$u.IsHidden
            last_deployment_change_time=$changed
        }
    }
    $warnings = @()
    for ($i=0; $i -lt $search.Warnings.Count; $i++) {
        $warnings += @{hresult=[int]$search.Warnings.Item($i).HResult}
    }
    @{result_code=[int]$search.ResultCode; updates=@($updates); total_updates=[int]$search.Updates.Count; warnings=@($warnings)} | ConvertTo-Json -Depth 8 -Compress
} catch {
    @{error_code=[int]$_.Exception.HResult} | ConvertTo-Json -Compress
}
'''


def _text(value,limit=1024):
    return ''.join(c for c in str(value or '') if ord(c)>=32 and ord(c)!=127)[:limit]


def _strings(value):
    if isinstance(value,str):return [value]
    return [x for x in value if isinstance(x,str)] if isinstance(value,list) else []


def _os_component(inventory):
    for c in inventory.get('components',[]):
        if not isinstance(c,dict) or not c.get('id') or not c.get('version'):continue
        meta=c.get('metadata') or {}
        if meta.get('windows_os') is True or (c.get('kind') in {'os','operating-system','os-release'} and 'windows' in str(c.get('name','')).lower()):return c
    return None


def _url(candidate,kbs):
    if isinstance(candidate,str) and len(candidate)<=2048:
        try:
            parts=urlsplit(candidate)
            domain=parts.hostname or ''
            if parts.scheme=='https' and not parts.username and not parts.password and not parts.fragment and not parts.query and (domain=='microsoft.com' or domain.endswith('.microsoft.com')) and not any(ord(c)<33 for c in candidate):return candidate
        except ValueError:pass
    return 'https://support.microsoft.com/help/'+kbs[0][2:] if kbs else DOCUMENTATION


def query_windows_updates(inventory:dict, options:dict|None=None)->dict:
    """Return advisories, sources and coverage for missing applicable updates.

    ``windows_runner(argv, run_options) -> (stdout, status)`` is injectable for
    fixture tests. Native execution is Windows-only. Offline searches use only
    existing WUA metadata and report unknown catalog freshness. Time/output and
    returned update count are bounded independently of PowerShell content.
    """
    options=dict(options or {})
    out={'advisories':[],'coverage':[],'sources':[]}
    def coverage(status,detail):out['coverage'].append({'collector':SOURCE,'status':status,'detail':detail})
    def source(status,detail,freshness='unknown'):
        out['sources'].append({'source':SOURCE,'id':SOURCE,'url':DOCUMENTATION,'status':status,'detail':detail,'freshness':freshness,'fetched_at':datetime.now(timezone.utc).isoformat() if status in {'ok','partial'} else None})
    host=inventory.get('host') or {}
    if 'windows' not in ' '.join(str(host.get(k,'')) for k in ('os','id','system','platform')).lower():
        coverage('skipped','Windows Update Agent applies only to Windows hosts');return out
    component=_os_component(inventory)
    if component is None:
        coverage('partial','A mapped Windows OS component identity/version is missing; applicable updates cannot be attached to an invented component')
        source('partial','Windows OS identity is missing from inventory');return out
    runner=options.get('windows_runner')
    if runner is not None and not callable(runner):
        coverage('error','Invalid Windows update runner');source('error','Invalid runner');return out
    if runner is None and platform.system()!='Windows':
        coverage('unavailable','Native Windows Update Agent requires a Windows host');source('unavailable','Windows COM unavailable on this platform');return out
    executable=shutil.which('powershell.exe')
    if runner is not None:executable=executable or 'powershell.exe'
    elif not executable or not _trusted_tool(executable):
        coverage('unavailable','Windows PowerShell is absent or outside trusted system directories');source('unavailable','Trusted Windows PowerShell unavailable');return out
    try:
        limit=max(1,min(int(options.get('max_windows_updates',1000)),5000))
        timeout=max(1,min(int(options.get('windows_update_timeout',60)),300))
    except (TypeError,ValueError):
        coverage('error','Invalid Windows update limits');source('error','Invalid configured limits');return out
    offline=bool(options.get('offline'))
    script=SEARCH_SCRIPT.replace('__ONLINE__','$false' if offline else '$true').replace('__LIMIT__',str(limit))
    argv=[executable,'-NoLogo','-NoProfile','-NonInteractive','-Command',script]
    try:
        data,status=(runner or run)(argv,{'command_timeout':timeout,'max_command_bytes':8*1024*1024})
        if status!='ok':
            label='timeout' if 'timeout' in str(status).lower() else 'failed or denied'
            coverage('error',f'Windows Update Agent search {label}; timeout={timeout}s; no clean result established')
            source('error',f'Windows Update Agent search {label}');return out
        if not isinstance(data,str) or len(data.encode('utf-8'))>8*1024*1024:raise ValueError('output limit')
        document=json.loads(data.lstrip('\ufeff'))
        if not isinstance(document,dict):raise ValueError('not object')
        if 'error_code' in document:
            error=document.get('error_code');code=error if isinstance(error,int) else None
            description='access denied' if code==-2147024891 else 'service unavailable, policy restricted or COM failure'
            coverage('error',f'Windows Update Agent {description}; HRESULT={code}; no updates were downloaded or installed')
            source('error',f'Windows Update Agent {description}');return out
        code=document.get('result_code')
        updates=document.get('updates')
        if code not in (2,3) or not isinstance(updates,list):raise ValueError('search not successful')
    except Exception as exc:
        coverage('error',f'Windows Update Agent returned unusable results ({type(exc).__name__}); source freshness unknown')
        source('error','Windows Update Agent failed or returned invalid structured output');return out
    omitted=0;ignored=0
    for update in updates[:limit]:
        if not isinstance(update,dict):omitted+=1;continue
        try:
            identity=str(uuid.UUID(str(update.get('update_id',''))))
            revision=update.get('revision')
            if isinstance(revision,bool) or not isinstance(revision,int) or not 0<=revision<=2147483647:raise ValueError('revision')
        except (ValueError,TypeError,AttributeError):omitted+=1;continue
        if update.get('type',1)!=1 or update.get('is_installed') is not False or update.get('is_hidden') is not False:
            ignored+=1;continue
        categories=[{'id':_text(c.get('id'),128),'name':_text(c.get('name'),256),'type':_text(c.get('type'),64)} for c in update.get('categories',[]) if isinstance(c,dict)] if isinstance(update.get('categories',[]),list) else []
        cves=sorted(set(x.upper() for x in _strings(update.get('cve_ids')) if re.fullmatch(r'CVE-\d{4}-\d{4,}',x,re.I)))
        bulletins=sorted(set(x.upper() for x in _strings(update.get('security_bulletin_ids')) if re.fullmatch(r'MS\d{2}-\d{3}',x,re.I)))
        severity={'CRITICAL':'CRITICAL','IMPORTANT':'HIGH','MODERATE':'MODERATE','LOW':'LOW'}.get(str(update.get('msrc_severity','')).upper(),'UNKNOWN')
        security=(severity!='UNKNOWN' or cves or bulletins or any(c['id'].lower()==SECURITY_CLASSIFICATION for c in categories))
        if not security:ignored+=1;continue
        kbs=sorted(set('KB'+x.upper().removeprefix('KB') for x in _strings(update.get('kb_article_ids')) if re.fullmatch(r'(?:KB)?\d{4,10}',x,re.I)))
        url=_url(update.get('support_url'),kbs)
        metadata={'fix_type':'windows_update','update_id':identity,'revision':revision,'kb_article_ids':kbs,'security_bulletin_ids':bulletins,'cve_ids':cves,'categories':categories,'reboot_required':update.get('reboot_required') if isinstance(update.get('reboot_required'),bool) else None,'eula_accepted':update.get('eula_accepted') if isinstance(update.get('eula_accepted'),bool) else None,'installed_build':_text(host.get('build'),128),'applicability':'WUA applicable missing software update; exact affected CVE ranges not inferred','catalog_freshness':'unknown' if offline else 'searched configured update source'}
        changed=update.get('last_deployment_change_time')
        if not isinstance(changed,str) or not re.fullmatch(r'\d{4}-\d\d-\d\dT[0-9:.+-]+Z?',changed):changed=None
        out['advisories'].append({'id':f'WUA:{identity}:{revision}','aliases':sorted(set(cves+bulletins)),'component_id':component['id'],'source':SOURCE,'source_url':url,'summary':_text(update.get('title') or 'Applicable missing Windows security update',2000),'severity':severity,'cvss_score':None,'attack_vector':'unknown','fixed_versions':kbs,'affected_range':{'type':'vendor_applicability','installed_version':component['version'],'installed_build':_text(host.get('build'),128)},'published':None,'modified':changed,'known_exploited':False,'match_confidence':'vendor_applicability','references':[url],'metadata':metadata})
    total=document.get('total_updates',len(updates))
    truncated=isinstance(total,int) and total>len(updates) or len(updates)>limit
    partial=offline or code==3 or bool(document.get('warnings')) or omitted>0 or truncated
    detail=f'{len(out["advisories"])} applicable security updates; {ignored} nonsecurity/driver/installed/hidden records excluded; {omitted} invalid records omitted; max_updates={limit}, timeout={timeout}s'
    if truncated:detail+='; result limit reached'
    if offline:detail+='; cached catalog only, latest freshness unknown'
    if code==3 or document.get('warnings'):detail+='; WUA returned incomplete search/warnings'
    coverage('partial' if partial else 'ok',detail)
    coverage('partial','WUA covers security updates visible to the configured update service and policy; hidden updates, all application vendors, exact CVE ranges and unsupported/EOL products are not fully covered')
    source('partial' if partial else 'ok',detail,'unknown' if offline else 'live_search')
    out['advisories'].sort(key=lambda a:a['id'])
    return out
