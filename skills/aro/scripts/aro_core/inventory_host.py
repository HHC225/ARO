"""Native read-only collectors. Fixed argument arrays; never execute project code."""
from __future__ import annotations
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
from .inventory_parsers import component, parse_sbom


def cov(result,collector,status,detail):
    result['coverage'].append({'collector':collector,'status':status,'detail':detail})


def run(argv,options):
    """Bound wall time and captured bytes without retaining raw error output."""
    timeout=options.get('command_timeout',20); limit=options.get('max_command_bytes',8*1024*1024)
    try:
        with tempfile.TemporaryFile() as output:
            proc=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=output,stderr=subprocess.DEVNULL,shell=False)
            start=time.monotonic(); error=None
            while proc.poll() is None:
                if os.fstat(output.fileno()).st_size>limit: error='output limit exceeded'; break
                if time.monotonic()-start>=timeout: error=f'timeout after {timeout}s'; break
                time.sleep(0.02)
            if error:
                proc.kill(); proc.wait(); return '',error
            if os.fstat(output.fileno()).st_size>limit:return '','output limit exceeded'
            if proc.returncode:return '',f'command exited {proc.returncode}'
            output.seek(0)
            return output.read(limit).decode('utf-8',errors='replace'),'ok'
    except (OSError,ValueError) as exc:return '',f'command unavailable ({type(exc).__name__})'


def _read(path,limit=2*1024*1024):
    with open(path,'rb') as f:
        data=f.read(limit+1)
    if len(data)>limit:raise ValueError('file limit')
    return data.decode(errors='replace')


def linux_packages(result,options):
    candidates=[('dpkg-query','apt',['-W','-f=${Package}\t${Version}\t${Architecture}\t${Status}\t${source:Package}\t${source:Version}\n']),('rpm','dnf',['-qa','--qf','%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{ARCH}\n']),('apk','apk',['info','-v']),('pacman','pacman',['-Q'])]
    present=False
    for binary,manager,args in candidates:
        exe=shutil.which(binary)
        if not exe:continue
        if not _trusted_tool(exe):cov(result,'os-packages','skipped',f'{binary}: executable outside trusted system tool directories');continue
        present=True; data,status=run([exe,*args],options)
        if status!='ok':cov(result,'os-packages','error',f'{binary}: {status}');continue
        count=0; malformed=0
        for line in data.splitlines():
            parts=line.split('\t') if binary in {'dpkg-query','rpm'} else line.split()
            n=v=arch=None
            if binary=='dpkg-query' and len(parts)>=4:
                if parts[3]!='install ok installed':continue
                n,v,arch=parts[:3]
            elif binary=='rpm' and len(parts)==3:n,v,arch=parts
            elif binary=='pacman' and len(parts)==2:n,v=parts
            elif binary=='apk':
                match=re.match(r'^(.+)-(\d[^\s]*)$',line)
                if match:n,v=match.groups()
            if n and v:
                meta={'distribution':result['host'].get('id'),'distribution_version':result['host'].get('version')}
                if arch:meta['architecture']=arch
                if binary=='dpkg-query' and len(parts)>=6:
                    meta['source_package']=parts[4];meta['source_version']=parts[5]
                if result['host'].get('release'):meta['distribution_release']=result['host']['release']
                c=component(n,v,None,'os-package',binary,manager=manager,scope=arch,metadata=meta)
                if c:result['components'].append(c);count+=1
            else:malformed+=1
        cov(result,'os-packages','partial' if malformed else 'ok',f'{binary}: {count} packages; {malformed} unparsed rows; distro versions retained without upstream comparison')
    if not present:cov(result,'os-packages','unavailable','No supported dpkg/rpm/apk/pacman query tool visible')


def linux_processes(result,options):
    roots=[]; processes=[]; failed=0; bounded=False; socket_owners={}
    try:pids=sorted((p for p in Path('/proc').iterdir() if p.name.isdigit()),key=lambda p:int(p.name))
    except OSError:
        cov(result,'processes','unavailable','/proc is inaccessible');return roots,{}
    for p in pids[:options.get('max_processes',4096)]:
        row={'pid':int(p.name)}
        try:row['name']=_read(p/'comm',1024).strip()
        except OSError:failed+=1;continue
        for field,link in (('executable','exe'),('cwd','cwd')):
            try:
                value=os.readlink(p/link)
                if value.endswith(' (deleted)'):value=value[:-10]
                row[field]=value
                candidate=Path(value) if field=='cwd' else Path(value).parent
                # Only plausible service roots. System executable directories are not projects.
                if candidate.is_absolute() and str(candidate) not in {'/','/usr/bin','/usr/sbin','/bin','/sbin','/usr/lib','/usr/libexec'} and candidate.is_dir():roots.append(str(candidate))
            except OSError:failed+=1
        try:
            for fd_index,fd in enumerate((p/'fd').iterdir()):
                if fd_index>=options.get('max_process_fds',1024):failed+=1;break
                try:
                    target=os.readlink(fd)
                    if target.startswith('socket:['):socket_owners.setdefault(target[8:-1],[]).append(int(p.name))
                except OSError:pass
        except OSError:pass
        processes.append(row)
    bounded=len(pids)>options.get('max_processes',4096)
    result['processes']=processes
    cov(result,'processes','partial' if failed or bounded else 'ok',f'{len(processes)} visible processes; {failed} unavailable fields; max_processes={options.get("max_processes",4096)}; executable and cwd only, command lines/environment excluded')
    return sorted(set(roots)),socket_owners


def _address(raw,ipv6=False):
    if ipv6:
        data=b''.join(bytes.fromhex(raw[i:i+8])[::-1] for i in range(0,32,8))
        return str(ipaddress.IPv6Address(data))
    return socket.inet_ntop(socket.AF_INET,struct.pack('<I',int(raw,16)))


def linux_network(result,options,owners):
    count=0; failures=0
    for proto in ('tcp','tcp6','udp','udp6'):
        try:data=_read('/proc/net/'+proto,options.get('max_command_bytes',8*1024*1024))
        except (OSError,ValueError):failures+=1;continue
        for line in data.splitlines()[1:]:
            parts=line.split()
            if len(parts)<10:continue
            if proto.startswith('tcp') and parts[3]!='0A':continue
            # UDP with a connected peer is not a listening endpoint.
            if proto.startswith('udp') and parts[2].split(':')[-1]!='0000':continue
            try:
                addr,port=parts[1].split(':')
                result['network']['listeners'].append({'protocol':'udp' if proto.startswith('udp') else 'tcp','address':_address(addr,proto.endswith('6')),'port':int(port,16),'pids':sorted(set(owners.get(parts[9],[])))})
                count+=1
            except (ValueError,IndexError):failures+=1
    ip=shutil.which('ip')
    if ip and _trusted_tool(ip):
        data,status=run([ip,'-j','address','show'],options)
        if status=='ok':
            try:
                for interface in json.loads(data):
                    label=interface.get('ifname','')
                    for address in interface.get('addr_info',[]):
                        if address.get('local'):result['network']['addresses'].append({'interface':label,'address':address['local'],'family':address.get('family')})
                    if label.startswith(('tun','tap','wg','tailscale','zt','ppp')):result['network']['tunnels'].append({'interface':label,'evidence':'interface name suggests tunnel; route/exposure unverified'})
            except (ValueError,TypeError,AttributeError):failures+=1
        else:failures+=1
    else:cov(result,'network-addresses','unavailable','ip utility unavailable; interface addresses and tunnel observations incomplete')
    cov(result,'listeners','partial' if failures else 'ok',f'{count} visible host network namespace endpoints; process attribution is best effort; other network namespaces and external forwarding are unverified')


def _trusted_tool(exe):
    path=Path(exe)
    if not path.is_absolute():return False
    if platform.system()=='Windows':
        # Known operating-system application directories; no project-relative PATH entries.
        text=str(path).lower().replace('\\','/')
        return text.startswith(('c:/windows/','c:/program files/','c:/program files (x86)/'))
    path=path.resolve()
    return any(str(path).startswith(prefix) for prefix in ('/usr/bin/','/usr/sbin/','/usr/local/bin/','/usr/lib/','/usr/lib64/','/usr/local/lib/','/bin/','/sbin/','/opt/codex/runtimes/'))


def runtimes(result,options):
    # Never execute binaries found by walking project directories.
    commands=[('python',sys.executable,['--version'],'PyPI'),('node','node',['--version'],'npm'),('go','go',['version'],'Go'),('ruby','ruby',['--version'],'RubyGems'),('php','php',['--version'],'Packagist'),('java','java',['--version'],'Maven'),('dotnet','dotnet',['--list-runtimes'],'NuGet'),('rustc','rustc',['--version'],'crates.io')]
    for name,binary,args,eco in commands:
        exe=sys.executable if name=='python' else shutil.which(binary)
        if not exe:
            cov(result,'runtime-'+name,'ok','Not applicable: runtime executable not observed on PATH; custom runtime installations remain outside this observation')
            result['coverage'][-1]['applicability']='not_applicable'
            continue
        # A discovered root must never control the runtime lookup via a relative PATH entry.
        if not _trusted_tool(exe) and name!='python':
            cov(result,'runtime-'+name,'skipped','Runtime executable is outside trusted system tool directories; untrusted project binaries are never executed');continue
        data,status=run([exe,*args],options)
        if status!='ok':cov(result,'runtime-'+name,'error',status);continue
        pattern=r'(v?\d+\.\d+(?:\.\d+)?(?:[A-Za-z][A-Za-z0-9]*)?(?:[-+._][A-Za-z0-9._+-]+)?)'
        if name=='dotnet':
            count=0
            for line in data.splitlines():
                parts=line.split()
                if len(parts)>=2 and re.fullmatch(pattern,parts[1]):
                    c=component(name,parts[1],None,'runtime','runtime-version',exe,scope=parts[0],metadata={'runtime_family':parts[0],'advisory_ecosystem_hint':eco})
                    if c:result['components'].append(c);count+=1
            cov(result,'runtime-'+name,'ok' if count else 'partial',f'{count} shared runtime family installations observed; SDK-only installations may be absent')
            continue
        match=re.search((r'\bgo' if name=='go' else r'\b')+pattern,data)
        if match:
            c=component(name,match[1].removeprefix('v'),None,'runtime','runtime-version',exe,metadata={'advisory_ecosystem_hint':eco})
            if c:result['components'].append(c)
            cov(result,'runtime-'+name,'ok','Version observed from fixed version query')
        else:cov(result,'runtime-'+name,'partial','Version query did not yield a recognized version; stderr is excluded')


def python_metadata(result,options):
    # Read the active interpreter's visible metadata without importing discovered packages.
    from importlib.metadata import distributions
    count=0; failed=0
    try:
        for index,dist in enumerate(distributions()):
            if index>=options.get('max_files',100000):failed+=1;break
            try:
                c=component(dist.metadata.get('Name',''),dist.version,'PyPI','package','python-metadata',str(dist.locate_file('')),'pip',metadata={'interpreter':os.path.abspath(sys.executable),'environment_prefix':os.path.abspath(sys.prefix),'evidence':'active interpreter distribution metadata'})
                if c:result['components'].append(c);count+=1
                else:failed+=1
            except (OSError,ValueError,TypeError):failed+=1
        cov(result,'python-metadata','partial' if failed else 'ok',f'{count} active interpreter distributions; {failed} unreadable/invalid; other environments require visible metadata roots')
    except Exception as exc:cov(result,'python-metadata','error',f'Metadata discovery failed ({type(exc).__name__})')


def collect_host(result,options):
    if platform.system()=='Windows':return windows_host(result,options)
    if platform.system()!='Linux':
        cov(result,'host','unavailable','Native host collection supports Linux and Windows only');return []
    try:
        fields={}
        for line in _read('/etc/os-release',65536).splitlines():
            key,sep,value=line.partition('=')
            if sep and key in {'ID','VERSION_ID','VERSION','PRETTY_NAME'}:fields[key]=value.strip('"\'')
        result['host'].update({'id':fields.get('ID','linux'),'version':fields.get('VERSION_ID',platform.release()),'name':fields.get('PRETTY_NAME','Linux'),'kernel':platform.release(),'release':fields.get('VERSION',fields.get('PRETTY_NAME',''))})
        cov(result,'os','ok','OS release metadata and kernel version observed')
    except (OSError,ValueError):cov(result,'os','partial','OS release metadata inaccessible; platform kernel information retained')
    linux_packages(result,options)
    roots,owners=linux_processes(result,options)
    linux_network(result,options,owners)
    runtimes(result,options)
    python_metadata(result,options)
    return roots


WINDOWS_SCRIPT=r'''
$ErrorActionPreference='Stop'
$errors=@()
function Read-Part($Name,[scriptblock]$Code) { try { & $Code } catch { $script:errors += $Name; @() } }
$os=Read-Part 'os' {Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture}
$apps=Read-Part 'apps' {Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object DisplayName | Select-Object DisplayName,DisplayVersion,Publisher,PSChildName}
$hotfixes=Read-Part 'hotfixes' {Get-HotFix | Select-Object HotFixID}
$processes=Read-Part 'processes' {Get-CimInstance Win32_Process | Select-Object ProcessId,Name,ExecutablePath}
$listeners=Read-Part 'listeners' {@(Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess,@{n='Protocol';e={'tcp'}}) + @(Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess,@{n='Protocol';e={'udp'}})}
$addresses=Read-Part 'addresses' {Get-NetIPAddress | Select-Object IPAddress,InterfaceAlias,AddressFamily}
@{os=$os;apps=@($apps);hotfixes=@($hotfixes);processes=@($processes);listeners=@($listeners);addresses=@($addresses);errors=@($errors)} | ConvertTo-Json -Depth 6 -Compress
'''


def windows_host(result,options):
    exe=shutil.which('powershell.exe') or shutil.which('pwsh')
    if not exe:cov(result,'windows','unavailable','PowerShell unavailable');return []
    if platform.system()=='Windows' and not _trusted_tool(exe):cov(result,'windows','skipped','PowerShell executable is outside trusted system directories');return []
    data,status=run([exe,'-NoLogo','-NoProfile','-NonInteractive','-Command',WINDOWS_SCRIPT],options)
    if status!='ok':cov(result,'windows','error',status);return []
    try:doc=json.loads(data.lstrip('\ufeff'))
    except ValueError:cov(result,'windows','error','PowerShell did not return valid structured JSON');return []
    osv=doc.get('os') or {}
    if isinstance(osv,list):osv=osv[0] if osv else {}
    result['host'].update({'id':'windows','name':osv.get('Caption'),'version':osv.get('Version'),'build':osv.get('BuildNumber'),'architecture':osv.get('OSArchitecture')})
    if osv.get('Version') and osv.get('Caption'):
        c=component(osv['Caption'],osv['Version'],None,'os','windows-os',metadata={'windows_os':True,'build':osv.get('BuildNumber'),'architecture':osv.get('OSArchitecture')})
        if c:c['id']='windows-os';c['collector']='windows-os';result['components'].append(c)
    for app in doc.get('apps',[]):
        if not isinstance(app,dict):continue
        c=component(app.get('DisplayName',''),app.get('DisplayVersion',''),None,'application','windows-registry',manager=None,metadata={'publisher':app.get('Publisher'),'registry_key':app.get('PSChildName')})
        if c:result['components'].append(c)
        else:cov(result,'windows-apps','partial','An installed app has no usable name/version')
    result['host']['hotfixes']=[x['HotFixID'] for x in doc.get('hotfixes',[]) if isinstance(x,dict) and x.get('HotFixID')]
    processes=[]; roots=[]
    for p in doc.get('processes',[])[:options.get('max_processes',4096)]:
        row={'pid':p.get('ProcessId'),'name':p.get('Name'),'executable':p.get('ExecutablePath')}
        processes.append(row)
        if p.get('ExecutablePath'):roots.append(str(Path(p['ExecutablePath']).parent))
    result['processes']=processes
    for row in doc.get('listeners',[]):
        result['network']['listeners'].append({'protocol':row.get('Protocol','tcp'),'address':row.get('LocalAddress'),'port':row.get('LocalPort'),'pids':[row.get('OwningProcess')]})
    for row in doc.get('addresses',[]):
        result['network']['addresses'].append({'address':row.get('IPAddress'),'interface':row.get('InterfaceAlias'),'family':row.get('AddressFamily')})
        if re.search(r'tunnel|tailscale|wireguard|vpn',row.get('InterfaceAlias',''),re.I):result['network']['tunnels'].append({'interface':row['InterfaceAlias'],'evidence':'interface name only; reachability unknown'})
    errors=doc.get('errors',[])
    for section in ('os','apps','hotfixes','processes','listeners','addresses'):
        cov(result,'windows-'+section,'partial' if section in errors else 'ok','Native structured query failed or was denied' if section in errors else 'Native structured query completed; visible scope only')
    cov(result,'windows-process-cwd','unavailable','Process cwd is not exposed by the read-only CIM query; protected process executable paths may be absent')
    if len(doc.get('processes',[]))>len(processes):cov(result,'windows-processes','partial',f'Process limit reached: max_processes={options.get("max_processes",4096)}')
    runtimes(result,options);python_metadata(result,options)
    return sorted(set(roots))


CONTAINER_FORMAT='{"Id":{{json .Id}},"Name":{{json .Name}},"Image":{{json .Image}},"ConfigImage":{{json .Config.Image}},"State":{{json .State.Status}},"Pid":{{json .State.Pid}},"Ports":{{json .NetworkSettings.Ports}},"Mounts":{{json .Mounts}}}'
IMAGE_FORMAT='{"Id":{{json .Id}},"RepoTags":{{json .RepoTags}},"RepoDigests":{{json .RepoDigests}},"Os":{{json .Os}},"Architecture":{{json .Architecture}}}'


def collect_docker(result,options):
    exe=shutil.which('docker')
    if not exe:cov(result,'docker','unavailable','Docker CLI unavailable; containers/images not inventoried');return
    if not _trusted_tool(exe):cov(result,'docker','skipped','Docker executable is outside trusted system tool directories');return
    image_ids=set(); max_items=options.get('max_containers',256)
    for kind in ('container','image'):
        data,status=run([exe,kind,'ls','--all','--quiet','--no-trunc'],options)
        if status!='ok':cov(result,'docker-'+kind,'error',status);continue
        ids=sorted(set(data.splitlines()))
        valid=[x for x in ids if re.fullmatch(r'(?:sha256:)?[a-fA-F0-9]{12,64}',x)]
        if len(valid)!=len(ids):cov(result,'docker-'+kind,'partial','Unexpected identifiers omitted')
        if len(valid)>max_items:cov(result,'docker-'+kind,'partial',f'Item limit reached: max_containers={max_items}')
        count=0
        for ident in valid[:max_items]:
            data,status=run([exe,kind,'inspect','--format',CONTAINER_FORMAT if kind=='container' else IMAGE_FORMAT,ident],options)
            if status!='ok':cov(result,'docker-'+kind,'partial',f'Inspect failed: {status}');continue
            try:doc=json.loads(data)
            except ValueError:cov(result,'docker-'+kind,'partial','Invalid selected-field inspect JSON');continue
            count+=1
            if kind=='container':
                mounts=[{'type':m.get('Type'),'source':m.get('Source'),'destination':m.get('Destination'),'read_write':m.get('RW')} for m in doc.get('Mounts') or [] if isinstance(m,dict)]
                result['containers'].append({'id':doc.get('Id'),'name':doc.get('Name'),'image_id':doc.get('Image'),'image_reference':doc.get('ConfigImage'),'state':doc.get('State'),'pid':doc.get('Pid'),'ports':doc.get('Ports') or {},'mounts':mounts})
                if re.fullmatch(r'(?:sha256:)?[a-fA-F0-9]{12,64}',doc.get('Image','')):image_ids.add(doc['Image'])
            else:
                image_ids.add(ident)
                c=component(doc.get('Id',ident),doc.get('Id',ident),None,'container-image','docker',identity=doc.get('Id',ident),metadata={'tags':doc.get('RepoTags') or [],'digests':doc.get('RepoDigests') or [],'os':doc.get('Os'),'architecture':doc.get('Architecture')})
                if c:result['components'].append(c)
        cov(result,'docker-'+kind,'ok' if count==len(ids) else 'partial',f'{count} locally visible {kind} records; running/stopped containers and local images queried; no pulls/exec/create')
    syft=shutil.which('syft') if options.get('enable_syft',True) else None
    if syft and not _trusted_tool(syft):syft=None
    if not syft:
        cov(result,'syft','partial','Syft unavailable or disabled; image metadata is not an installed package SBOM and container package coverage is incomplete');return
    if not image_ids:cov(result,'syft','skipped','No visible local image IDs to scan');return
    for ident in sorted(image_ids)[:max_items]:
        # docker: forces daemon-only reads: never resolve/pull a registry image.
        data,status=run([syft,'scan','docker:'+ident,'-o','syft-json','--quiet'],options)
        if status!='ok':cov(result,'syft','partial',f'Local image SBOM unavailable: {status}');continue
        try:
            doc=json.loads(data)
            components,skipped=parse_sbom(doc,'docker:'+ident,'syft',ident)
            distro=doc.get('distro') or {}
            for c in components:
                c['metadata'].update({'distribution':distro.get('id'),'distribution_version':distro.get('versionID')})
            result['components'].extend(components)
            cov(result,'syft','partial' if skipped else 'ok',f'{ident}: {len(components)} image package coordinates; {skipped} omitted; running container writable layers/mounts are outside image SBOM')
        except (ValueError,TypeError,AttributeError):cov(result,'syft','partial','Invalid or incomplete local image SBOM')
    cov(result,'container-runtime-filesystem','partial','Image scans exclude running writable layers, mounted application data and alternate namespaces; no container exec performed')
