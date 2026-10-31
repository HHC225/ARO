import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'skills/aro/scripts'))
from aro_core import inventory_host as host

# Command fixtures isolate trust lookup: fake executable paths must not resolve
# through the runner's real filesystem. CollectorSecurityTests retains real checks.
class HostTests(unittest.TestCase):
    def result(self):return {'host':{},'components':[],'containers':[],'network':{'listeners':[],'addresses':[],'tunnels':[]},'coverage':[]}
    def options(self):return {'command_timeout':1,'max_command_bytes':1000000,'max_processes':100,'max_containers':100,'enable_syft':True}
    def test_command_timeout_and_limit_do_not_expose_output(self):
        output,status=host.run([sys.executable,'-c','print("secret"*100)'],{'command_timeout':2,'max_command_bytes':10})
        self.assertEqual(output,'');self.assertEqual(status,'output limit exceeded')
        output,status=host.run([sys.executable,'-c','import time;time.sleep(5)'],{'command_timeout':1,'max_command_bytes':10})
        self.assertEqual(output,'');self.assertIn('timeout',status)
    def test_docker_selected_fields_and_explicit_deep_coverage(self):
        calls=[]
        def command(argv,opts):
            calls.append(argv)
            if argv[1:3]==['container','ls']:return 'a'*64+'\n','ok'
            if argv[1:3]==['image','ls']:return 'sha256:'+'b'*64+'\n','ok'
            if argv[1:3]==['container','inspect']:
                return json.dumps({'Id':'a'*64,'Name':'/web','Image':'sha256:'+'b'*64,'ConfigImage':'web:1','State':'running','Pid':42,'Ports':{'80/tcp':[{'HostIp':'0.0.0.0','HostPort':'8080'}]},'Mounts':[]})+'\n','ok'
            if argv[1:3]==['image','inspect']:return json.dumps({'Id':'sha256:'+'b'*64,'RepoTags':['web:1'],'RepoDigests':[],'Os':'linux','Architecture':'amd64'})+'\n','ok'
            raise AssertionError(argv)
        result=self.result()
        with patch.object(host,'run',side_effect=command),patch.object(host.shutil,'which',side_effect=lambda x:'/usr/bin/docker' if x=='docker' else None),patch.object(host,'_trusted_tool',side_effect=lambda executable:executable=='/usr/bin/docker'):host.collect_docker(result,self.options())
        self.assertIn(['/usr/bin/docker','container','ls','--all','--quiet','--no-trunc'],calls)
        self.assertIn(['/usr/bin/docker','image','ls','--all','--quiet','--no-trunc'],calls)
        self.assertEqual(result['containers'][0]['state'],'running')
        self.assertEqual(result['containers'][0]['ports']['80/tcp'][0]['HostPort'],'8080')
        self.assertTrue(any(c['collector']=='syft' and c['status']=='partial' for c in result['coverage']))
        self.assertFalse(any('exec' in x or 'pull' in x or 'create' in x for a in calls for x in a))
        self.assertFalse(any('Env' in x or 'Cmd' in x for a in calls for x in a))
    def test_linux_dpkg_versions_and_manager_metadata(self):
        result=self.result()
        with patch.object(host,'run',return_value=('bash\t5.2-2\tamd64\tinstall ok installed\n','ok')) as command,patch.object(host.shutil,'which',side_effect=lambda x:'/usr/bin/dpkg-query' if x=='dpkg-query' else None),patch.object(host,'_trusted_tool',side_effect=lambda executable:executable=='/usr/bin/dpkg-query'):
            host.linux_packages(result,self.options())
        command.assert_called_once_with(['/usr/bin/dpkg-query','-W','-f=${Package}\t${Version}\t${Architecture}\t${Status}\t${source:Package}\t${source:Version}\n'],self.options())
        self.assertEqual(result['components'][0]['version'],'5.2-2')
        self.assertEqual(result['components'][0]['manager'],'apt')
        self.assertEqual(result['components'][0]['metadata']['architecture'],'amd64')
    def test_windows_structured_inventory_no_environment_or_commands(self):
        result=self.result(); calls=[]
        doc={'os':{'Caption':'Windows','Version':'10.0','BuildNumber':'26100','OSArchitecture':'64-bit'},'apps':[{'DisplayName':'App','DisplayVersion':'1.2','Publisher':'Vendor','PSChildName':'App'}],'hotfixes':[{'HotFixID':'KB123'}],'processes':[{'ProcessId':12,'Name':'app','ExecutablePath':'C:\\app.exe'}],'listeners':[{'LocalAddress':'::','LocalPort':443,'OwningProcess':12}],'addresses':[]}
        with patch.object(host,'run',side_effect=lambda argv,opts:(calls.append(argv) or json.dumps(doc),'ok')),patch.object(host.shutil,'which',side_effect=lambda x:'powershell.exe' if x=='powershell.exe' else None),patch.object(host,'_trusted_tool',side_effect=lambda executable:executable=='powershell.exe'),patch.object(host,'runtimes'),patch.object(host,'python_metadata'):
            host.windows_host(result,self.options())
        self.assertEqual(result['host']['build'],'26100')
        self.assertTrue(any(c['name']=='App' for c in result['components']))
        self.assertEqual(calls[0][:-1],['powershell.exe','-NoLogo','-NoProfile','-NonInteractive','-Command'])
        script=calls[0][-1]
        self.assertNotIn('CommandLine',script);self.assertNotIn('Environment',script)
        self.assertEqual(result['network']['listeners'][0]['port'],443)

if __name__=='__main__':unittest.main()

class CollectorSecurityTests(unittest.TestCase):
    def test_runtime_does_not_execute_project_path_binary(self):
        result={'components':[],'coverage':[]};calls=[]
        def command(argv,opts):calls.append(argv);return 'Python 3.11.0','ok'
        with patch.object(host.shutil,'which',return_value='/workspace/untrusted/node'),patch.object(host,'run',side_effect=command):
            host.runtimes(result,{'command_timeout':1,'max_command_bytes':10000})
        self.assertTrue(all(argv[0]==sys.executable for argv in calls))
        self.assertTrue(any(c['status']=='skipped' for c in result['coverage']))

class RuntimeParsingTests(unittest.TestCase):
    def test_go_prerelease_and_all_dotnet_runtime_versions(self):
        result={'components':[],'coverage':[]};calls=[]
        def command(argv,opts):
            calls.append(argv)
            if argv[0]==sys.executable:return 'Python 3.14.0rc1','ok'
            if argv[0].endswith('/go'):return 'go version go1.23.1 linux/amd64','ok'
            if argv[0].endswith('/dotnet'):return 'Microsoft.NETCore.App 8.0.10 [/usr/lib/dotnet]\nMicrosoft.AspNetCore.App 9.0.0 [/usr/lib/dotnet]\n','ok'
            return '', 'command unavailable'
        with patch.object(host.shutil,'which',side_effect=lambda x:'/usr/bin/'+x if x in {'go','dotnet'} else None),patch.object(host,'run',side_effect=command),patch.object(host,'_trusted_tool',side_effect=lambda executable:executable in {'/usr/bin/go','/usr/bin/dotnet'}):host.runtimes(result,{})
        self.assertEqual(calls,[[sys.executable,'--version'],['/usr/bin/go','version'],['/usr/bin/dotnet','--list-runtimes']])
        self.assertEqual(next(c['version'] for c in result['components'] if c['name']=='python'),'3.14.0rc1')
        self.assertEqual(next(c['version'] for c in result['components'] if c['name']=='go'),'1.23.1')
        self.assertEqual({c['version'] for c in result['components'] if c['name']=='dotnet'},{'8.0.10','9.0.0'})
    def test_rpm_apk_and_pacman_inventory(self):
        for tool,data,name,version in [('rpm','openssl\t1:3.0.0-1\tx86_64\n','openssl','1:3.0.0-1'),('apk','ca-certificates-bundle-20241010-r0\n','ca-certificates-bundle','20241010-r0'),('pacman','openssl 3.3.0-1\n','openssl','3.3.0-1')]:
            with self.subTest(tool=tool):
                result={'host':{'id':'test','version':'1'},'components':[],'coverage':[]}
                with patch.object(host.shutil,'which',side_effect=lambda x:'/usr/bin/'+tool if x==tool else None),patch.object(host,'run',return_value=(data,'ok')) as command,patch.object(host,'_trusted_tool',side_effect=lambda executable:executable=='/usr/bin/'+tool):host.linux_packages(result,{})
                query={'rpm':['-qa','--qf','%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{ARCH}\n'],'apk':['info','-v'],'pacman':['-Q']}[tool]
                command.assert_called_once_with(['/usr/bin/'+tool,*query],{})
                self.assertEqual(result['components'][0]['name'],name)
                self.assertEqual(result['components'][0]['version'],version)

class NativeIdentityTests(unittest.TestCase):
    def test_dpkg_source_package_and_version_are_separate(self):
        result={'host':{'id':'ubuntu','version':'24.04'},'components':[],'coverage':[]}
        with patch.object(host.shutil,'which',side_effect=lambda x:'/usr/bin/dpkg-query' if x=='dpkg-query' else None),patch.object(host,'run',return_value=('libssl3t64\t3.0.13-0ubuntu3.4\tamd64\tinstall ok installed\topenssl\t3.0.13-0ubuntu3.4\n','ok')),patch.object(host,'_trusted_tool',side_effect=lambda executable:executable=='/usr/bin/dpkg-query'):host.linux_packages(result,{})
        self.assertEqual(result['components'][0]['metadata']['source_package'],'openssl')
        self.assertEqual(result['components'][0]['metadata']['source_version'],'3.0.13-0ubuntu3.4')
    def test_windows_os_component_identity(self):
        result={'host':{},'components':[],'network':{'listeners':[],'addresses':[],'tunnels':[]},'coverage':[]}
        data={'os':{'Caption':'Microsoft Windows 11 Pro','Version':'10.0.26100','BuildNumber':'26100','OSArchitecture':'64-bit'}}
        with patch.object(host.shutil,'which',side_effect=lambda x:'powershell.exe' if x=='powershell.exe' else None),patch.object(host,'run',return_value=(json.dumps(data),'ok')),patch.object(host,'_trusted_tool',side_effect=lambda executable:executable=='powershell.exe'),patch.object(host,'runtimes'),patch.object(host,'python_metadata'):host.windows_host(result,{})
        os_component=next(c for c in result['components'] if c['kind']=='os')
        self.assertEqual(os_component['id'],'windows-os')
        self.assertEqual(os_component['metadata']['build'],'26100')

class PythonEnvironmentIdentityTests(unittest.TestCase):
    def test_active_venv_interpreter_retains_lexical_path_and_prefix(self):
        import tempfile
        from importlib.metadata import PathDistribution
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'bin').mkdir();exe=root/'bin'/'python';exe.symlink_to(sys.executable)
            info=root/'lib'/'site-packages'/'foo-1.dist-info';info.mkdir(parents=True);(info/'METADATA').write_text('Name: foo\nVersion: 1\n')
            result={'components':[],'coverage':[]}
            with patch('importlib.metadata.distributions',return_value=[PathDistribution(info)]),patch.object(host.sys,'executable',str(exe)),patch.object(host.sys,'prefix',str(root)):
                host.python_metadata(result,{})
            self.assertEqual(result['components'][0]['metadata']['interpreter'],str(exe))
            self.assertEqual(result['components'][0]['metadata']['environment_prefix'],str(root))

class RuntimeAbsenceTests(unittest.TestCase):
    def test_uninstalled_runtime_is_not_a_collection_failure(self):
        result={'components':[],'coverage':[]}
        with patch.object(host.shutil,'which',return_value=None),patch.object(host,'run',return_value=('Python 3.11.0','ok')):host.runtimes(result,{})
        row=next(c for c in result['coverage'] if c['collector']=='runtime-node')
        self.assertEqual(row['status'],'ok');self.assertEqual(row['applicability'],'not_applicable')
