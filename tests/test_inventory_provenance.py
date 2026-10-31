import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'skills/aro/scripts'))
from aro_core.inventory import collect_inventory
from aro_core.inventory_parsers import parse_lock

class ProvenanceTests(unittest.TestCase):
    def parse(self,name,data):
        return parse_lock(Path('/project')/name,data if isinstance(data,str) else json.dumps(data))
    def test_npm_all_lock_versions_keep_nonpublic_numeric_versions_without_secret_urls(self):
        for version in (1,2,3):
            with self.subTest(version=version):
                deps={'public':{'version':'1.0','resolved':'https://registry.npmjs.org/public/-/public-1.0.tgz'},'private':{'version':'1.0','resolved':'https://user:SECRET@registry.example.com/private.tgz'},'git':{'version':'1.0','resolved':'git+https://user:SECRET@example.com/repo.git'},'file':{'version':'1.0','resolved':'file:../local'},'link':{'version':'1.0','link':True},'unknown':{'version':'1.0'}}
                doc={'lockfileVersion':version, 'dependencies':deps} if version==1 else {'lockfileVersion':version,'packages':{'node_modules/'+k:v for k,v in deps.items()}}
                components,warnings=self.parse('package-lock.json',doc)
                byname={c['name']:c for c in components}
                self.assertEqual(set(byname),set(deps))
                for name in ('private','git','file','link'):
                    self.assertIs(byname[name]['metadata']['selected'],False)
                    self.assertTrue(byname[name]['metadata']['provenance_reason'])
                    self.assertEqual(byname[name]['version'],'1.0')
                self.assertIsNot(byname['public'].get('metadata',{}).get('selected'),False)
                self.assertIsNot(byname['unknown'].get('metadata',{}).get('selected'),False)
                self.assertNotIn('SECRET',json.dumps([components,warnings]));self.assertTrue(warnings)
    def test_cargo_alternate_registry_and_vcs_are_visible_but_not_public_matches(self):
        components,warnings=self.parse('Cargo.lock','[[package]]\nname="public"\nversion="1.0"\nsource="registry+https://github.com/rust-lang/crates.io-index"\n[[package]]\nname="private"\nversion="2.0"\nsource="registry+https://user:SECRET@example.com/index"\n[[package]]\nname="local"\nversion="3.0"\n')
        byname={c['name']:c for c in components}
        self.assertEqual(set(byname),{'public','private','local'})
        self.assertFalse(byname['private']['metadata']['selected']);self.assertFalse(byname['local']['metadata']['selected'])
        self.assertNotIn('SECRET',json.dumps([components,warnings]))
    def test_python_lock_registry_provenance(self):
        for filename,text in [('uv.lock','[[package]]\nname="private"\nversion="1.0"\nsource={registry="https://user:SECRET@example.com/simple"}\n[[package]]\nname="public"\nversion="2.0"\nsource={registry="https://pypi.org/simple"}\n'),('poetry.lock','[[package]]\nname="private"\nversion="1.0"\n[package.source]\ntype="legacy"\nurl="https://user:SECRET@example.com/simple"\n[[package]]\nname="public"\nversion="2.0"\n')]:
            components,warnings=self.parse(filename,text);byname={c['name']:c for c in components}
            self.assertFalse(byname['private']['metadata']['selected']);self.assertIsNot(byname['public'].get('metadata',{}).get('selected'),False)
            self.assertNotIn('SECRET',json.dumps([components,warnings]))
    def test_requirements_custom_index_affects_pins_before_and_after_option(self):
        components,warnings=self.parse('requirements.txt','foo==1.0\n--extra-index-url https://user:SECRET@example.com/simple\nbar==2.0\n')
        self.assertEqual(len(components),2);self.assertTrue(all(c['metadata']['selected'] is False for c in components))
        self.assertNotIn('SECRET',json.dumps([components,warnings]))
    def test_installed_python_direct_url_is_metadata_only_and_unverified(self):
        with tempfile.TemporaryDirectory() as directory:
            info=Path(directory)/'.venv/lib/python3.11/site-packages/foo-1.dist-info';info.mkdir(parents=True)
            (info/'METADATA').write_text('Name: foo\nVersion: 1\n')
            (info/'direct_url.json').write_text(json.dumps({'url':'https://user:SECRET@example.com/repo','vcs_info':{'vcs':'git','commit_id':'abc'}}))
            result=collect_inventory([directory],{'host':False,'docker':False,'discover_services':False})
            self.assertFalse(result['components'][0]['metadata']['selected']);self.assertIn('direct',result['components'][0]['metadata']['provenance_reason'])
            self.assertNotIn('SECRET',json.dumps(result));self.assertTrue(any(c['collector']=='python-metadata' and c['status']=='partial' for c in result['coverage']))
    def test_active_python_direct_url_annotates_existing_component(self):
        with tempfile.TemporaryDirectory() as directory:
            info=Path(directory)/'foo-1.dist-info';info.mkdir()
            (info/'METADATA').write_text('Name: foo\nVersion: 1\n');(info/'direct_url.json').write_text('{"url":"file:///secret/source"}')
            def host(result,opts):
                result['components'].append({'id':'active','name':'foo','version':'1','ecosystem':'PyPI','kind':'package','source':'python-metadata','path':directory,'metadata':{'interpreter':sys.executable}})
                return []
            with patch('aro_core.inventory.collect_host',side_effect=host):result=collect_inventory([str(Path(directory)/'not-existing')],{'docker':False,'discover_services':False})
            self.assertFalse(result['components'][0]['metadata']['selected']);self.assertNotIn('/secret/source',json.dumps(result))

class JavaDiscoveryTests(unittest.TestCase):
    def test_maven_and_gradle_unresolved_without_executing_build(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for name in ('pom.xml','build.gradle','build.gradle.kts'):(root/name).write_text('untrusted arbitrary code')
            result=collect_inventory([directory],{'host':False,'docker':False,'discover_services':False})
            warnings=[c['detail'] for c in result['coverage'] if c['collector']=='manifest' and c['status']=='partial']
            self.assertTrue(all(any(name in w for w in warnings) for name in ('pom.xml','build.gradle','build.gradle.kts')))
    def test_gradle_current_and_legacy_lockfiles_exact_coordinates(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'build.gradle.kts').write_text('plugins {}')
            (root/'gradle.lockfile').write_text('# generated\norg.example:library:1.2.3=compileClasspath,runtimeClasspath\nempty=annotationProcessor\n')
            legacy=root/'gradle/dependency-locks';legacy.mkdir(parents=True);(legacy/'testCompileClasspath.lockfile').write_text('org.example:legacy:2.0\n')
            result=collect_inventory([directory],{'host':False,'docker':False,'discover_services':False})
            self.assertEqual({(c['name'],c['version'],c['ecosystem']) for c in result['components']},{('org.example:library','1.2.3','Maven'),('org.example:legacy','2.0','Maven')})
            self.assertTrue(all(c['manager']=='gradle' for c in result['components']))
