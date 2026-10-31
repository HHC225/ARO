import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'skills/aro/scripts'))
from aro_core import inventory

class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
    def tearDown(self): self.tmp.cleanup()
    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value if isinstance(value, str) else json.dumps(value))
        return path
    def scan(self):
        return inventory.collect_inventory([str(self.root)], {'host':False, 'docker':False, 'discover_services':False})
    def test_npm_v2_nested_stable_ids_and_no_script_execution(self):
        self.write('package-lock.json', {'lockfileVersion':2, 'packages': {'': {'name':'app'}, 'node_modules/foo': {'name':'foo','version':'1.2.3'}, 'node_modules/foo/node_modules/bar':{'version':'2.0'}}})
        self.write('package.json', {'scripts':{'preinstall':'touch PWNED'}})
        first = self.scan()
        self.assertEqual({c['name'] for c in first['components']}, {'foo','bar'})
        old_id = next(c['id'] for c in first['components'] if c['name']=='foo')
        self.write('package-lock.json', {'lockfileVersion':3,'packages':{'node_modules/foo':{'version':'2.0'}}})
        self.assertEqual(old_id, self.scan()['components'][0]['id'])
        self.assertFalse((self.root/'PWNED').exists())
    def test_npm_v1_and_unresolved_manifest(self):
        self.write('package-lock.json', {'lockfileVersion':1,'dependencies':{'foo':{'version':'1.0','dependencies':{'bar':{'version':'2.0'}}}}})
        self.write('other/package.json', {'dependencies':{'unresolved':'^3'}})
        result=self.scan()
        self.assertEqual(len(result['components']),2)
        self.assertTrue(any(c['status']=='partial' and 'package.json' in c['detail'] for c in result['coverage']))
    def test_lockfile_coordinates(self):
        self.write('requirements.txt', 'foo==1.2.3\nbar>=2\nsecret @ https://user:password@example.com/pkg\n')
        self.write('Pipfile.lock', {'default':{'baz':{'version':'==3.0'}}})
        self.write('poetry.lock', '[[package]]\nname="poet"\nversion="4.0"\n')
        self.write('uv.lock', '[[package]]\nname="uvpkg"\nversion="5.0"\nsource={registry="https://example.org"}\n')
        self.write('Cargo.lock', '[[package]]\nname="crate"\nversion="1.0"\nsource="registry+https://github.com/rust-lang/crates.io-index"\n')
        self.write('go.mod', 'module example.com/app\nrequire (\n example.com/mod v1.2.0\n)\n')
        self.write('go.sum', 'example.com/trans v2.0.0 h1:test\n')
        self.write('composer.lock', {'packages':[{'name':'vendor/pkg','version':'v1.0'}]})
        self.write('Gemfile.lock', 'GEM\n  specs:\n    rack (3.0.0)\n\nPLATFORMS\n  ruby\n')
        self.write('packages.lock.json', {'dependencies':{'net8.0':{'Newtonsoft.Json':{'type':'Direct','resolved':'13.0.3'}}}})
        result=self.scan()
        names={c['name'] for c in result['components']}
        self.assertTrue({'foo','baz','poet','uvpkg','crate','example.com/mod','example.com/trans','vendor/pkg','rack','Newtonsoft.Json'} <= names, names)
        self.assertFalse(next(c for c in result['components'] if c['name']=='uvpkg')['metadata']['selected'])
        self.assertNotIn('password',json.dumps(result))
        self.assertTrue(any(c['status']=='partial' for c in result['coverage']))
    def test_symlinks_secrets_generated_dirs_and_bounds(self):
        self.write('.env','password=secret')
        self.write('node_modules/deep/package-lock.json',{'dependencies':{'hidden':{'version':'1'}}})
        outside=self.root/'outside'; outside.mkdir(); (outside/'requirements.txt').write_text('linked==1')
        os.symlink(outside,self.root/'linked')
        result=self.scan()
        self.assertEqual([c['name'] for c in result['components']],['linked'])
        self.assertTrue(any('skipped' in c['detail'] for c in result['coverage']))
        bounded=inventory.collect_inventory([str(self.root)],{'host':False,'docker':False,'discover_services':False,'max_files':1})
        self.assertTrue(any(c['status']=='partial' for c in bounded['coverage']))
    def test_installed_metadata_without_import(self):
        self.write('.venv/lib/python3.11/site-packages/foo-1.dist-info/METADATA','Name: installed-foo\nVersion: 1.2\n')
        self.write('.venv/lib/python3.11/site-packages/evil.py','raise Exception("must not import")')
        result=self.scan()
        self.assertIn('installed-foo',{c['name'] for c in result['components']})
    def test_failed_collectors_visible(self):
        with patch.object(inventory,'collect_host',side_effect=PermissionError('private-secret')):
            result=inventory.collect_inventory([str(self.root)],{'docker':False,'discover_services':False})
        self.assertTrue(any(c['collector']=='host' and c['status']=='error' for c in result['coverage']))
        self.assertNotIn('private-secret',json.dumps(result))

if __name__=='__main__': unittest.main()

class InventoryProvenanceTests(unittest.TestCase):
    def test_components_have_collector_and_pinned_package_versions_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'package-lock.json').write_text(json.dumps({'lockfileVersion':3,'packages':{'node_modules/foo':{'version':'^1.0'},'node_modules/bar':{'version':'1.0'}}}))
            result=inventory.collect_inventory([directory],{'host':False,'docker':False,'discover_services':False})
            self.assertEqual([c['name'] for c in result['components']],['bar'])
            self.assertEqual(result['components'][0]['collector'],'lockfile')
            self.assertTrue(any(c.get('scope') and Path(c['scope']).resolve()==(root/'package-lock.json').resolve() and c['status']=='partial' for c in result['coverage']))
    def test_root_ancestor_symlink_is_not_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'real'/'sub').mkdir(parents=True)
            (root/'real'/'sub'/'requirements.txt').write_text('foo==1.0')
            os.symlink(root/'real',root/'alias')
            result=inventory.collect_inventory([str(root/'alias'/'sub')],{'host':False,'docker':False,'discover_services':False})
            self.assertEqual(result['components'],[])
            self.assertTrue(any(c['status']=='skipped' for c in result['coverage']))

class InventorySbomTests(unittest.TestCase):
    def test_local_syft_sbom_import_without_external_tools(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'sbom.json'
            path.write_text(json.dumps({'artifacts':[{'name':'foo','version':'1.2','type':'npm','locations':[{'path':'/app/node_modules/foo/package.json'}]}]}))
            result=inventory.collect_inventory([directory],{'host':False,'docker':False,'discover_services':False,'sbom_files':[str(path)]})
            self.assertEqual(len(result['components']),1)
            self.assertEqual(result['components'][0]['name'],'foo')
            self.assertEqual(result['components'][0]['source'],'local-sbom')
            self.assertTrue(any(c['collector']=='local-sbom' and c['status']=='partial' for c in result['coverage']))
    def test_secret_scope_is_not_scanned_even_if_explicit_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/'.ssh';root.mkdir();(root/'requirements.txt').write_text('foo==1')
            result=inventory.collect_inventory([str(root)],{'host':False,'docker':False,'discover_services':False})
            self.assertEqual(result['components'],[])

class InventoryScopeTests(unittest.TestCase):
    def test_aro_state_directory_is_excluded_and_does_not_change_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);state=root/'aro-state';state.mkdir()
            (state/'package-lock.json').write_text(json.dumps({'dependencies':{'cache-package':{'version':'1'}}}))
            opts={'host':False,'docker':False,'discover_services':False,'state_dir':str(state)}
            first=inventory.collect_inventory([directory],opts)
            (state/'nested').mkdir();(state/'nested'/'requirements.txt').write_text('cache==1')
            second=inventory.collect_inventory([directory],opts)
            self.assertEqual(first['components'],[]);self.assertEqual(second['components'],[])
            self.assertEqual(first['projects'],second['projects'])
            self.assertEqual(first['coverage'],second['coverage'])
    def test_general_scope_limitations_are_information_not_failed_collection(self):
        with tempfile.TemporaryDirectory() as directory:
            result=inventory.collect_inventory([directory],{'host':False,'docker':False,'discover_services':False})
        self.assertEqual(next(c for c in result['coverage'] if c['collector']=='scope')['status'],'ok')
