import copy
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'skills/aro/scripts'))
from aro_core.advisory_windows import query_windows_updates

GUID='12345678-1234-4234-8234-123456789abc'
SECURITY='0fa1201d-4330-4fa8-8ae9-b877473b6441'
def inventory():
    return {'host':{'os':'windows','id':'windows','version':'10.0.26100','build':'26100','hotfixes':['KB111']},'components':[{'id':'windows-os','name':'Microsoft Windows 11 Pro','version':'10.0.26100','kind':'os','metadata':{'windows_os':True}}]}
def update(**kw):
    value={'update_id':GUID,'revision':2,'title':'Security update for Microsoft Windows (KB1234567)','kb_article_ids':['1234567'],'msrc_severity':'Important','categories':[{'id':SECURITY,'name':'Sicherheitsupdates','type':'UpdateClassification'},{'id':'product','name':'Windows 11','type':'Product'}],'support_url':'https://support.microsoft.com/help/1234567','security_bulletin_ids':['MS26-001'],'cve_ids':[],'reboot_required':False,'eula_accepted':False,'type':1,'is_installed':False,'is_hidden':False}
    value.update(kw);return value
class WindowsUpdateTests(unittest.TestCase):
    def query(self,updates=None,inv=None,**options):
        self.calls=[]
        doc=options.pop('document',{'result_code':2,'updates':updates if updates is not None else [update()],'total_updates':len(updates) if updates is not None else 1,'warnings':[]})
        def runner(argv,settings):self.calls.append((argv,settings));return json.dumps(doc),'ok'
        return query_windows_updates(inv or inventory(),dict(options,windows_runner=runner))
    def test_applicable_security_update_normalizes_vendor_evidence_and_kb_fix(self):
        result=self.query();ad=result['advisories'][0]
        self.assertEqual(ad['component_id'],'windows-os');self.assertEqual(ad['match_confidence'],'vendor_applicability')
        self.assertEqual(ad['severity'],'HIGH');self.assertEqual(ad['fixed_versions'],['KB1234567'])
        self.assertEqual(ad['metadata']['fix_type'],'windows_update');self.assertEqual(ad['metadata']['update_id'],GUID)
        self.assertEqual(ad['metadata']['revision'],2);self.assertEqual(ad['aliases'],['MS26-001'])
        self.assertFalse(any(x.startswith('CVE-') for x in ad['aliases']))
        self.assertIsNone(ad['cvss_score']);self.assertEqual(ad['attack_vector'],'unknown')
        self.assertFalse(ad['known_exploited'])
    def test_non_windows_never_runs(self):
        calls=[]
        result=query_windows_updates({'host':{'os':'linux'}},{'windows_runner':lambda *args:calls.append(args)})
        self.assertEqual(calls,[]);self.assertEqual(result['advisories'],[])
        self.assertEqual(result['coverage'][0]['status'],'skipped')
    def test_fixed_script_does_not_interpolate_inventory_or_install(self):
        inv=inventory();inv['host']['name']='$(touch PRIVATE)';result=self.query(inv=inv)
        script=self.calls[0][0][-1]
        self.assertIn("IsInstalled=0 and IsHidden=0 and Type='Software'",script)
        self.assertIn('CanAutomaticallyUpgradeService = $false',script)
        for text in ['CreateUpdateInstaller','CreateUpdateDownloader','AcceptEula','PRIVATE','Install()','Download()']:self.assertNotIn(text,script)
        self.assertIn('-NoProfile',self.calls[0][0]);self.assertIn('-NonInteractive',self.calls[0][0])
    def test_offline_reads_cached_metadata_and_marks_freshness_unknown(self):
        result=self.query(offline=True)
        self.assertIn('Online = $false',self.calls[0][0][-1]);self.assertEqual(result['sources'][0]['freshness'],'unknown')
        self.assertTrue(any('cached' in x['detail'].lower() for x in result['coverage']))
    def test_nonsecurity_critical_feature_and_drivers_excluded(self):
        result=self.query([update(msrc_severity='',security_bulletin_ids=[],categories=[{'id':'critical','name':'Critical Updates'}]),update(type=2),update(msrc_severity='',security_bulletin_ids=[],categories=[{'id':'upgrade','name':'Upgrades'}])])
        self.assertEqual(result['advisories'],[])
    def test_security_update_can_be_classified_by_real_cve_and_localized_category(self):
        result=self.query([update(msrc_severity='',security_bulletin_ids=[],categories=[],cve_ids=['CVE-2026-12345','injected text'])])
        self.assertEqual(result['advisories'][0]['aliases'],['CVE-2026-12345'])
    def test_missing_os_identity_does_not_invent_component(self):
        inv=inventory();inv['components']=[]
        result=self.query(inv=inv)
        self.assertEqual(result['advisories'],[])
        self.assertTrue(any('identity' in x['detail'].lower() for x in result['coverage']))
    def test_invalid_guid_revision_or_unsafe_url_are_not_commands(self):
        result=self.query([update(update_id="x'; Install()",revision=2),update(revision=-1),update(support_url='https://user:secret@evil.example/path')])
        self.assertEqual(len(result['advisories']),1);self.assertNotIn('secret',json.dumps(result))
        self.assertEqual(result['advisories'][0]['source_url'],'https://support.microsoft.com/help/1234567')
    def test_partial_results_and_output_truncation_are_visible(self):
        result=self.query(document={'result_code':3,'updates':[update()],'total_updates':101,'warnings':[{'hresult':-1}]},max_windows_updates=1)
        self.assertEqual(len(result['advisories']),1)
        self.assertTrue(any(x['status']=='partial' for x in result['coverage']))
    def test_error_permission_and_timeout_are_not_clean(self):
        result=self.query(document={'error_code':-2147024891})
        self.assertEqual(result['advisories'],[]);self.assertEqual(result['sources'][0]['status'],'error')
        result=query_windows_updates(inventory(),{'windows_runner':lambda *a:('','timeout after 1s')})
        self.assertEqual(result['advisories'],[]);self.assertTrue(any(x['status']=='error' for x in result['coverage']))
    def test_malformed_document_is_error(self):
        result=self.query(document=['wrong'])
        self.assertEqual(result['advisories'],[]);self.assertEqual(result['sources'][0]['status'],'error')
    def test_already_installed_or_hidden_record_is_rejected(self):
        result=self.query([update(is_installed=True),update(is_hidden=True)])
        self.assertEqual(result['advisories'],[])

if __name__=='__main__':unittest.main()

@unittest.skipUnless(sys.platform=='win32','Native WUA requires Windows')
class WindowsUpdateNativeSmoke(unittest.TestCase):
    def test_native_cached_search_when_service_is_available(self):
        import shutil
        import subprocess
        exe=shutil.which('powershell.exe')
        if not exe:self.skipTest('Windows PowerShell unavailable')
        service=subprocess.run([exe,'-NoProfile','-NonInteractive','-Command',"$s=Get-Service wuauserv -ErrorAction SilentlyContinue; if ($null -eq $s -or $s.StartType -eq 'Disabled') { exit 3 }; exit 0"],capture_output=True,timeout=8,check=False)
        if service.returncode:self.skipTest('Windows Update service unavailable or disabled')
        native=inventory();native['host']['version']=str(sys.getwindowsversion().major)+'.'+str(sys.getwindowsversion().minor)
        native['host']['build']=str(sys.getwindowsversion().build)
        result=query_windows_updates(native,{'offline':True,'windows_update_timeout':8,'max_windows_updates':5})
        self.assertTrue(result['sources']);self.assertTrue(result['coverage'])
        self.assertTrue(all(x['match_confidence']=='vendor_applicability' for x in result['advisories']))
        self.assertTrue(any('cached' in x['detail'].lower() or 'timeout' in x['detail'].lower() or x['status']=='error' for x in result['coverage']))
