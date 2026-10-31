"""Observable advisory matching, privacy, freshness and safety regressions."""
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'skills/aro/scripts'))
from aro_core import advisories


def component(name='demo', version='1.2.0', ecosystem='npm', **extra):
    return dict(id=name + ':' + str(version), name=name, version=version, ecosystem=ecosystem,
                kind='package', source='lockfile', **extra)


def osv(identifier='TEST-1', name='demo', ecosystem='npm', **extra):
    return dict(id=identifier, aliases=['CVE-2024-1234'], summary='A real test issue',
                published='2024-01-01T00:00:00Z', modified='2024-02-01T00:00:00Z',
                affected=[dict(package=dict(name=name, ecosystem=ecosystem),
                               ranges=[dict(type='SEMVER', events=[{'introduced':'0'}, {'fixed':'1.3.0'},
                                                                  {'introduced':'2.0.0'}, {'fixed':'2.4.0'}])])], **extra)


def archive(files):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w:gz') as tar:
        for name, value in files.items():
            data = json.dumps(value).encode()
            item = tarfile.TarInfo('repo-main/' + name)
            item.size = len(data)
            tar.addfile(item, io.BytesIO(data))
    return out.getvalue()


class FakeHTTP:
    def __init__(self, records=None, batches=None, routes=None):
        self.records, self.batches, self.routes = records or {}, list(batches or []), routes or {}
        self.calls = []
    def __call__(self, method, url, payload=None, timeout=10):
        self.calls.append((method, url, payload))
        if url in self.routes:
            value = self.routes[url]
            if isinstance(value, Exception): raise value
            return value
        if url.endswith('/querybatch'):
            if self.batches: return self.batches.pop(0)
            return {'results':[{} for _ in payload['queries']]}
        if '/v1/vulns/' in url:
            value = self.records[url.rsplit('/',1)[1]]
            if isinstance(value, Exception): raise value
            return value
        if 'known_exploited' in url: return {'vulnerabilities': []}
        if '/security-advisories?' in url: return []
        raise RuntimeError('Unexpected URL ' + url)


class AdvisoryQueries(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cache = Path(self.tmp.name)
    def tearDown(self):
        if self.cache.is_file(): self.cache.unlink(); self.cache.mkdir()
        self.tmp.cleanup()
    def run_query(self, comps, http=None, **options):
        return advisories.query_advisories({'host':{'os':'linux','id':'ubuntu'},'components':comps},
             self.cache, dict(requester=http or FakeHTTP(), retries=0, **options))

    def test_exact_queries_keep_mixed_versions_and_ecosystems(self):
        http = FakeHTTP()
        self.run_query([component(), component(version='2.0.0'), component(ecosystem='PyPI')], http)
        queries = next(call[2]['queries'] for call in http.calls if call[1].endswith('querybatch'))
        self.assertEqual({(q['package']['ecosystem'],q['package']['name'],q['version']) for q in queries},
                         {('npm','demo','1.2.0'),('npm','demo','2.0.0'),('PyPI','demo','1.2.0')})

    def test_private_exclusions_and_host_paths_never_leave(self):
        http = FakeHTTP()
        self.run_query([component('@secret/api'),component('public',path='/secret/host/repo')], http,
                       exclude_packages=['@secret/*'])
        sent = json.dumps(http.calls)
        self.assertNotIn('@secret',sent)
        self.assertNotIn('/secret/host',sent)
        self.assertIn('public',sent)

    def test_unsupported_and_missing_versions_are_coverage_gaps(self):
        http = FakeHTTP()
        result = self.run_query([component(ecosystem='Mystery'), component(version=None)], http)
        self.assertFalse(any(c[1].endswith('querybatch') for c in http.calls))
        self.assertTrue(any(x['status'] in ('partial','unavailable') for x in result['coverage']))

    def test_pagination_full_records_and_fix_branches(self):
        http = FakeHTTP({'TEST-1':osv(),'TEST-2':osv('TEST-2')},
             [{'results':[{'vulns':[{'id':'TEST-1'}],'next_page_token':'page2'}]},
              {'results':[{'vulns':[{'id':'TEST-2'}]}]}])
        result = self.run_query([component()],http)
        self.assertEqual([x['id'] for x in result['advisories']],['TEST-1','TEST-2'])
        self.assertEqual(result['advisories'][0]['fixed_versions'],['1.3.0','2.4.0'])
        self.assertEqual(http.calls[1][2]['queries'][0]['page_token'],'page2')

    def test_withdrawn_records_are_excluded(self):
        http = FakeHTTP({'TEST-1':osv(withdrawn='2024-03-01T00:00:00Z')},
                        [{'results':[{'vulns':[{'id':'TEST-1'}]}]}])
        self.assertEqual(self.run_query([component()],http)['advisories'],[])

    def test_wrong_package_record_is_never_matched(self):
        http = FakeHTTP({'TEST-1':osv(name='other')},[{'results':[{'vulns':[{'id':'TEST-1'}]}]}])
        result=self.run_query([component()],http)
        self.assertEqual(result['advisories'],[])
        self.assertTrue(any(s['status']=='partial' for s in result['sources']))

    def test_full_record_fetch_failure_is_not_clean(self):
        http=FakeHTTP({'TEST-1':RuntimeError('down')},[{'results':[{'vulns':[{'id':'TEST-1'}]}]}])
        result=self.run_query([component()],http)
        self.assertEqual(result['advisories'],[])
        self.assertTrue(any(s['status'] in ('error','partial') for s in result['sources']))

    def test_cached_response_works_offline_and_marks_stale(self):
        http=FakeHTTP({'TEST-1':osv()},[{'results':[{'vulns':[{'id':'TEST-1'}]}]}])
        self.run_query([component()],http,now=1000)
        result=self.run_query([component()],FakeHTTP(),offline=True,now=100000,cache_ttl_hours=1)
        self.assertEqual(len(result['advisories']),1)
        self.assertTrue(any(s['status']=='stale' for s in result['sources']))

    def test_expired_offline_cache_is_unavailable(self):
        http=FakeHTTP({'TEST-1':osv()},[{'results':[{'vulns':[{'id':'TEST-1'}]}]}])
        self.run_query([component()],http,now=1000)
        result=self.run_query([component()],offline=True,now=9999999,max_cache_age_hours=1)
        self.assertEqual(result['advisories'],[])
        self.assertTrue(any(s['status']=='unavailable' for s in result['sources']))

    def test_kevs_match_aliases_and_preserve_context(self):
        http=FakeHTTP({'TEST-1':osv()},[{'results':[{'vulns':[{'id':'TEST-1'}]}]}],
          {advisories.KEV_URL:{'vulnerabilities':[{'cveID':'CVE-2024-1234','dueDate':'2024-02-03'}]}})
        result=self.run_query([component()],http)
        self.assertTrue(result['advisories'][0]['known_exploited'])

    def test_distro_packages_do_not_use_upstream_osv(self):
        http=FakeHTTP()
        result=self.run_query([component('openssl','1.1.1f-1ubuntu2.22',None,manager='dpkg')],http)
        self.assertFalse(any(c[1].endswith('querybatch') for c in http.calls))
        self.assertTrue(any(x['source']=='trivy' for x in result['source_plan']))

    def test_repeated_pagination_token_is_partial(self):
        http=FakeHTTP({},[{'results':[{'next_page_token':'same'}]},
                          {'results':[{'next_page_token':'same'}]}])
        result=self.run_query([component()],http)
        self.assertTrue(any(s['status']=='partial' for s in result['sources']))

    def test_runtime_go_queries_both_stdlib_and_toolchain(self):
        http=FakeHTTP()
        self.run_query([component('go','go1.22.1',None,**{'kind_override':'unused'}) | {'kind':'runtime'}],http)
        queries=next(x[2]['queries'] for x in http.calls if x[1].endswith('querybatch'))
        self.assertEqual({q['package']['name'] for q in queries},{'stdlib','toolchain'})
        self.assertEqual({q['version'] for q in queries},{'1.22.1'})

    def test_python_official_records_use_osv_imported_tag_evidence(self):
        rec={'id':'PSF-2024-1','aliases':['CVE-2024-1234'],'affected':[
             {'ranges':[{'type':'GIT','repo':'https://github.com/python/cpython','events':[
                {'introduced':'0'},{'fixed':'deadbeef'}]}], 'versions':['v3.11.7']}]}
        http=FakeHTTP({'PSF-2024-1':rec},routes={advisories.PYTHON_SNAPSHOT:
                    archive({'advisories/python/PSF-2024-1.json':rec})})
        result=self.run_query([component('python','3.11.7',None)|{'kind':'runtime'}],http)
        self.assertEqual([x['id'] for x in result['advisories']],['PSF-2024-1'])
        self.assertEqual(result['advisories'][0]['fixed_versions'],[])

    def test_python_missing_tag_evidence_is_gap_not_confirmed(self):
        rec={'id':'PSF-1','affected':[{'ranges':[{'type':'GIT','events':[{'introduced':'0'}]}]}]}
        http=FakeHTTP({'PSF-1':rec},routes={advisories.PYTHON_SNAPSHOT:
                    archive({'advisories/python/PSF-1.json':rec})})
        result=self.run_query([component('python','3.11.7',None)|{'kind':'runtime'}],http)
        self.assertEqual(result['advisories'],[])
        self.assertTrue(any(s['status']=='partial' for s in result['sources']))

    def test_node_official_wildcard_and_patched_ranges(self):
        records={'vuln/core/1.json':{'cve':['CVE-2024-1234'],'vulnerable':'18.x || 20.x',
                'patched':'^18.19.1 || ^20.11.1','description':'runtime bug'}}
        http=FakeHTTP(routes={advisories.NODE_SNAPSHOT:archive(records)})
        result=self.run_query([component('node','20.11.0',None)|{'kind':'runtime'}],http)
        self.assertEqual(len(result['advisories']),1)
        self.assertEqual(result['advisories'][0]['fixed_versions'],['18.19.1','20.11.1'])
        fixed=self.run_query([component('node','20.11.1',None)|{'kind':'runtime'}],http)
        self.assertEqual(fixed['advisories'],[])

    def test_no_lexical_version_comparison_for_node(self):
        records={'vuln/core/1.json':{'cve':['CVE-2024-1234'],'vulnerable':'>=18.0.0 <18.10.0',
                'patched':'>=18.10.0','description':'bug'}}
        http=FakeHTTP(routes={advisories.NODE_SNAPSHOT:archive(records)})
        result=self.run_query([component('node','18.9.0',None)|{'kind':'runtime'}],http)
        self.assertEqual(len(result['advisories']),1)

    def test_windows_coverage_explicit(self):
        result=advisories.query_advisories({'host':{'os':'Windows'},'components':[]},self.cache,
                                         {'requester':FakeHTTP()})
        self.assertTrue(any(x['status'] in ('partial','unavailable') and ('Windows' in x.get('detail','') or 'WUA' in x.get('detail',''))
                            for x in result['coverage']))

    def test_github_runtime_ranges_match_package_identity(self):
        url='https://api.github.com/repos/php/php-src/security-advisories?state=published&per_page=100&page=1'
        records=[{'ghsa_id':'GHSA-test','summary':'PHP bug','vulnerabilities':[
          {'package':{'name':'php','ecosystem':'other'},'vulnerable_version_range':'>=8.2.0, <8.2.7',
           'patched_versions':'8.2.7'}]}]
        http=FakeHTTP(routes={url:records})
        result=self.run_query([component('php','8.2.6',None)|{'kind':'runtime'}],http)
        self.assertEqual([x['id'] for x in result['advisories']],['GHSA-test'])
        self.assertTrue(any(s['status']=='partial' for s in result['sources']))

    def test_failed_cache_write_does_not_lose_live_findings(self):
        http=FakeHTTP({'TEST-1':osv()},[{'results':[{'vulns':[{'id':'TEST-1'}]}]}])
        self.cache.rmdir();self.cache.write_text('not a directory')
        result=self.run_query([component()],http)
        self.assertEqual(len(result['advisories']),1)
        self.assertTrue(any('cache' in s.get('detail','').lower() for s in result['sources']))

    def test_https_allowlist_blocks_injected_urls(self):
        from aro_core.advisory_http import AdvisoryHTTP
        client=AdvisoryHTTP(self.cache,{'requester':FakeHTTP()})
        with self.assertRaises(ValueError): client.fetch('https://evil.example/metadata')
        with self.assertRaises(ValueError): client.fetch('http://api.osv.dev/v1/vulns/X')

    def test_trivy_maps_distro_evidence_and_stale_database(self):
        report={'Metadata':{'OS':{'Family':'ubuntu','Name':'22.04'}},'Results':[
           {'Class':'os-pkgs','Type':'ubuntu','Vulnerabilities':[{
            'VulnerabilityID':'CVE-2024-1234','PkgName':'openssl','InstalledVersion':'1.1.1f-1ubuntu2',
            'FixedVersion':'1.1.1f-1ubuntu2.22','Severity':'HIGH','PrimaryURL':'https://ubuntu.com/security/CVE-2024-1234'}]}]}
        result=self.run_query([component('openssl','1.1.1f-1ubuntu2',None,manager='dpkg')],
            trivy_reports=[{'report':report,'db_updated_at':'2000-01-01T00:00:00Z'}])
        self.assertEqual(result['advisories'][0]['fixed_versions'],['1.1.1f-1ubuntu2.22'])
        self.assertTrue(any(s['status']=='stale' for s in result['sources']))

    def test_unmapped_trivy_findings_are_not_attached_to_host(self):
        report={'Results':[{'Class':'os-pkgs','Vulnerabilities':[{
         'VulnerabilityID':'CVE-2024-1234','PkgName':'openssl','InstalledVersion':'WRONG'}]}]}
        result=self.run_query([component('openssl','1.1.1f-1ubuntu2',None,manager='dpkg')],
                    trivy_reports=[{'report':report}])
        self.assertEqual(result['advisories'],[])
        self.assertTrue(any(s['status']=='partial' for s in result['sources']))

    def test_arbitrary_image_not_allowed_or_pulled(self):
        with patch('subprocess.run') as run:
            result=self.run_query([],trivy_targets=[{'kind':'image','target':'evil.example/private:latest'}])
        self.assertFalse(run.called)
        self.assertTrue(any(x['status'] in ('unavailable','error') for x in result['coverage']))


    def test_osv_explicit_versions_must_include_installed(self):
        record=osv();record['affected'][0]={'package':{'name':'demo','ecosystem':'npm'},'versions':['0.1.0']}
        http=FakeHTTP({'TEST-1':record},[{'results':[{'vulns':[{'id':'TEST-1'}]}]}])
        result=self.run_query([component()],http)
        self.assertEqual(result['advisories'],[])
        self.assertTrue(any(s['status']=='partial' for s in result['sources']))

    def test_malformed_osv_record_is_failed_coverage(self):
        record=osv();record['affected']={'untrusted':'malformed'}
        http=FakeHTTP({'TEST-1':record},[{'results':[{'vulns':[{'id':'TEST-1'}]}]}])
        result=self.run_query([component()],http)
        self.assertEqual(result['advisories'],[])
        self.assertTrue(any(s['status'] in ('error','partial') for s in result['sources']))

    def test_trivy_wrong_distribution_cannot_confirm_host_package(self):
        report={'Metadata':{'OS':{'Family':'alpine','Name':'3.19'}},'Results':[
          {'Class':'os-pkgs','Vulnerabilities':[{'VulnerabilityID':'CVE-2024-1234',
           'PkgName':'openssl','InstalledVersion':'1.2.3','FixedVersion':'1.2.4'}]}]}
        result=self.run_query([component('openssl','1.2.3',None,manager='dpkg')],
                             trivy_reports=[{'report':report}])
        self.assertEqual(result['advisories'],[])
        self.assertTrue(any('distribution' in s['detail'].lower() for s in result['sources']))

    def test_checksum_only_go_coordinates_are_never_queried(self):
        http=FakeHTTP()
        result=self.run_query([component('example.org/private','1.0.0','Go',metadata={'selected':False})],http)
        self.assertFalse(any(call[1].endswith('querybatch') for call in http.calls))
        self.assertTrue(any(c['collector']=='component-selection' for c in result['coverage']))

    def test_source_plan_deterministic_under_component_reordering(self):
        values=[component('z'),component('a','1.0.0','PyPI')]
        self.assertEqual(advisories.build_source_plan({'components':values}),
                         advisories.build_source_plan({'components':list(reversed(values))}))

    def test_cisa_official_mirror_retains_primary_failure_coverage(self):
        http=FakeHTTP({'TEST-1':osv()},[{'results':[{'vulns':[{'id':'TEST-1'}]}]}],{
          advisories.KEV_URL:RuntimeError('blocked'),
          'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json':
          {'vulnerabilities':[{'cveID':'CVE-2024-1234'}]}})
        result=self.run_query([component()],http)
        self.assertTrue(result['advisories'][0]['known_exploited'])
        self.assertTrue(any(s['source']=='cisa-kev' and s['status']!='ok' for s in result['sources']))

    def test_semver_fixed_boundary_is_not_confirmed_from_fuzzy_query(self):
        http=FakeHTTP({'TEST-1':osv()},[{'results':[{'vulns':[{'id':'TEST-1'}]}]}])
        result=self.run_query([component(version='1.3.0')],http)
        self.assertEqual(result['advisories'],[])
        self.assertTrue(any(s['status']=='partial' for s in result['sources']))

    def test_node_short_numeric_comparator_is_version_aware(self):
        records={'vuln/core/54.json':{'vulnerable':'<= 10','patched':'>=10.9.0','description':'old bug'}}
        http=FakeHTTP(routes={advisories.NODE_SNAPSHOT:archive(records)})
        result=self.run_query([component('node','20.11.0',None)|{'kind':'runtime'}],http)
        self.assertEqual(result['advisories'],[])
        self.assertEqual(next(s['status'] for s in result['sources'] if s['source']=='nodejs-security-wg'),'ok')

    def test_host_architecture_scope_maps_to_host_trivy(self):
        report={'Metadata':{'OS':{'Family':'ubuntu','Name':'22.04'}},'Results':[
          {'Class':'os-pkgs','Vulnerabilities':[{'VulnerabilityID':'CVE-2024-1234',
           'PkgName':'openssl','InstalledVersion':'1.2.3','FixedVersion':'1.2.4'}]}]}
        value=component('openssl','1.2.3',None,manager='apt',scope='amd64')|{'kind':'os-package'}
        result=self.run_query([value],trivy_reports=[{'report':report}])
        self.assertEqual(len(result['advisories']),1)

    def test_image_distro_purl_does_not_use_host_distribution(self):
        image='sha256:'+'a'*64
        report={'Metadata':{'OS':{'Family':'alpine','Name':'3.19'}},'Results':[
          {'Class':'os-pkgs','Vulnerabilities':[{'VulnerabilityID':'CVE-2024-1234',
           'PkgName':'openssl','InstalledVersion':'1.2.3','FixedVersion':'1.2.4'}]}]}
        value=component('openssl','1.2.3',None,purl='pkg:apk/alpine/openssl@1.2.3',
                        metadata={'image_id':image,'scope':'image'})|{'kind':'container-package'}
        result=self.run_query([value],trivy_reports=[{'report':report,'image_id':image}])
        self.assertEqual(len(result['advisories']),1)

    def test_corrupt_cache_json_shape_becomes_offline_unavailable(self):
        from aro_core.advisory_http import AdvisoryHTTP,SourceUnavailable
        client=AdvisoryHTTP(self.cache,{'requester':FakeHTTP()})
        client.fetch(advisories.OSV_URL,{'queries':[]})
        next(self.cache.glob('*.json')).write_text('[]')
        with self.assertRaises(SourceUnavailable):
            AdvisoryHTTP(self.cache,{'requester':FakeHTTP(),'offline':True}).fetch(advisories.OSV_URL,{'queries':[]})

    def test_local_file_version_and_path_name_never_leave(self):
        http=FakeHTTP()
        result=self.run_query([component('demo','file:/secret/source'),component('/secret/source')],http)
        self.assertFalse(any(c[1].endswith('querybatch') for c in http.calls))
        self.assertTrue(any(s['status']=='unavailable' for s in result['sources']))

    def test_project_path_trivy_executable_never_runs(self):
        with patch('shutil.which',return_value='/workspace/untrusted/trivy'), patch('subprocess.run') as runner:
            result=self.run_query([component('openssl','1.2.3',None,manager='apt')])
        self.assertFalse(runner.called)
        self.assertTrue(any(s['status']=='unavailable' for s in result['sources']))

    def test_local_image_trivy_uses_docker_only_and_offline_database_flags(self):
        from types import SimpleNamespace
        image='sha256:'+'a'*64
        inventory={'host':{'os':'linux','id':'ubuntu'},'containers':[{'image_id':image}], 'components':[]}
        calls=[]
        def run(argv,**kwargs):
            calls.append((argv,kwargs))
            return SimpleNamespace(returncode=0,stdout=json.dumps(
                {'VulnerabilityDB':{'UpdatedAt':'2026-10-31T00:00:00Z'}} if '--version' in argv else
                {'Metadata':{'OS':{'Family':'alpine','Name':'3.19'}},'Results':[]}))
        with patch('shutil.which',return_value='/usr/bin/trivy'), patch('subprocess.run',side_effect=run):
            advisories.query_advisories(inventory,self.cache,{'requester':FakeHTTP(),'offline':True})
        scan=calls[0][0]
        self.assertEqual(scan[scan.index('--image-src')+1],'docker')
        self.assertIn('--offline-scan',scan)
        self.assertIn('--skip-db-update',scan)
        self.assertEqual(scan[-1],image)
        self.assertFalse(any(key.startswith('TRIVY_') for key in calls[0][1]['env']))

    def test_native_ubuntu_queries_source_package_with_release_suffix(self):
        value=component('libssl3t64','3.0.13-0ubuntu3.4',None,manager='apt',metadata={
          'distribution':'ubuntu','distribution_version':'24.04','distribution_release':'24.04.2 LTS (Noble Numbat)',
          'source_package':'openssl','source_version':'3.0.13-0ubuntu3.4'})|{'kind':'os-package'}
        http=FakeHTTP()
        self.run_query([value],http)
        queries=next(c[2]['queries'] for c in http.calls if c[1].endswith('querybatch'))
        self.assertEqual(queries,[{'package':{'ecosystem':'Ubuntu:24.04:LTS','name':'openssl'},'version':'3.0.13-0ubuntu3.4'}])

    def test_native_debian_backport_evidence_is_distro_qualified(self):
        value=component('libssl3','3.0.11-1~deb12u2',None,manager='apt',metadata={
          'distribution':'debian','distribution_version':'12','source_package':'openssl','source_version':'3.0.11-1~deb12u2'})|{'kind':'os-package'}
        record=osv('DEBIAN-CVE-2024-1234',name='openssl',ecosystem='Debian:12')
        record['affected'][0]['ranges']=[{'type':'ECOSYSTEM','events':[{'introduced':'0'},{'fixed':'3.0.11-1~deb12u3'}]}]
        http=FakeHTTP({'DEBIAN-CVE-2024-1234':record},[{'results':[{'vulns':[{'id':'DEBIAN-CVE-2024-1234'}]}]}])
        result=self.run_query([value],http)
        row=result['advisories'][0]
        self.assertEqual(row['component_id'],'libssl3:3.0.11-1~deb12u2')
        self.assertEqual(row['fixed_versions'],['3.0.11-1~deb12u3'])
        self.assertEqual(row['match_confidence'],'vendor-source-package')
        self.assertEqual(row['affected_range'][0]['package']['ecosystem'],'Debian:12')

    def test_distro_source_name_privacy_exclusion_applies_before_query(self):
        value=component('binary','1.0-1',None,manager='apt',metadata={
          'distribution':'debian','distribution_version':'12','source_package':'private-source','source_version':'1.0-1'})
        http=FakeHTTP()
        self.run_query([value],http,exclude_packages=['private-*'])
        self.assertFalse(any(c[1].endswith('querybatch') for c in http.calls))

    def test_distro_owned_runtime_is_upstream_review_only(self):
        records={'vuln/core/1.json':{'cve':['CVE-2024-1234'],'vulnerable':'20.x','patched':'>=20.11.1','description':'bug'}}
        http=FakeHTTP(routes={advisories.NODE_SNAPSHOT:archive(records)})
        value=component('node','20.11.0',None,path='/usr/bin/node',metadata={'distribution_owned':True})|{'kind':'runtime'}
        result=self.run_query([value],http)
        self.assertEqual(result['advisories'][0]['match_confidence'],'upstream-version')
        self.assertTrue(any('backport' in c['detail'].lower() for c in result['coverage']))

    def test_windows_adapter_is_routed_for_mapped_os(self):
        inventory={'host':{'os':'Windows'},'components':[{'id':'windows-os','name':'Microsoft Windows',
          'version':'10.0.20348','kind':'os','ecosystem':None}]}
        result=advisories.query_advisories(inventory,self.cache,{'requester':FakeHTTP(),
          'windows_runner':lambda argv,options:(json.dumps({'result_code':2,'updates':[],'total_updates':0,'warnings':[]}),'ok')})
        self.assertTrue(any(s['source']=='windows-update-agent' and s['status']=='ok' for s in result['sources']))

    def test_osv_vendor_priority_and_upstream_cve_are_retained(self):
        record=osv();record['aliases']=[];record['upstream']=['CVE-2024-1234'];record['severity']=[
            {'type':'Ubuntu','score':'medium'},{'type':'CVSS_V3','score':'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H'}]
        http=FakeHTTP({'TEST-1':record},[{'results':[{'vulns':[{'id':'TEST-1'}]}]}])
        result=self.run_query([component()],http)
        self.assertEqual(result['advisories'][0]['severity'],'MEDIUM')
        self.assertEqual(result['advisories'][0]['attack_vector'],'network')
        self.assertIn('CVE-2024-1234',result['advisories'][0]['aliases'])

    def test_python_wrong_import_id_cannot_confirm_a_match(self):
        source={'id':'PSF-1','modified':'2026-01-01T00:00:00Z'}
        wrong={'id':'PSF-OTHER','affected':[{'ranges':[{'type':'GIT','repo':'https://github.com/python/cpython'}],
                                                    'versions':['v3.11.7']}]}
        http=FakeHTTP({'PSF-1':wrong},routes={advisories.PYTHON_SNAPSHOT:archive({'advisories/python/PSF-1.json':source})})
        result=self.run_query([component('python','3.11.7',None)|{'kind':'runtime'}],http)
        self.assertEqual(result['advisories'],[])
        self.assertTrue(any(s['status']=='partial' for s in result['sources']))

    def test_python_official_withdrawal_overrides_old_import(self):
        source={'id':'PSF-1','withdrawn':'2026-01-01T00:00:00Z'}
        old={'id':'PSF-1','affected':[{'ranges':[{'type':'GIT','repo':'https://github.com/python/cpython'}],
                                                  'versions':['v3.11.7']}]}
        http=FakeHTTP({'PSF-1':old},routes={advisories.PYTHON_SNAPSHOT:archive({'advisories/python/PSF-1.json':source})})
        self.assertEqual(self.run_query([component('python','3.11.7',None)|{'kind':'runtime'}],http)['advisories'],[])

    def test_python_import_lag_is_visible(self):
        source={'id':'PSF-1','modified':'2026-01-02T00:00:00Z'}
        old={'id':'PSF-1','modified':'2026-01-01T00:00:00Z','affected':[
            {'ranges':[{'type':'GIT','repo':'https://github.com/python/cpython'}],'versions':['v3.11.7']}]}
        http=FakeHTTP({'PSF-1':old},routes={advisories.PYTHON_SNAPSHOT:archive({'advisories/python/PSF-1.json':source})})
        result=self.run_query([component('python','3.11.7',None)|{'kind':'runtime'}],http)
        self.assertTrue(any(s['source']=='python-psf' and s['status']=='partial' and 'older' in s['detail'] for s in result['sources']))

    def test_no_cve_kev_is_completed_not_applicable(self):
        result=self.run_query([component()],FakeHTTP())
        self.assertEqual(next(s['status'] for s in result['sources'] if s['source']=='cisa-kev'),'not_applicable')

    def test_local_image_components_are_mapped_trivy_targets(self):
        from types import SimpleNamespace
        image='sha256:'+'b'*64
        inventory={'host':{'os':'linux','id':'ubuntu'},'containers':[], 'components':[
            {'id':'local-image','name':image,'version':image,'kind':'container-image','ecosystem':None}]}
        scans=[]
        def run(argv,**kwargs):
            if '--version' not in argv: scans.append(argv)
            return SimpleNamespace(returncode=0,stdout=json.dumps(
                {'VulnerabilityDB':{'UpdatedAt':'2026-10-31T00:00:00Z'}} if '--version' in argv else
                {'Metadata':{'OS':{'Family':'alpine','Name':'3.19'}},'Results':[]}))
        with patch('shutil.which',return_value='/usr/bin/trivy'),patch('subprocess.run',side_effect=run):
            advisories.query_advisories(inventory,self.cache,{'requester':FakeHTTP(),'offline':True})
        self.assertEqual(len(scans),1)
        self.assertEqual(scans[0][-1],image)

    def test_go_shared_record_retains_both_runtime_affected_sections(self):
        record=osv('GO-TEST',name='stdlib',ecosystem='Go')
        record['affected'].append({'package':{'name':'toolchain','ecosystem':'Go'},'ranges':[
            {'type':'SEMVER','events':[{'introduced':'0'},{'fixed':'1.4.0'}]}]})
        http=FakeHTTP({'GO-TEST':record},[{'results':[{'vulns':[{'id':'GO-TEST'}]},{'vulns':[{'id':'GO-TEST'}]}]}])
        result=self.run_query([component('go','go1.2.0',None)|{'kind':'runtime'}],http)
        self.assertEqual(len(result['advisories']),1)
        self.assertEqual({a['package']['name'] for a in result['advisories'][0]['affected_range']},{'stdlib','toolchain'})
        self.assertEqual(result['advisories'][0]['fixed_versions'],['1.3.0','2.4.0','1.4.0'])

    def test_force_refresh_fetches_online_but_preserves_offline_cache(self):
        http=FakeHTTP({'TEST-1':osv()},[{'results':[{'vulns':[{'id':'TEST-1'}]}]}])
        self.run_query([component()],http,now=1000)
        ordinary=self.run_query([component()],FakeHTTP(),now=1001)
        self.assertEqual(len(ordinary['advisories']),1)
        offline=self.run_query([component()],FakeHTTP(),now=1001,offline=True,force_refresh=True)
        self.assertEqual(len(offline['advisories']),1)
        fresh=self.run_query([component()],FakeHTTP(),now=1001,force_refresh=True)
        self.assertEqual(fresh['advisories'],[])

if __name__=='__main__': unittest.main()
