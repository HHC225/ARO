"""Bounded HTTPS transport, injectable at the HTTP boundary, with local cache."""
from __future__ import annotations
import base64
import hashlib
import json
import os
from pathlib import Path
import tempfile
import threading
import time
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler


class SourceUnavailable(RuntimeError):
    """A source could not be checked; it is never equivalent to no findings."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise SourceUnavailable('HTTP redirect rejected')


class AdvisoryHTTP:
    def __init__(self, cache_dir: Path, options=None):
        self.options = options or {}
        self.cache_dir = Path(cache_dir)
        self.now = float(self.options.get('now', time.time()))
        self.events = []
        self._lock = threading.Lock()
        self._requests = 0
        self.requester = self.options.get('requester') or self._request
        self.limit = min(max(int(self.options.get('max_requests', 1500)), 1), 5000)
        self.max_bytes = min(max(int(self.options.get('max_response_bytes', 32*1024*1024)), 1024), 64*1024*1024)
        self.timeout = min(max(float(self.options.get('timeout', 12)), .1), 30)
        self.retries = min(max(int(self.options.get('retries', 1)), 0), 2)

    @staticmethod
    def validate_url(url):
        parsed = urlsplit(url)
        if parsed.scheme != 'https' or parsed.port not in (None,443) or parsed.username or parsed.password or parsed.fragment:
            raise ValueError('Only allowlisted HTTPS advisory endpoints are permitted')
        host, path = parsed.hostname, parsed.path
        allowed = (host == 'api.osv.dev' and (path == '/v1/querybatch' or path.startswith('/v1/vulns/'))
            or host == 'www.cisa.gov' and path == '/sites/default/files/feeds/known_exploited_vulnerabilities.json'
            or host == 'raw.githubusercontent.com' and path == '/cisagov/kev-data/develop/known_exploited_vulnerabilities.json'
            or host == 'codeload.github.com' and path in (
                '/psf/advisory-database/tar.gz/refs/heads/main', '/nodejs/security-wg/tar.gz/refs/heads/main')
            or host == 'api.github.com' and path in tuple('/repos/'+repo+'/security-advisories' for repo in (
                'python/cpython','nodejs/node','php/php-src','ruby/ruby','dotnet/runtime','rust-lang/rust')))
        if not allowed: raise ValueError('URL is outside the advisory allowlist')

    def _request(self, method, url, payload=None, timeout=12):
        raw = None if payload is None else json.dumps(payload,sort_keys=True,separators=(',',':')).encode()
        req = Request(url, data=raw, method=method, headers={
            'Accept':'application/json', 'Content-Type':'application/json', 'User-Agent':'ARO/1 advisory-check'})
        with build_opener(_NoRedirect()).open(req,timeout=timeout) as response:
            data = response.read(self.max_bytes+1)
        if len(data)>self.max_bytes: raise SourceUnavailable('Response exceeds configured byte limit')
        return data if 'codeload.github.com' in url else json.loads(data)

    def fetch(self, url, payload=None):
        self.validate_url(url)
        method = 'GET' if payload is None else 'POST'
        signature = json.dumps([method,url,payload],sort_keys=True,separators=(',',':'))
        path = self.cache_dir/(hashlib.sha256(signature.encode()).hexdigest()+'.json')
        cached = None
        try:
            if path.stat().st_size <= self.max_bytes*2:
                cached=json.loads(path.read_text(encoding='utf-8'))
                if not isinstance(cached,dict) or cached.get('signature')!=hashlib.sha256(signature.encode()).hexdigest() or 'data' not in cached: cached=None
        except (OSError,ValueError,TypeError): pass
        age = self.now-float(cached['fetched_epoch']) if cached and isinstance(cached.get('fetched_epoch'),(int,float)) else float('inf')
        ttl = max(0,float(self.options.get('cache_ttl_hours',6)))*3600
        max_age = max(0,float(self.options.get('max_cache_age_hours',168)))*3600
        usable = cached is not None and 0 <= age <= max_age
        def record(status,epoch,detail):
            from datetime import datetime,timezone
            fetched_at=datetime.fromtimestamp(epoch,timezone.utc).isoformat().replace('+00:00','Z') if epoch is not None else None
            with self._lock: self.events.append(dict(url=url,status=status,fetched_at=fetched_at,detail=detail))
        def unpack():
            try: return base64.b64decode(cached['data'],validate=True) if cached.get('binary') else cached['data']
            except (ValueError,KeyError) as exc: raise SourceUnavailable('Corrupt cached response') from exc
        if usable and age<=ttl and (not self.options.get('force_refresh') or self.options.get('offline')):
            record('ok',cached['fetched_epoch'],'Fresh cached response'+(' (offline)' if self.options.get('offline') else ''))
            return unpack()
        if self.options.get('offline'):
            if usable:
                record('stale',cached['fetched_epoch'],'Offline response older than freshness TTL')
                return unpack()
            record('unavailable',None,'Offline and no usable cache within maximum age')
            raise SourceUnavailable('No usable offline cache')
        failure = 'Source request failed'
        for _ in range(self.retries+1):
            try:
                with self._lock:
                    self._requests+=1
                    if self._requests>self.limit: raise SourceUnavailable('HTTP request budget exhausted')
                data=self.requester(method,url,payload,timeout=self.timeout)
                if isinstance(data,tuple): data=data[0]
                binary=isinstance(data,bytes)
                size = len(data) if binary else len(json.dumps(data))
                if size > self.max_bytes: raise SourceUnavailable('Response exceeds byte limit')
                entry=dict(signature=hashlib.sha256(signature.encode()).hexdigest(), fetched_epoch=self.now,
                           binary=binary,data=base64.b64encode(data).decode() if binary else data)
                detail='Live response'
                status='ok'
                try:
                    self.cache_dir.mkdir(parents=True,exist_ok=True)
                    descriptor,temporary=tempfile.mkstemp(prefix='.aro-cache-',dir=self.cache_dir)
                    try:
                        with os.fdopen(descriptor,'w',encoding='utf-8') as stream:
                            json.dump(entry,stream,sort_keys=True,separators=(',',':'))
                        os.replace(temporary,path)
                    finally:
                        try: os.unlink(temporary)
                        except OSError: pass
                except OSError:
                    status='partial';detail='Live response; cache could not be written'
                record(status,self.now,detail)
                return data
            except Exception as exc:
                failure=type(exc).__name__+((' '+str(exc.code)) if isinstance(getattr(exc,'code',None),int) else '')+': source request failed'
        if usable:
            record('stale',cached['fetched_epoch'],failure+'; using bounded-age cached response')
            return unpack()
        record('error',None,failure+'; no usable cache')
        raise SourceUnavailable(failure)
