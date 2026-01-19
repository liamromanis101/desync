#!/usr/bin/env python3
"""
HTTP/1.1 vs HTTP/2 Differential Desync Harness (authorized use only)

- Parses a Burp-captured HTTP/1.x request (preserves header order + duplicates).
- Replays a baseline request over HTTP/1.1 and HTTP/2 (httpx).
- Runs a small set of header/body "anomaly" variants over both protocols.
- Scores divergence vs each protocol baseline (status + body hash) to reduce false positives.
- Supports verbosity:
    * (no -v) : prints JSON report only
    * -v      : prints human-readable progress + JSON report
    * -vv     : additionally prints request/response dumps (headers + first N bytes of body)

Requires:
    pip install "httpx[h2]"

Additional test variants to add
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import random
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

import httpx


# -----------------------------
# Models
# -----------------------------

@dataclass
class Header:
    name: str
    value: str


@dataclass
class BurpRequest:
    method: str
    path: str
    version: str
    headers: List[Header]  # preserves order + duplicates
    body: bytes


@dataclass
class Fingerprint:
    status_code: int
    body_sha256: str
    body_len: int
    ttfb_ms: int
    total_ms: int
    headers_subset: Dict[str, str]


@dataclass
class Trial:
    ok: bool
    error: Optional[str]
    fp: Optional[Fingerprint]


@dataclass
class Baseline:
    status_counts: Dict[int, int]
    body_hash_counts: Dict[str, int]
    samples: int


@dataclass
class Variant:
    id: str
    description: str
    extra_headers: List[Header]
    body_append: bytes


IMPORTANT_HEADERS = (
    "server",
    "via",
    "alt-svc",
    "x-cache",
    "cf-cache-status",
    "age",
    "x-request-id",
    "x-amz-cf-id",
)


# -----------------------------
# Helpers
# -----------------------------

def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def jitter_sleep(base_s: float, jitter_ms: int) -> None:
    extra = (random.random() * jitter_ms) / 1000.0 if jitter_ms > 0 else 0.0
    time.sleep(max(0.0, base_s + extra))


def sanitize_base_url(url: str) -> str:
    u = urlsplit(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise ValueError("URL must include scheme and host, e.g. https://example.com/")
    netloc = u.hostname
    if u.port:
        netloc = f"{netloc}:{u.port}"
    return urlunsplit((u.scheme, netloc, "", "", ""))


def read_burp_request(path: str) -> BurpRequest:
    raw = open(path, "rb").read()

    # Find header/body separator: \r\n\r\n or \n\n
    sep = b"\r\n\r\n"
    idx = raw.find(sep)
    if idx >= 0:
        head = raw[:idx]
        body = raw[idx + 4 :]
        lines = head.split(b"\r\n")
    else:
        sep = b"\n\n"
        idx = raw.find(sep)
        if idx < 0:
            raise ValueError("Could not find header/body separator in Burp file.")
        head = raw[:idx]
        body = raw[idx + 2 :]
        lines = head.split(b"\n")

    if not lines:
        raise ValueError("Empty request")

    first = lines[0].decode("utf-8", "replace").strip()
    parts = first.split(" ")
    if len(parts) < 3:
        raise ValueError(f"Bad request line: {first!r}")

    method, path_part, version = parts[0].upper(), parts[1], parts[2].upper()

    headers: List[Header] = []
    for bline in lines[1:]:
        line = bline.decode("utf-8", "replace")
        if not line.strip():
            continue
        if line.lstrip().startswith("#"):
            continue
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers.append(Header(name=name.strip(), value=value.strip()))

    # Strip trailing line breaks from body to match typical Burp "raw" export expectations
    body = body.rstrip(b"\r\n")

    return BurpRequest(method=method, path=path_part, version=version, headers=headers, body=body)


def headers_to_httpx(headers: List[Header]) -> List[Tuple[str, str]]:
    # httpx supports list-of-tuples to preserve duplicates
    return [(h.name, h.value) for h in headers]


def subset_headers(h: httpx.Headers) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k in IMPORTANT_HEADERS:
        if k in h:
            out[k] = h.get(k, "")
    return out


def dump_request(proto: str, label: str, req: httpx.Request, max_body: int = 1000) -> None:
    print("\n" + "-" * 80)
    print(f"➡️  REQUEST [{label}] ({proto.upper()})")
    print(f"{req.method} {req.url}")
    for k, v in req.headers.items():
        print(f"{k}: {v}")
    if req.content:
        body = req.content
        if isinstance(body, bytes):
            body = body[:max_body]
            print("\n" + body.decode("utf-8", "replace"))
    print("-" * 80)


def dump_response(proto: str, label: str, resp: httpx.Response, max_body: int = 1000) -> None:
    print("\n" + "-" * 80)
    print(f"⬅️  RESPONSE [{label}] ({proto.upper()})")
    print(f"HTTP {resp.status_code}")
    for k, v in resp.headers.items():
        print(f"{k}: {v}")
    if resp.content:
        body = resp.content[:max_body]
        print("\n" + body.decode("utf-8", "replace"))
    print("-" * 80)


# -----------------------------
# Runner
# -----------------------------

class DiffHarness:
    def __init__(
        self,
        base_url: str,
        timeout_s: float,
        rps: float,
        jitter_ms: int,
        max_body: int,
        keepalive: bool,
        verify_tls: bool,
        user_agent: str,
        verbose: int = 0,
        dump_bytes: int = 1000,
    ):
        self.base_url = base_url
        self.timeout_s = timeout_s
        self.rps = rps
        self.jitter_ms = jitter_ms
        self.max_body = max_body
        self.keepalive = keepalive
        self.verify_tls = verify_tls
        self.user_agent = user_agent
        self.verbose = verbose
        self.dump_bytes = dump_bytes

    def _client(self, http2: bool) -> httpx.Client:
        limits = httpx.Limits(
            max_connections=10,
            max_keepalive_connections=(10 if self.keepalive else 0),
            keepalive_expiry=(30 if self.keepalive else 0.0),
        )
        return httpx.Client(
            base_url=self.base_url,
            http2=http2,
            verify=self.verify_tls,
            follow_redirects=False,
            timeout=httpx.Timeout(self.timeout_s),
            limits=limits,
            headers={"User-Agent": self.user_agent},
        )

    def _fingerprint(self, resp: httpx.Response, ttfb_ms: int, total_ms: int) -> Fingerprint:
        body = resp.content[: self.max_body]
        return Fingerprint(
            status_code=resp.status_code,
            body_sha256=sha256_hex(body),
            body_len=len(resp.content),
            ttfb_ms=ttfb_ms,
            total_ms=total_ms,
            headers_subset=subset_headers(resp.headers),
        )

    def send(
        self,
        proto: str,
        label: str,
        req: BurpRequest,
        override_headers: Optional[List[Header]] = None,
        override_body: Optional[bytes] = None,
    ) -> Trial:
        http2 = (proto == "h2")
        client = self._client(http2=http2)

        headers = override_headers if override_headers is not None else req.headers
        body = override_body if override_body is not None else req.body

        # Pacing
        base_s = (1.0 / self.rps) if self.rps > 0 else 0.0
        jitter_sleep(base_s, self.jitter_ms)

        start = time.perf_counter()
        ttfb_ms = -1

        try:
            with client.stream(
                req.method,
                req.path,
                headers=headers_to_httpx(headers),
                content=body if req.method in ("POST", "PUT", "PATCH") else None,
            ) as r:
                if self.verbose >= 2:
                    dump_request(proto, label, r.request, max_body=self.dump_bytes)

                first = True
                collected = b""
                for chunk in r.iter_bytes():
                    if first:
                        ttfb_ms = int((time.perf_counter() - start) * 1000)
                        first = False
                    collected += chunk
                    if len(collected) >= self.max_body:
                        break

                resp = httpx.Response(
                    status_code=r.status_code,
                    headers=r.headers,
                    content=collected,
                    request=r.request,
                    extensions=r.extensions,
                )

                if self.verbose >= 2:
                    dump_response(proto, label, resp, max_body=self.dump_bytes)

            total_ms = int((time.perf_counter() - start) * 1000)
            if ttfb_ms < 0:
                ttfb_ms = total_ms

            return Trial(ok=True, error=None, fp=self._fingerprint(resp, ttfb_ms, total_ms))

        except Exception as e:
            return Trial(ok=False, error=f"{type(e).__name__}: {e}", fp=None)

        finally:
            if not self.keepalive:
                try:
                    client.close()
                except Exception:
                    pass


# -----------------------------
# Analysis
# -----------------------------

def baseline_from_trials(trials: List[Trial]) -> Baseline:
    status_counts: Dict[int, int] = {}
    body_hash_counts: Dict[str, int] = {}
    samples = 0

    for t in trials:
        if not t.ok or not t.fp:
            continue
        samples += 1
        status_counts[t.fp.status_code] = status_counts.get(t.fp.status_code, 0) + 1
        body_hash_counts[t.fp.body_sha256] = body_hash_counts.get(t.fp.body_sha256, 0) + 1

    return Baseline(status_counts=status_counts, body_hash_counts=body_hash_counts, samples=samples)


def divergence_score(base: Baseline, fp: Fingerprint) -> float:
    # Simple explainable score in [0, 1]
    score = 0.0
    if fp.status_code not in base.status_counts:
        score += 0.5
    if fp.body_sha256 not in base.body_hash_counts:
        score += 0.5
    return min(1.0, score)


# -----------------------------
# Variants (keeps your existing set; does not add new exploit-y payloads)
# -----------------------------

def build_variants() -> List[Variant]:
    return [
        Variant(
            id="cl_te_classic",
            description="Adds CL then TE (as captured).",
            extra_headers=[Header("Content-Length", "6"), Header("Transfer-Encoding", "chunked")],
            body_append=b"\r\n0\r\n\r\n",
        ),
        Variant(
            id="te_cl",
            description="Adds TE then CL (as captured).",
            extra_headers=[Header("Transfer-Encoding", "chunked"), Header("Content-Length", "13")],
            body_append=b"5\r\nabcde\r\n0\r\n\r\n",
        ),
        Variant(
            id="double_cl",
            description="Adds two CL then TE (as captured).",
            extra_headers=[
                Header("Content-Length", "6"),
                Header("Content-Length", "200"),
                Header("Transfer-Encoding", "chunked"),
            ],
            body_append=b"\r\n0\r\n\r\n",
        ),
        Variant(
            id="te_zero",
            description="Adds TE and immediate zero chunk (as captured).",
            extra_headers=[Header("Transfer-Encoding", "chunked")],
            body_append=b"0\r\n\r\n",
        ),
    ]


def merged_headers(original: List[Header], extra: List[Header]) -> List[Header]:
    # Header order can matter for intermediaries: keep "extra first" like your original script.
    # Preserve duplicates; do NOT dedupe.
    return extra + original


# -----------------------------
# CLI / Main
# -----------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="HTTP/1.1 vs HTTP/2 differential tester (authorized use only).")
    p.add_argument("url", help="Base URL e.g. https://example.com")
    p.add_argument("burp_file", help="Burp-captured request text file")
    p.add_argument("--ack", required=True, help='Must be exactly: "I am authorized"')
    p.add_argument("--baseline", type=int, default=5, help="Baseline samples per protocol")
    p.add_argument("--trials", type=int, default=3, help="Trials per variant per protocol")
    p.add_argument("--max-requests", type=int, default=60, help="Hard cap on total requests")
    p.add_argument("--timeout", type=float, default=15.0)
    p.add_argument("--rps", type=float, default=1.0)
    p.add_argument("--jitter-ms", type=int, default=200)
    p.add_argument("--keepalive", action="store_true", help="Enable keep-alive (off by default)")
    p.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    p.add_argument("--max-body", type=int, default=200_000, help="Max bytes to read per response")
    p.add_argument("--json-out", default="", help="Write JSON report to file")
    p.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Verbose output (-v = progress, -vv = request/response dumps)",
    )
    p.add_argument(
        "--dump-bytes",
        type=int,
        default=1000,
        help="When using -vv, dump at most this many bytes of request/response body",
    )
    return p.parse_args()


def main() -> int:
    args = parse_args()
    if args.ack.strip() != "I am authorized":
        print('Refusing to run. Use --ack "I am authorized"')
        return 2

    base_url = sanitize_base_url(args.url)
    req = read_burp_request(args.burp_file)

    if args.verbose:
        print(f"🎯 TARGET: {base_url}{req.path}")
        print(f"📄 METHOD: {req.method} | HTTP VERSION (captured): {req.version}")
        print(f"📦 Headers: {len(req.headers)} (order+dupes preserved) | Body: {len(req.body)} bytes")

    harness = DiffHarness(
        base_url=base_url,
        timeout_s=args.timeout,
        rps=args.rps,
        jitter_ms=args.jitter_ms,
        max_body=args.max_body,
        keepalive=args.keepalive,
        verify_tls=not args.insecure,
        user_agent="desync-diff/2.1",
        verbose=args.verbose,
        dump_bytes=args.dump_bytes,
    )

    report: Dict[str, object] = {
        "timestamp": now_iso(),
        "target": base_url,
        "request": {"method": req.method, "path": req.path, "http_version": req.version},
        "config": {
            "baseline": args.baseline,
            "trials": args.trials,
            "timeout_s": args.timeout,
            "rps": args.rps,
            "jitter_ms": args.jitter_ms,
            "keepalive": args.keepalive,
            "verify_tls": not args.insecure,
            "max_requests": args.max_requests,
            "max_body": args.max_body,
        },
        "baseline_summaries": {},
        "variants": [],
    }

    budget = args.max_requests

    def take(n: int) -> bool:
        nonlocal budget
        budget -= n
        return budget >= 0

    # Baseline per protocol
    baselines: Dict[str, Baseline] = {}
    for proto in ("h1", "h2"):
        trials: List[Trial] = []
        for i in range(args.baseline):
            if not take(1):
                break
            label = f"baseline#{i+1}"
            if args.verbose:
                print(f"🧪 {label} ({proto.upper()})")
            trials.append(harness.send(proto, label, req))
        baselines[proto] = baseline_from_trials(trials)
        report["baseline_summaries"][proto] = dataclasses.asdict(baselines[proto])

    # Variants
    variants = build_variants()
    for v in variants:
        entry = {"id": v.id, "description": v.description, "results": {}}
        for proto in ("h1", "h2"):
            proto_trials: List[Dict[str, object]] = []
            for i in range(args.trials):
                if not take(1):
                    break
                label = f"{v.id}#{i+1}"
                if args.verbose:
                    print(f"🧪 {label} ({proto.upper()})")

                hdrs = merged_headers(req.headers, v.extra_headers)
                body = (req.body or b"") + v.body_append

                tr = harness.send(proto, label, req, override_headers=hdrs, override_body=body)
                if tr.ok and tr.fp:
                    score = divergence_score(baselines[proto], tr.fp)
                    proto_trials.append({"ok": True, "fp": dataclasses.asdict(tr.fp), "divergence": score})
                else:
                    proto_trials.append({"ok": False, "error": tr.error})

            entry["results"][proto] = proto_trials
        report["variants"].append(entry)

    out = json.dumps(report, indent=2)
    print(out)

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            f.write(out + "\n")
        if args.verbose:
            print(f"📝 Wrote report to {args.json_out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
