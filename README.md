
# HTTP Desync Tester 🧪

**HTTP Request Smuggling (HTTP/1.1→HTTP/2) testing tool**

Test HTTP Desync vulnerabilities between **Burp Suite proxy (HTTP/1.1)** and **origin server (HTTP/2)** by mutating your captured requests.

## 🚀 Features

- ✅ **Preserves original method** (GET/POST/PUT/PATCH) - no more 405s!
- ✅ **Smart GET-first strategy** + POST fallback for GET-only endpoints
- ✅ **4 core smuggling variants**:
  - `CL.TE` (Classic)
  - `TE.CL` 
  - `Double CL.TE`
  - `TE.ZeroChunk`
- ✅ **Keeps ALL original headers** (Auth, Cookies, User-Agent)
- ✅ **Automatic vulnerability detection**:
  - Timeouts (>30s)
  - Proxy blocks (4xx)
  - Server errors (5xx)
  - Response size anomalies
- ✅ **macOS compatible** (urllib3<2 + SSL fixes)
- ✅ **Baseline testing** (original request unchanged)

## 📋 Requirements

```bash
Python 3.8+
requests
urllib3

pip3 install requests urllib3 h2
```

## 🎯 Quick Start

- Capture request in Burp → Copy to file → burp_get.txt
- Run tests:
  ```bash
  python3 desync.py http://target.com burp_get.txt
  ```

- Example output:
  ```bash
  🎯 TARGET: http://target.com/api/users
  📄 ORIGINAL METHOD: GET

  🧪 BASELINE: Original Burp request ✓ 200 | 0.3s
  ================================================================================
  🧪 CL.TE CLASSIC
  🎯 Trying GET smuggling...
  🚨 VULN! 413 | 45.2s | 47B  🔥 CONFIRMED!
  ================================================================================
  🎯 SUMMARY: 3/4 tests vulnerable
  🔥 CONFIRMED: HTTP Desync Vulnerable!
  ```

## 🛠️ Usage
```bash
python3 desync.py <target_url> <burp_file.txt> [options]

# Full example
python3 desync.py http://api.target.com/users burp_request.txt -t 45 -v
```

## 📁 Burp Request Format
Works with ANY valid Burp request (GET/POST/PUT):
```bash
POST /api/users HTTP/1.1
Host: target.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Cookie: session=abc123
User-Agent: Mozilla/5.0...

{"user_id": 123}
```

## 🎭 Test Variants Explained
| Test | Headers | Body | Attack |
| ---- | ------- | ---- | ------ |
| CL.TE | CL:6TE:chunked | 0\r\n\r\n | "Proxy reads 6B origin waits on chunked" |
| TE.CL | TE:chunkedCL:13 | 5\r\nabcde\r\n0\r\n\r\n | Reverse header parsing order |
| Double CL | CL:6CL:200TE:chunked | 0\r\n\r\n | Which CL does proxy/origin obey? |
| TE.Zero | TE:chunked | 0\r\n\r\n | Premature body termination |

