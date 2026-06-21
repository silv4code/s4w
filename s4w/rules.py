from __future__ import annotations

CWE = {
    "CWE-89": "https://cwe.mitre.org/data/definitions/89.html",
    "CWE-78": "https://cwe.mitre.org/data/definitions/78.html",
    "CWE-22": "https://cwe.mitre.org/data/definitions/22.html",
    "CWE-20": "https://cwe.mitre.org/data/definitions/20.html",
    "CWE-209": "https://cwe.mitre.org/data/definitions/209.html",
    "CWE-434": "https://cwe.mitre.org/data/definitions/434.html",
    "CWE-425": "https://cwe.mitre.org/data/definitions/425.html",
    "CWE-538": "https://cwe.mitre.org/data/definitions/538.html",
    "CWE-548": "https://cwe.mitre.org/data/definitions/548.html",
    "CWE-598": "https://cwe.mitre.org/data/definitions/598.html",
    "CWE-601": "https://cwe.mitre.org/data/definitions/601.html",
    "CWE-16": "https://cwe.mitre.org/data/definitions/16.html",
    "CWE-79": "https://cwe.mitre.org/data/definitions/79.html",
    "CWE-200": "https://cwe.mitre.org/data/definitions/200.html",
    "CWE-287": "https://cwe.mitre.org/data/definitions/287.html",
    "CWE-319": "https://cwe.mitre.org/data/definitions/319.html",
    "CWE-345": "https://cwe.mitre.org/data/definitions/345.html",
    "CWE-346": "https://cwe.mitre.org/data/definitions/346.html",
    "CWE-352": "https://cwe.mitre.org/data/definitions/352.html",
    "CWE-359": "https://cwe.mitre.org/data/definitions/359.html",
    "CWE-489": "https://cwe.mitre.org/data/definitions/489.html",
    "CWE-522": "https://cwe.mitre.org/data/definitions/522.html",
    "CWE-614": "https://cwe.mitre.org/data/definitions/614.html",
    "CWE-639": "https://cwe.mitre.org/data/definitions/639.html",
    "CWE-862": "https://cwe.mitre.org/data/definitions/862.html",
    "CWE-693": "https://cwe.mitre.org/data/definitions/693.html",
    "CWE-829": "https://cwe.mitre.org/data/definitions/829.html",
    "CWE-922": "https://cwe.mitre.org/data/definitions/922.html",
    "CWE-1004": "https://cwe.mitre.org/data/definitions/1004.html",
    "CWE-1021": "https://cwe.mitre.org/data/definitions/1021.html",
}

OWASP = {
    "access_control": "OWASP A01:2021 - Broken Access Control",
    "crypto": "OWASP A02:2021 - Cryptographic Failures",
    "injection": "OWASP A03:2021 - Injection",
    "misconfig": "OWASP A05:2021 - Security Misconfiguration",
    "vulnerable_components": "OWASP A06:2021 - Vulnerable and Outdated Components",
    "auth": "OWASP A07:2021 - Identification and Authentication Failures",
    "integrity": "OWASP A08:2021 - Software and Data Integrity Failures",
    "logging": "OWASP A09:2021 - Security Logging and Monitoring Failures",
    "ssrf": "OWASP A10:2021 - Server-Side Request Forgery",
}

DOM_SINKS = [
    "innerHTML",
    "outerHTML",
    "insertAdjacentHTML",
    "document.write",
    "document.writeln",
    "eval(",
    "new Function",
]

DOM_SOURCES = [
    "location.hash",
    "location.search",
    "document.URL",
    "document.documentURI",
    "document.referrer",
    "window.name",
]

TOKEN_WORDS = ["token", "jwt", "bearer", "auth", "session", "secret", "apikey", "api_key"]

CSRF_WORDS = ["csrf", "xsrf", "nonce", "_wpnonce", "token", "authenticity_token"]
