import requests
fname = "payloads.txt"
with open(fname) as f:
    content = f.readlines()
# you may also want to remove whitespace characters like `\n` at the end of each line
payloads = [x.strip() for x in content] 
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


