import json, urllib, argparse, hashlib, re, sys, hashlib,time
from pprint import pprint
try:
    import urllib.request as urllib2
except ImportError:
    import urllib2
apikey="-- YOUR API KEY --"
url = "https://www.virustotal.com/vtapi/v2/file/report"

def checkhash(sha,vendor):
 parameters = {"resource": sha, "apikey": apikey}
 data = urllib.parse.urlencode(parameters).encode("utf-8")
 req = urllib2.Request(url, data)
 response = urllib2.urlopen(req).read().decode("utf-8")
 response_dict = json.loads(response)
 print (sha,response_dict.get("scans",{}).get(vendor,{}))
 #print(response)
 time.sleep(15)

hashes = ["52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c"]
for hash in hashes:
 checkhash(hash,"AV Vendor")