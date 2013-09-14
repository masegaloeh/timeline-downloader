#!/usr/bin/env python3
# python 3
# This code was working (at least). But this code wasn't neatly writing. So I plan to write it more neatly, soon
# Anyway, please edit this 4 variable
#   consumer_secret = 'xxxxx'
#   consumer_key = 'xxxxx'
#   oauth_access_token_secret = 'xxxxx'
#   oauth_access_token = 'xxxxx'
# This program have 1 parameter and 1 optional parameter.
# More info ./this-script.py -h

from time import time
from hashlib import sha1
import base64
import collections
import urllib.parse
import hmac
import binascii
import random
import json
import subprocess
import re
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("screen_name",
                    help="display a square of a given number")
parser.add_argument("-o", "--output",
                    help="specify output file")
args = parser.parse_args()


username = args.screen_name
if args.output:
    fileout = args.output
else:
    fileout = username + ".tw"



def buildBaseString(baseURI, method, params):
    myarray = []
    oparams = collections.OrderedDict(sorted(params.items()))
    for key, val in oparams.items():
        #print(str(key) + " " + str(val))
        myarray.append(key + "=" + urllib.parse.quote(str(val)))
    return method + "&" + urllib.parse.quote(baseURI,'') + "&" + urllib.parse.quote('&'.join(myarray))

def buildAuthorizationHeader(oauth):
    retval = 'Authorization: OAuth '
    myarray = []
    oparams = collections.OrderedDict(sorted(oauth.items()))
    for key, val in oparams.items():
        if 'oauth' in key:
            myarray.append(key + "=\"" + urllib.parse.quote(str(val)) + "\"")
    return retval + ", ".join(myarray)

def BuildUrl(oauth):
    myarray = []
    oparams = collections.OrderedDict(sorted(oauth.items()))
    for key, val in oparams.items():
        if not('oauth' in key):
            myarray.append(key + "=" + urllib.parse.quote(str(val)))
    return "&".join(myarray)

def getJson(screen_name, max_id=0):
    # define
    url = 'https://api.twitter.com/1.1/statuses/user_timeline.json'
    consumer_secret = 'xxxxx'
    consumer_key = 'xxxxx'
    oauth_access_token_secret = 'xxxxx'
    oauth_access_token = 'xxxxx'
    LIMIT = 150

    oauth = {
        'count': LIMIT,
        'screen_name': screen_name,
        'include_rts': 'true',
        'oauth_consumer_key': consumer_key,
        'oauth_nonce':    sha1(str(random.random()).encode('ascii')).hexdigest(),
        'oauth_signature_method': 'HMAC-SHA1',
        'oauth_token': oauth_access_token,
        'oauth_timestamp': int(time()),
        'oauth_version': '1.0'
    }

    if max_id != 0:
        oauth['max_id'] = str(max_id)

    base_info = buildBaseString(url, 'GET', oauth).encode()
    composite_key = (urllib.parse.quote(consumer_secret) + '&' + urllib.parse.quote(oauth_access_token_secret)).encode()
    oauth_signature = binascii.b2a_base64(hmac.new(composite_key, base_info, sha1).digest()).rstrip().decode()
    oauth['oauth_signature'] = oauth_signature

    #curlget = 'curl --get "' + url + '" --data "' + BuildUrl(oauth) + '" --header \'' + buildAuthorizationHeader(oauth) + '\''
    curlp = subprocess.Popen(["curl", "-s", "--get", url, "--data", BuildUrl(oauth), "--header", buildAuthorizationHeader(oauth)], stdout=subprocess.PIPE)
    (out, err) = curlp.communicate()
    return out
    #return curlget

#print(getJson('nginxorg',376169300735700992))
max_id = 0
n_out = 2
counter = 25
fo = open(fileout, "w")
fo.write("<pre>")
while n_out > 1:
    if max_id <= 0 :
        jsonout = getJson(username)
    else:
        jsonout = getJson(username, max_id)
    #print(type(jsonout))
    tweetdict = json.loads(jsonout.decode("utf-8"))
    #print(tweetdict)
    n_out = len(tweetdict)
    #break
    if max_id == tweetdict[0]['id']:
        del tweetdict[0]

    if n_out > 1:
        for tweet in tweetdict:  
            max_id = tweet['id']
            text = None
            try:
                tweet['retweeted_status']['user']['screen_name']
            except:
                text = tweet['text']

            if  text is None:
                text = "[RT] " + tweet['retweeted_status']['text']
            my = re.sub(r'(http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+)', r'<a href="\1">\1</a>', text)
            my = re.sub(r'(?<=^|(?<=[^a-zA-Z0-9-_\.]))@([A-Za-z]+[A-Za-z0-9]+)', r'<a href="http://twitter.com/\1">@\1</a>', my)
            fo.write(my.encode('ascii','ignore').decode())
            fo.write("\n")
            fo.write("\n")
            #print(line)
            #print("")

    counter = counter - 1
    if counter < 1:
        break
