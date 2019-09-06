import splunk
import json
import traceback
import requests
import urllib
from requests.auth import HTTPBasicAuth

class SVCRestore(splunk.rest.BaseRestHandler):

    def handle_POST(self):
        #look at what was sent in via the POST request
        payload = urllib.unquote_plus(self.request['payload'])

        #currently we only receive the Splunk authorization key, so obtain that
        authKey = payload.split(" ")[1]
        headers = { "Authorization" : "Splunk " + authKey }
        #self.response.write(authKey + "\n")

        #Run a query back against the source system to check the username/role
        res = requests.get("https://" + self.request['remoteAddr'] + ":8089/services/authentication/current-context?output_mode=json", verify=False, headers=headers)
        json_dict = json.loads(res.text) 
        #self.response.write(str(json_dict) + "\n\n\n")
        username = json_dict['entry'][0]['content']['username']
        roles = json_dict['entry'][0]['content']['roles']

        self.response.write(username + "\n")
        self.response.write(str(roles) + "\n")

        #Now run queries locally to check if the mentioned config matches an existing backup name
        headers = { "Authorization" : "Splunk " + self.request['systemAuth'] }
        res = requests.get("https://" + self.request['remoteAddr'] + ":8089/servicesNS/-/-/data/inputs/splunkversioncontrol_backup?output_mode=json", verify=False, headers=headers)
        json_dict = json.loads(res.text)
        self.response.write(str(json_dict) + "\n\n\n")

    #handle verbs, otherwise Splunk will throw an error
    #handle_GET = handle_POST

