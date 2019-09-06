import splunk
import json
import traceback
import requests
import urlparse
import urllib
from requests.auth import HTTPBasicAuth
import logging
from logging.config import dictConfig
import os

splunkLogsDir = os.environ['SPLUNK_HOME'] + "/var/log/splunk"
#Setup the logging
logging_config = dict(
    version = 1,
    formatters = {
        'f': {'format':
              '%(asctime)s %(name)-12s %(levelname)-8s %(message)s'}
        },
    handlers = {
        'h': {'class': 'logging.StreamHandler',
              'formatter': 'f',
              'level': logging.WARN},
        'file': {'class' : 'logging.handlers.RotatingFileHandler',
              'filename' : splunkLogsDir + '/splunkversioncontrol_rest_restore.log',
              'formatter': 'f',
              'maxBytes' :  2097152,
              'level': logging.DEBUG,
              'backupCount' : 5 }
        },        
    root = {
        'handlers': ['h','file'],
        'level': logging.DEBUG,
        },
)

dictConfig(logging_config)

logger = logging.getLogger()
logging.getLogger().setLevel(logging.INFO)

class SVCRestore(splunk.rest.BaseRestHandler):

    def handle_POST(self):
        payload = urlparse.parse_qs(self.request['payload'])
        #self.response.write(str(payload) + "\n")
        #currently we only receive the Splunk authorization key, so obtain that
        
        if not 'Authorization' in payload or not 'splunk_vc_name' in payload:
            logger.error("Received remote call but either Authorization field or splunk_vc_name missing from POST arguments, exiting")
            self.response.write("Error either Authorization field or splunk_vc_name missing from POST arguments")
            return
        
        headers = { "Authorization" : payload['Authorization'][0] }

        #Run a query back against the source system to check the username/role
        remoteAddr = self.request['remoteAddr']
        url = "https://" + remoteAddr + ":8089/services/authentication/current-context?output_mode=json"
        logger.info("Received remote request checking username and role related to the token on url %s" % (url))
        logger.debug("token=%s" % (payload['Authorization'][0]))
        res = requests.get(url, verify=False, headers=headers)
        if (res.status_code != requests.codes.ok):
            logger.error("Unexpected response code while checking username with token on url %s, statuscode=%s reason=%s, response=\"%s\"" % (url, res.status_code, res.reason, res.text))
            self.response.write("Error unexpected response code while checking username with token on url %s (based on incoming ip address), statuscode=%s reason=%s, response=\"%s\"" % (url, res.status_code, res.reason, res.text))
            return
        
        json_dict = json.loads(res.text) 
        #self.response.write(str(json_dict) + "\n\n\n")
        username = json_dict['entry'][0]['content']['username']
        roles = json_dict['entry'][0]['content']['roles']

        #self.response.write(username + "\n")
        #self.response.write(str(roles) + "\n")
        logger.info("username is %s roles are %s" % (username, roles))
        
        splunk_vc_name = payload['splunk_vc_name'][0]
        #self.response.write(splunk_vc_name + "\n\n\n")
        
        #Now run queries locally to check if the mentioned config matches an existing backup name
        headers = { "Authorization" : "Splunk " + self.request['systemAuth'] }
        url = "https://localhost:8089/servicesNS/-/-/data/inputs/splunkversioncontrol_backup/" + urllib.quote(splunk_vc_name) + "?output_mode=json"
        logger.debug("Now running query against %s to obtain config information" % (url))
        
        res = requests.get(url, verify=False, headers=headers)
        if (res.status_code != requests.codes.ok):
            logger.error("Unexpected response code while querying the inputs for splunkversioncontrol_backup with name %s, on url %s, statuscode=%s reason=%s, response=\"%s\"" % (splunk_vc_name, url, res.status_code, res.reason, res.text))           
            self.response.write("Error unexpected response code while querying the inputs for splunkversioncontrol_backup with name %s, on url %s, statuscode=%s reason=%s, response=\"%s\"" % (splunk_vc_name, urlres.status_code, res.reason, res.text))
            return
        
        #Look under the entry/content section for the relevant information we require, mainly srcURL, useLocalAuth and potentially srcUsername/srcPassword
        json_dict = json.loads(res.text)['entry'][0]['content']
        self.response.write(str(json_dict) + "\n\n\n")
        
        useLocalAuth = False
        if 'useLocalAuth' in json_dict:
            if json_dict['useLocalAuth'].lower() == 't' or json_dict['useLocalAuth'].lower() == "true":
                useLocalAuth = True
        
        if not useLocalAuth:
            if not 'srcUsername' in json_dict or not 'srcPassword' in json_dict or not 'srcURL' in json_dict:
                logger.error("Missing one of srcUsername, srcPassword or srcURL from the splunk version control backup stanza, and useLocalAuth is not true, invalid configuration")
                self.response.write("Missing one of srcUsername, srcPassword or srcURL from the splunk version control backup stanza, and useLocalAuth is not true, invalid configuration")
                return
            srcUsername = json_dict['srcUsername']
            srcPassword = json_dict['srcPassword']
        else:
            if not 'srcURL' in json_dict:
                logger.error("Missing one of srcURL from the splunk version control backup stanza, invalid configuration")
                self.response.write("Missing srcURL from the splunk version control backup stanza, invalid configuration")
                return

        srcURL = json_dict['srcURL']

        headers = {}
        auth = None
        
        if useLocalAuth:
            headers = { "Authorization" : "Splunk " + self.request['systemAuth'] }
        else:
            auth = HTTPBasicAuth(srcUsername, srcPassword)

        if 'remoteAppName' in json_dict:
            remoteAppName = json_dict['remoteAppName']
        else:
            remoteAppName = "SplunkVersionControl"
        
        #At this point we run a POST request to check the audit logs and ensure the user is allowed to run a restore....
        #TODO make this a POST request on the correct URL endpoint for the app?
        url = srcURL + "/services/authentication/current-context?output_mode=json"
        res = requests.get(url, verify=False, headers=headers)
        if (res.status_code != requests.codes.ok):
            logger.error("Unexpected response code while checking username with token on url %s, statuscode=%s reason=%s, response=\"%s\"" % (url, res.status_code, res.reason, res.text))
            self.response.write("Error unexpected response code while checking username with token on url %s (based on incoming ip address), statuscode=%s reason=%s, response=\"%s\"" % (url, res.status_code, res.reason, res.text))
            return
        self.response.write(res.text)
    #handle verbs, otherwise Splunk will throw an error
    #handle_GET = handle_POST


