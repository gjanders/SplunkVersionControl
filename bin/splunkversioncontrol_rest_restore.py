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
import time
import calendar
from splunkversioncontrol_restore_class import SplunkVersionControlRestore

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

"""
    Receive a POST request with a Splunk authentication token from a (potentially) remote instance
    Check the remote instance (remote IP of incoming request) for the username of the requester by using this token
    Then if a valid splunk backup configuration stanza is found, run a remote check against it to see if the user
    who remotely queried this instance did actually send the query (by running a report against the audit logs)
    Finally, if this passes attempt to restore the object and return the results to the remote caller
"""


class SVCRestore(splunk.rest.BaseRestHandler):

    def handle_POST(self):
        starttime = calendar.timegm(time.gmtime())
        payload = urlparse.parse_qs(self.request['payload'])
        #self.response.write(str(payload) + "\n")
        #currently we only receive the Splunk authorization key, so obtain that
        
        req_attributes = ['Authorization', 'splunk_vc_name', 'app', 'type', 'obj_name', 'tag', 'scope' ]
        for attr in req_attributes:
            if attr not in payload:
                #Don't log the authorization key if it was sent
                if 'Authorization' in payload:
                    del payload['Authorization']
                logger.error("Received remote call but attr=%s was missing from arguments, received=\"%s\"" % (attr, payload))
                self.response.write("Received remote call but attr=%s was missing from arguments, received=\"%s\"" % (attr, payload))
                return
        
        headers = { "Authorization" : payload['Authorization'][0] }

        #Run a query back against the source system to check the username/role
        remoteAddr = self.request['remoteAddr']
        url = "https://" + remoteAddr + ":8089/services/authentication/current-context?output_mode=json"
        logger.info("Received remote request checking username and role related to the token on url=%s" % (url))
        logger.debug("token=%s" % (payload['Authorization'][0]))
        res = requests.get(url, verify=False, headers=headers)
        if (res.status_code != requests.codes.ok):
            logger.error("Unexpected response code while checking username with token on url=%s, statuscode=%s reason=%s, response=\"%s\"" % (url, res.status_code, res.reason, res.text))
            self.response.write("Error unexpected response code while checking username with token on url %s (based on incoming ip address), statuscode=%s reason=%s, response=\"%s\"" % (url, res.status_code, res.reason, res.text))
            return
        
        json_dict = json.loads(res.text) 
        #self.response.write(str(json_dict) + "\n\n\n")
        username = json_dict['entry'][0]['content']['username']
        roles = json_dict['entry'][0]['content']['roles']

        #self.response.write(username + "\n")
        #self.response.write(str(roles) + "\n")
        logger.info("username=%s roles=%s" % (username, roles))
        
        splunk_vc_name = payload['splunk_vc_name'][0]
        #self.response.write(splunk_vc_name + "\n\n\n")
        
        #Now run queries locally to check if the mentioned config matches an existing backup name
        headers = { "Authorization" : "Splunk " + self.request['systemAuth'] }
        url = "https://localhost:8089/servicesNS/-/-/data/inputs/splunkversioncontrol_restore/" + urllib.quote(splunk_vc_name) + "?output_mode=json"
        logger.debug("Now running query against url=%s to obtain config information" % (url))
        
        res = requests.get(url, verify=False, headers=headers)
        if (res.status_code != requests.codes.ok):
            logger.error("Unexpected response code while querying the inputs for splunkversioncontrol_restore with name %s, on url %s, statuscode=%s reason=%s, response=\"%s\"" % (splunk_vc_name, url, res.status_code, res.reason, res.text))
            self.response.write("Error unexpected response code while querying the inputs for splunkversioncontrol_restore with name %s, on url %s, statuscode=%s reason=%s, response=\"%s\"" % (splunk_vc_name, url, res.status_code, res.reason, res.text))
            return
        
        #Look under the entry/content section for the relevant information we require, mainly destURL, useLocalAuth and potentially destUsername/destPassword
        json_dict = json.loads(res.text)['entry'][0]['content']
        #self.response.write(str(json_dict) + "\n\n\n")
        
        useLocalAuth = False
        if 'useLocalAuth' in json_dict:
            if json_dict['useLocalAuth'].lower() == 't' or json_dict['useLocalAuth'].lower() == "true":
                useLocalAuth = True
        
        if not useLocalAuth:
            if not 'destUsername' in json_dict or not 'destPassword' in json_dict or not 'destURL' in json_dict:
                logger.error("Missing one of destUsername, destPassword or destURL from the splunk version control restore stanza, and useLocalAuth is not true, invalid configuration")
                self.response.write("Missing one of destUsername, destPassword or destURL from the splunk version control restore stanza, and useLocalAuth is not true, invalid configuration")
                return
            destUsername = json_dict['destUsername']
            destPassword = json_dict['destPassword']
        else:
            if not 'destURL' in json_dict:
                logger.error("Missing one of destURL from the splunk version control restore stanza, invalid configuration")
                self.response.write("Missing destURL from the splunk version control restore stanza, invalid configuration")
                return

        destURL = json_dict['destURL']

        headers = {}
        auth = None
        
        if useLocalAuth:
            headers = { "Authorization" : "Splunk " + self.request['systemAuth'] }
        else:
            auth = HTTPBasicAuth(destUsername, destPassword)

        if 'remoteAppName' in json_dict and json_dict['remoteAppName']!="":
            remoteAppName = json_dict['remoteAppName']
        else:
            remoteAppName = "SplunkVersionControl"
        
        app = payload['app'][0]
        type = payload['type'][0]
        obj_name = payload['obj_name'][0]
        tag = payload['tag'][0]
        
        if not 'restoreAsUser' in payload:
            restoreAsUser = ''
        else:
            restoreAsUser = payload['restoreAsUser'][0]
        scope = payload['scope'][0]
        
        #We need a little bit of time to index the _audit event that literally just happened
        #a 30 second delay is annoying but it appears to work...hardcoding this for now
        logger.info("Sleeping for 30 seconds to wait for audit logs")
        time.sleep(30)
        logger.info("Sleep completed")
        #At this point we run a POST request to check the audit logs and ensure the user is allowed to run a restore....
        #TODO make this a POST request on the correct URL endpoint for the app?
        starttime = starttime-60
        #FIXME
        json_res = self.runSearchJob(destURL, remoteAppName, headers, auth, username, starttime)

        if 'error' in json_res:
            self.response.write("An error occurred: %s" % (json_res['error']))
            return
        if len(json_res['results']) == 0:
            logger.warn("No matching results for audit query using username=%s, remoteAppName=%s on url=%s with starttime of %s" % (username, remoteAppName, destURL, starttime))
            self.response.write("No matching results for audit query using username=%s, remoteAppName=%s on url=%s with starttime of %s" % (username, remoteAppName, destURL, starttime))
            return
        else:
            #we are at the point where we checked the remote instance and confirmed the user in question was allowed to request a restore, pass control
            #to the restore class to attempt the actual restore
            svc_restore_obj = SplunkVersionControlRestore()
            resList = [{ 'app' : app, 'type': type, 'name': obj_name, 'tag': tag, 'scope': scope, 'time': starttime, 'restoreAsUser': restoreAsUser, 'user': username }]
            #Name is required as part of the config dictionary, session_key is used if useLocalAuth is true in the config
            json_dict['name'] = "splunkversioncontrol_restore://" + splunk_vc_name
            json_dict['session_key'] = self.request['systemAuth']
            result = svc_restore_obj.run_script(resList, json_dict)
            if result:
                self.response.write("Restore has completed successfully in app %s, object of type %s, with name %s was restored from tag %s, scope %s with restoreAsUser %s and your username of %s" % (app, type, obj_name, tag, scope, restoreAsUser, username))
                logger.info("Restore has completed successfully in app=%s, object of type=%s, with name=%s was restored from tag=%s, scope=%s with restoreAsUser=%s and requested by username=%s" % (app, type, obj_name, tag, scope, restoreAsUser, username))
            else:
                self.response.write("Restore has failed to complete successfully in app %s, object of type %s, with name %s was restored from tag %s, scope %s with restoreAsUser %s and your username of %s" % (app, type, obj_name, tag, scope, restoreAsUser, username))
                logger.warn("Restore has failed to successfully in app=%s, object of type=%s, with name=%s was restored from tag=%s, scope=%s with restoreAsUser=%s and requested by username=%s" % (app, type, obj_name, tag, scope, restoreAsUser, username))    

    #Run a Splunk query via the search/jobs endpoint
    def runSearchJob(self, url, appname, headers, auth, username, earliest_time):
        url = url + "/servicesNS/-/%s/search/jobs" % (appname)
        query = "savedsearch \"Splunk Version Control Audit Query POST\" username=\"%s\" | stats count | where count>0" % (username)
        logger.debug("Running requests.post() on url=%s query=\"%s\"" % (url, query))
        data = { "search" : query, "output_mode" : "json", "exec_mode" : "oneshot", "earliest_time" : earliest_time }
        
        res = requests.post(url, auth=auth, headers=headers, verify=False, data=data)
        if (res.status_code != requests.codes.ok):
            logger.error("url=%s status_code=%s reason=%s, response=\"%s\"" % (url, res.status_code, res.reason, res.text))
            return { "error": "url=%s status_code=%s reason=%s, response=\"%s\"" % (url, res.status_code, res.reason, res.text) } 
        res = json.loads(res.text)
        
        #Log return messages from Splunk, often these advise of an issue but not always...
        if len(res["messages"]) > 0:
            firstMessage = res["messages"][0]
            if 'type' in firstMessage and firstMessage['type'] == "INFO":
                #This is a harmless info message ,most other messages are likely an issue
                logger.info("messages from query=\"%s\" were messages=\"%s\"" % (query, res["messages"]))
            else:
                logger.warn("messages from query=\"%s\" were messages=\"%s\"" % (query, res["messages"]))
        return res
