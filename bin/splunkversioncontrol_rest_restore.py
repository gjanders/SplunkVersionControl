import splunk
import json
import traceback
import requests
from requests.auth import HTTPBasicAuth
import logging
from logging.config import dictConfig
import os
import time
import calendar
import sys
import splunk.rest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

from splunklib import six

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "bin"))
from splunkversioncontrol_restore_class import SplunkVersionControlRestore
from splunkversioncontrol_utility import get_password

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

    def query_back_for_user_and_permissions(self, requestingAddress, authorization_token, sslVerify):
        headers = { "Authorization" : authorization_token }

        #Run a query back against the source system to check the username/role
        if requestingAddress:
            remoteAddr = requestingAddress
        else:
            remoteAddr = "https://" + self.request['remoteAddr'] + ":8089"
        url = remoteAddr + "/services/authentication/current-context?output_mode=json"
        logger.info("Received remote request checking username and role related to the token on url=%s" % (url))
        logger.debug("token=%s" % (authorization_token))

        res = self.runHttpRequest(url, headers, None, "get", "checking username with token (based on incoming ip address)", sslVerify=sslVerify)
        if not res:
            return

        json_dict = json.loads(res.text)
        #self.response.write(str(json_dict) + "\n\n\n")
        username = json_dict['entry'][0]['content']['username']
        roles = json_dict['entry'][0]['content']['roles']
        return username, roles


    def handle_POST(self):
        starttime = calendar.timegm(time.gmtime())
        payload = six.moves.urllib.parse.parse_qs(self.request['payload'])
        #self.response.write(str(payload) + "\n")
        #currently we only receive the Splunk authorization key, so obtain that

        req_attributes = ['Authorization', 'splunk_vc_name', 'app', 'type', 'obj_name', 'tag', 'scope', 'timeout' ]
        for attr in req_attributes:
            if attr not in payload:
                #Don't log the authorization key if it was sent
                if 'Authorization' in payload:
                    del payload['Authorization']
                logger.error("Received remote call but attr=%s was missing from arguments, received=\"%s\"" % (attr, payload))
                self.response.write("Received remote call but attr=%s was missing from arguments, received=\"%s\"" % (attr, payload))
                return


        splunk_vc_name = payload['splunk_vc_name'][0]
        #self.response.write(splunk_vc_name + "\n\n\n")

        #Now run queries locally to check if the mentioned config matches an existing backup name
        headers = { "Authorization" : "Splunk " + self.request['systemAuth'] }
        url = "https://localhost:8089/servicesNS/-/-/data/inputs/splunkversioncontrol_restore/" + six.moves.urllib.parse.quote(splunk_vc_name) + "?output_mode=json"
        logger.debug("Now running query against url=%s to obtain config information" % (url))

        res = self.runHttpRequest(url, headers, None, "get", "querying the inputs for splunkversioncontrol_restore with name %s" % (splunk_vc_name), sslVerify=False)
        if not res:
            return

        #Look under the entry/content section for the relevant information we require, mainly destURL, useLocalAuth and potentially destUsername/destPassword
        json_dict = json.loads(res.text)['entry'][0]['content']
        #self.response.write(str(json_dict) + "\n\n\n")

        useLocalAuth = False
        if 'useLocalAuth' in json_dict:
            useLocalAuth = json_dict['useLocalAuth']
            if isinstance(useLocalAuth, bool) and useLocalAuth:
                useLocalAuth = True
            elif isinstance(useLocalAuth, bool) and not useLocalAuth:
                pass
            elif useLocalAuth.lower() == 't' or useLocalAuth.lower() == "true":
                useLocalAuth = True
        if not useLocalAuth:
            if not 'destUsername' in json_dict or not 'destPassword' in json_dict or not 'destURL' in json_dict:
                logger.error("Missing one of destUsername, destPassword or destURL from the splunk version control restore stanza, and useLocalAuth is not true, invalid configuration")
                self.response.write("Missing one of destUsername, destPassword or destURL from the splunk version control restore stanza, and useLocalAuth is not true, invalid configuration")
                return
            destUsername = json_dict['destUsername']
            destPassword = json_dict['destPassword']
            if destPassword.find("password:") == 0:
                destPassword = get_password(destPassword[9:], self.request['systemAuth'], logger)            
        else:
            if not 'destURL' in json_dict:
                logger.error("Missing one of destURL from the splunk version control restore stanza, invalid configuration")
                self.response.write("Missing destURL from the splunk version control restore stanza, invalid configuration")
                return

        destURL = json_dict['destURL']

        sslVerify = False
        if 'sslVerify' in json_dict:
            sslVerifyValue = json_dict['sslVerify']
            if isinstance(sslVerifyValue, bool) and sslVerifyValue:
                useLocalAuth = True
            elif isinstance(sslVerifyValue, bool) and not sslVerifyValue:
                pass
            elif sslVerifyValue.lower() == 'true' or sslVerifyValue == "1":
                sslVerify = True
                logger.debug('sslverify set to boolean True from: ' + sslVerifyValue)
            elif sslVerifyValue.lower() == 'false' or sslVerifyValue == "0":
                sslVerify = False
                logger.debug('sslverify set to boolean False from: ' + sslVerifyValue)
            else:
                sslVerify = sslVerifyValue
                logger.debug('sslverify set to: %s' % (sslVerifyValue))

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

        if 'timewait' in json_dict and json_dict['timewait'] != '':
            try:
                time_wait = int(json_dict['timewait'])
            except ValueError:
                logger.warn("Time wait value of %s is invalid, not an integer, defaulting to 600 seconds" % (json_dict['timewait']))
                time_wait = 600
        else:
            time_wait = 600

        if 'requestingAddress' in payload and payload['requestingAddress'][0].lower() != 'false':
            requestingAddress = payload['requestingAddress'][0]
        else:
            requestingAddress = None

        username, roles = self.query_back_for_user_and_permissions(requestingAddress, payload['Authorization'][0], sslVerify=sslVerify)
        logger.info("username=%s roles=%s" % (username, roles))

        app = payload['app'][0]
        obj_type = payload['type'][0]
        obj_name = payload['obj_name'][0]
        tag = payload['tag'][0]
        timeout = payload['timeout'][0]

        if not 'restoreAsUser' in payload:
            restoreAsUser = ''
        else:
            restoreAsUser = payload['restoreAsUser'][0]
        scope = payload['scope'][0]

        logger.debug("Converting timeout of argument %s to integer" % timeout)
        timeout = int(timeout)
        #We need a little bit of time to index the _audit event that literally just happened
        #a 30 second delay is annoying but it appears to work...hardcoding this for now
        logger.info("Sleeping for %s seconds to wait for audit logs" % (timeout))
        time.sleep(timeout)
        logger.info("Sleep completed")

        starttime = starttime-60-timeout

        json_res = self.runSearchJob(destURL, remoteAppName, headers, auth, username, starttime, sslVerify=sslVerify)

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
            resList = [{ 'app' : app, 'type': obj_type, 'name': obj_name, 'tag': tag, 'scope': scope, 'time': starttime, 'restoreAsUser': restoreAsUser, 'user': username }]
            #Name is required as part of the config dictionary, session_key is used if useLocalAuth is true in the config
            json_dict['name'] = "splunkversioncontrol_restore://" + splunk_vc_name
            json_dict['session_key'] = self.request['systemAuth']

            #Check current time and see if anyone is running a restore
            headers = { "Authorization" : "Splunk " + self.request['systemAuth'] }
            curtime = calendar.timegm(time.gmtime())
            url = "https://localhost:8089/servicesNS/nobody/" + remoteAppName + "/storage/collections/data/splunkversioncontrol_rest_restore_status"
            res = self.runHttpRequest(url, headers, None, "get", "checking kvstore collection splunkversioncontrol_rest_restore_status", sslVerify=False)
            if not res:
                return

            res = json.loads(res.text)
            res = ""
            #An empty list is good in this case, we are safe to run, if not we have checks to do
            if not len(res) == 0:
                if not 'start_time' in res[0]:
                    logger.warn("Warning invalid kvstore data, will wipe it and continue in collection splunkversioncontrol_rest_restore_status on url=%s, value returned res=\"%s\"" % (url, payload))
                    self.runHttpRequest(url, headers, None, 'delete', 'wiping kvstore splunkversioncontrol_rest_restore_status', sslVerify=False)
                else:
                    kvstore_start_time = res[0]['start_time']
                    target_time = curtime - time_wait
                    if kvstore_start_time < target_time:
                        logger.warn("Found existing entry from %s but time is %s, this is past the limit of current time minus %s (%s)" % (kvstore_start_time, curtime, time_wait, target_time))
                        #More than 10 minutes ago, delete the entry and move on
                        self.runHttpRequest(url, headers, None, "delete", "wiping kvstore splunkversioncontrol_rest_restore_status due to record %s older than %s time period" % (kvstore_start_time, target_time), sslVerify=False)
                    else:
                        removal_target = kvstore_start_time + time_wait + 1
                        logger.warn("Attempted to run but found a running restore instance with time=%s and current_time=%s, will delete and move on after current_time_minus=%s seconds (override_time=%s)" % (kvstore_start_time, curtime, time_wait, removal_target))
                        self.response.write("Attempted to run but found a running restore instance with time %s and current time is %s, will delete and move on after current time minus %s seconds (which would be %s) " % (kvstore_start_time, curtime, time_wait, removal_target))
                        self.response.write("Please try your restore request again in a minute...")
                        return

            payload = json.dumps({ 'start_time': curtime })
            headers['Content-Type'] = 'application/json'
            #update kvstore with runtime
            res = self.runHttpRequest(url, headers, payload, 'post', 'updating kvstore collection splunkversioncontrol_rest_restore_status', sslVerify=False)
            if not res:
                return

            (result, message) = svc_restore_obj.run_script(resList, json_dict)
            if result == True:
                self.response.write("Restore has completed successfully in app %s, object of type %s, with name %s was restored from tag %s, scope %s with restoreAsUser %s and your username of %s" % (app, obj_type, obj_name, tag, scope, restoreAsUser, username))
                logger.info("Restore has completed successfully in app=%s, object of type=%s, with name=%s was restored from tag=%s, scope=%s with restoreAsUser=%s and requested by username=%s" % (app, obj_type, obj_name, tag, scope, restoreAsUser, username))
            else:
                self.response.write("Restore has failed to complete successfully in app %s, object of type %s, with name %s, from tag %s, scope %s with restoreAsUser %s and your username of %s. Message is %s" % (app, obj_type, obj_name, tag, scope, restoreAsUser, username, message))
                logger.warn("Restore has failed to complete successfully in app=%s, object of type=%s, with name=%s, from tag=%s, scope=%s with restoreAsUser=%s and requested by username=%s, message=%s" % (app, obj_type, obj_name, tag, scope, restoreAsUser, username, message))

            self.runHttpRequest(url, headers, None, 'delete', 'wiping kvstore splunkversioncontrol_rest_restore_status after completed run', sslVerify=False)

    #Run a Splunk query via the search/jobs endpoint
    def runSearchJob(self, url, appname, headers, auth, username, earliest_time, sslVerify=False):
        url = url + "/servicesNS/-/%s/search/jobs" % (appname)
        query = "savedsearch \"Splunk Version Control Audit Query POST\" username=\"%s\" | stats count | where count>0" % (username)
        logger.debug("Running requests.post() on url=%s query=\"%s\"" % (url, query))
        data = { "search" : query, "output_mode" : "json", "exec_mode" : "oneshot", "earliest_time" : earliest_time }

        res = requests.post(url, auth=auth, headers=headers, verify=sslVerify, data=data)
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

    def runHttpRequest(self, url, headers, data, obj_type, text, sslVerify=False):
        if obj_type == "delete":
            res = requests.delete(url, headers=headers, verify=sslVerify)
        elif obj_type == "post":
            res = requests.post(url, headers=headers, verify=sslVerify, data=data)
        elif obj_type == "get":
            res = requests.get(url, headers=headers, verify=sslVerify)

        if (res.status_code != requests.codes.ok and res.status_code != 201):
            logger.error("Unexpected response code while %s, on url=%s, statuscode=%s reason=%s, response=\"%s\", payload=\"%s\", verify=\"%s\"" % (text, url, res.status_code, res.reason, res.text, data, sslVerify))
            self.response.write("Error unexpected response code while %s, on url %s, statuscode %s reason %s, response \"%s\", payload=\"%s\", verify=\"%s\"" % (text, url, res.status_code, res.reason, res.text, data, sslVerify))
            return

        return res
