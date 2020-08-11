import requests
import xml.etree.ElementTree as ET
import logging
from logging.config import dictConfig
import json
import copy
import tempfile
import os
import calendar
import time
import sys
from requests.auth import HTTPBasicAuth
import xml.dom.minidom
import datetime
import shutil
from io import open
import platform
from splunkversioncontrol_utility import runOSProcess, get_password

"""
 Restore Knowledge Objects
   Query a remote lookup file to determine what items should be restored from git into a Splunk instance
   In general this will be running against the localhost unless it is been tested as the lookup file will be updated
   by a user accessible dashboard
   Basic validation will be done to ensure someone without the required access cannot restore someone else's knowledge objects
 
"""

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
              'filename' : splunkLogsDir + '/splunkversioncontrol_restore.log',
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


class SplunkVersionControlRestore:

    splunk_rest = None
    destUsername = None
    destPassword = None
    session_key = None
    gitTempDir = None
    gitRootDir = None
    appName = "SplunkVersionControl"
    gitRepoURL = None
    stanzaName = None
    
    # read XML configuration passed from splunkd
    def get_config(self):
        config = {}

        try:
            # read everything from stdin
            config_str = sys.stdin.read()

            # parse the config XML
            doc = xml.dom.minidom.parseString(config_str)
            root = doc.documentElement
            session_key = root.getElementsByTagName("session_key")[0].firstChild.data
            #Grab the session key in case we need it
            config['session_key'] = session_key
            conf_node = root.getElementsByTagName("configuration")[0]
            if conf_node:
                logger.debug("XML: found configuration")
                stanza = conf_node.getElementsByTagName("stanza")[0]
                if stanza:
                    stanza_name = stanza.getAttribute("name")
                    if stanza_name:
                        logger.debug("XML: found stanza " + stanza_name)
                        config["name"] = stanza_name
                        shortName = stanza_name.replace("splunkversioncontrol_restore://", "")
                        
                        params = stanza.getElementsByTagName("param")
                        for param in params:
                            param_name = param.getAttribute("name")
                            logger.debug("i=\"%s\" XML: found param=\"%s\"" % (shortName, param_name))
                            if param_name and param.firstChild and \
                               param.firstChild.nodeType == param.firstChild.TEXT_NODE:
                                data = param.firstChild.data
                                config[param_name] = data
                                logger.debug("i=\"%s\" XML: \"%s\"=\"%s\"" % (shortName, param_name, data))

            if not config:
                raise Exception("Invalid configuration received from Splunk.")
        except Exception as e:
            raise Exception("Error getting Splunk configuration via STDIN: %s" % str(e))
        
        return config
       
    ###########################
    #
    # runQueries (generic version)
    #   This attempts to read the config data from git (stored in json format), if found it will attempt to restore the config to the
    #   destination server
    #   This method works for everything excluding macros which have a different process
    #   Due to variations in the REST API there are a few hacks inside this method to handle specific use cases, however the majority are straightforward
    # 
    ###########################
    def runQueries(self, app, endpoint, type, name, scope, user, restoreAsUser, adminLevel):
        logger.info("i=\"%s\" user=%s, attempting to restore name=%s in app=%s of type=%s in scope=%s, restoreAsUser=%s, adminLevel=%s" % (self.stanzaName, user, name, app, type, scope, restoreAsUser, adminLevel))
        
        url = None
        #Check if the object exists or not
        #Data models require a slightly different URL to just about everything else
        if type=="datamodels" and (scope=="app" or scope=="global"):
            url = self.splunk_rest + "/servicesNS/nobody/%s%s/%s?output_mode=json" % (app, endpoint, name)
        elif type=="datamodels":
            url = self.splunk_rest + "/servicesNS/%s/%s%s/%s?output_mode=json" % (user, app, endpoint, name)
        else:
            url = self.splunk_rest + "/servicesNS/-/%s%s/%s?output_mode=json" % (app, endpoint, name)
        
        logger.debug("i=\"%s\" Running requests.get() on url=%s with user=%s in app=%s proxies_length=%s" % (self.stanzaName, url, self.destUsername, app, len(self.proxies)))

        #Determine scope that we will attempt to restore
        appScope = False
        userScope = False
        if scope == "all":
            appScope = True
            userScope = True
        elif scope == "app":
            appScope = True
        elif scope == "user":
            userScope = True
        else:
            logger.error("i=\"%s\" user=%s, while attempting to restore name=%s, found invalid scope of scope=%s" % (self.stanzaName, user, name, scope))

        headers = {}
        auth = None
        
        if not self.destUsername:
            headers={'Authorization': 'Splunk %s' % self.session_key}
        else:
            auth = HTTPBasicAuth(self.destUsername, self.destPassword)
        
        #Verify=false is hardcoded to workaround local SSL issues
        res = requests.get(url, auth=auth, headers=headers, verify=False, proxies=self.proxies)
        objExists = False
        
        #If we get 404 it definitely does not exist or it has a name override 
        if (res.status_code == 404):
            logger.debug("i=\"%s\" URL=%s is throwing a 404, assuming new object creation" % (self.stanzaName, url))
        elif (res.status_code != requests.codes.ok):
            logger.error("i=\"%s\" URL=%s in app=%s statuscode=%s reason=%s response=\"%s\"" % (self.stanzaName, url, app, res.status_code, res.reason, res.text))
        else:
            #However the fact that we did not get a 404 does not mean it exists in the context we expect it to, perhaps it's global and from another app context?
            #or perhaps it's app level but we're restoring a private object...
            logger.debug("i=\"%s\" Attempting to JSON loads on %s" % (self.stanzaName, res.text))
            resDict = json.loads(res.text)
            for entry in resDict['entry']:
                sharingLevel = entry['acl']['sharing']
                appContext = entry['acl']['app']
                if appContext == app and appScope == True and (sharingLevel == 'app' or sharingLevel == 'global'):
                    objExists = True
                elif appContext == app and userScope == True and sharingLevel == "user":
                    objExists = True
        
        configList = []
        
        foundAtAnyScope = False
        #We need to work with user scope
        if userScope == True:
            userDir = self.gitTempDir + "/" + app + "/" + "user"
            #user directory exists
            if os.path.isdir(userDir):
                typeFile = userDir + "/" + type
                if os.path.isfile(typeFile):
                    #The file exists, open it and read the config
                    logger.debug("i=\"%s\" user=%s, name=%s, found typeFile=%s to restore from" % (self.stanzaName, user, name, typeFile))
                    with open(typeFile, 'r') as f:
                        configList = json.load(f)
                        found = False
                        for configItem in configList:
                            if configItem['name'] == name or ('origName' in configItem and configItem['origName'] == name):
                                #We found the configItem we need, run the restoration
                                logger.debug("i=\"%s\" user=%s, name=%s is found, dictionary is %s" % (self.stanzaName, user, name, configItem))
                                self.runRestore(configItem, type, endpoint, app, name, user, restoreAsUser, adminLevel, objExists)
                                found = True
                                foundAtAnyScope = True
                        #Let the logs know we never found it at this scope
                        if found == False:
                            logger.info("i=\"%s\" user=%s, name=%s not found at scope=user in file=%s" % (self.stanzaName, user, name, typeFile))
                #We never found a file that we could use to restore from  at this scope
                else:
                    logger.info("i=\"%s\" user=%s, name=%s, did not find a typeFile=%s to restore from" % (self.stanzaName, user, name, typeFile))
            else:
                #There are no user level objects for this app, therefore the restore will not occur at this scope
                logger.info("i=\"%s\" user directory of dir=%s does not exist" % (self.stanzaName, userDir))
        
        #It's either app level of globally scoped
        if appScope == True:
            appDir = self.gitTempDir + "/" + app + "/" + "app"
            #app directory exists
            if os.path.isdir(appDir):
                typeFile = appDir + "/" + type
                if os.path.isfile(typeFile):
                    #The file we need exists
                    logger.debug("i=\"%s\" user=%s, name=%s, found typeFile=%s to restore from" % (self.stanzaName, user, name, typeFile))
                    with open(typeFile, 'r') as f:
                        configList = json.load(f)
                        found = False
                        for configItem in configList:
                            #We found the required configuration file, now we restore the object
                            if configItem['name'] == name:
                                logger.debug("i=\"%s\" user=%s, name=%s is found, dictionary is %s" % (self.stanzaName, user, name, configItem))
                                self.runRestore(configItem, type, endpoint, app, name, user, restoreAsUser, adminLevel, objExists)
                                found = True
                                foundAtAnyScope = True
                        #We never found the object we wanted to restore
                        if found == False:
                            logger.info("i=\"%s\" user=%s, name=%s not found at app level scope in typeFile=%s" % (self.stanzaName, user, name, typeFile))
                #We did not find the file we wanted to restore from
                else:
                    logger.info("i=\"%s\" user=%s, name=%s, did not find a typeFile=%s to restore from" % (self.stanzaName, user, name, typeFile))
            else:
                #The app level scope directory does not exist for this app
                logger.info("i=\"%s\" app directory of dir=%s does not exist" % (self.stanzaName, appDir))
            
            #If could also be a global level restore...
            globalDir = self.gitTempDir + "/" + app + "/" + "global"
            #user directory exists
            if os.path.isdir(globalDir):
                typeFile = globalDir + "/" + type
                if os.path.isfile(typeFile):
                    #We found the file to restore from
                    logger.debug("i=\"%s\" user=%s, name=%s, found typeFile=%s to restore from" % (self.stanzaName, user, name, typeFile))
                    with open(typeFile, 'r') as f:
                        configList = json.load(f)
                        found = False
                        for configItem in configList:
                            #We found the relevant piece of configuration to restore, now run the restore
                            if configItem['name'] == name:
                                logger.debug("i=\"%s\" user=%s, name=%s is found, dictionary is %s" % (self.stanzaName, user, name, configItem))
                                self.runRestore(configItem, type, endpoint, app, name, user, restoreAsUser, adminLevel, objExists)
                                found = True
                                foundAtAnyScope = True
                        #We never found the config we wanted to restore
                        if found == False:
                            logger.info("i=\"%s\" user=%s, name=%s not found at scope=global in typeFile=%s" % (self.stanzaName, user, name, typeFile))
                #This type of configuration does not exist at the global level
                else:
                    logger.info("i=\"%s\" user=%s, name=%s, did not find a typeFile=%s to restore from" % (self.stanzaName, user, name, typeFile))
            #The global directory for this app does not exist
            else:
                logger.debug("i=\"%s\" global directory of dir=%s does not exist" % (self.stanzaName, globalDir))
        
        if foundAtAnyScope == True:
            logger.info("i=\"%s\" user=%s restore has run successfully for name=%s, type=%s, restoreAsUser=%s, adminLevel=%s" % (self.stanzaName, user, name, type, restoreAsUser, adminLevel))
            return True
        else:
            logger.warn("i=\"%s\" user=%s attempted to restore name=%s, type=%s, restoreAsUser=%s, adminLevel=%s however the object was not found, the restore was unsuccessful. Perhaps check the restore date, scope & capitilisation before trying again?" % (self.stanzaName, user, name, type, restoreAsUser, adminLevel))
            return False
    
    ###########################
    #
    # runRestore (generic version)
    #   Once we have received the required configuration, type, app, endpoint, name et cetera we attempt
    #   to run the post to restore or create the object
    # 
    ###########################
    def runRestore(self, config, type, endpoint, app, name, user, restoreAsUser, adminLevel, objExists):
        result = True
        #Only an admin can restore an object owned by someone else
        if config['owner'] != user and adminLevel == False:
            logger.error("i=\"%s\" Owner of the object is listed as owner=%s, however user user=%s requested the restore and is not an admin, rejected" % (self.stanzaName, config['owner'], user))
            return False
        
        #Only an admin can use the restoreAsUser option
        if restoreAsUser != "" and restoreAsUser != user and adminLevel == False:
            logger.error("i=\"%s\" restoreAsUser=%s which is not user=%s, this user is not an admin, rejected" % (self.stanzaName))
            return False
        
        #Change the owner to the new oner
        if restoreAsUser != "" and adminLevel == True:
            config["owner"] = restoreAsUser
        
        logger.info("i=\"%s\" Attempting to run restore for name=%s of type=%s with endpoint=%s user=%s, restoreAsUser=%s, adminLevel=%s, objExists=%s" % (self.stanzaName, name, type, endpoint, user, restoreAsUser, adminLevel, objExists))

        sharing = config["sharing"]
        owner = config["owner"]

        createOrUpdate = None
        if objExists == True:
            createOrUpdate = "update"
        else:
            createOrUpdate = "create"
        
        headers = {}
        auth = None
        if not self.destUsername:
            headers={'Authorization': 'Splunk %s' % self.session_key}
        else:
            auth = HTTPBasicAuth(self.destUsername, self.destPassword)
        
        #We cannot post the sharing/owner information to the REST API, we use them later
        del config["sharing"]
        del config["owner"]
        
        #App / Global scope required the /nobody/ context to be used for POST requests (GET requests do not care)
        url = ""
        if sharing == "user":
            url = "%s/servicesNS/%s/%s%s" % (self.splunk_rest, owner, app, endpoint)
        else:
            url = "%s/servicesNS/nobody/%s%s" % (self.splunk_rest, app, endpoint)
        
        payload = config
        
        #The config has an origName in it, therefore the object exists lookup may have not worked as expected
        #repeat it here for the edge cases (field extractions, field transforms and automatic lookups)
        origName = None
        if 'origName' in config:
            origName = config['origName']
            del config['origName']
            objExistsURL = "%s/%s?output_mode=json" % (url, origName)
            logger.debug("i=\"%s\" URL=%s re-checking object exists URL due to name override from %s to original name of %s proxies_length=%s" % (self.stanzaName, objExistsURL, name, origName, len(self.proxies)))
            #Verify=false is hardcoded to workaround local SSL issues
            res = requests.get(objExistsURL, auth=auth, headers=headers, verify=False, proxies=self.proxies)
        
            #If we get 404 it definitely does not exist or it has a name override 
            if (res.status_code == 404):
                logger.debug("i=\"%s\" URL=%s is throwing a 404, assuming new object creation" % (self.stanzaName, objExistsURL))
                objExists = False
            elif (res.status_code != requests.codes.ok):
                logger.error("i=\"%s\" URL=%s in app=%s statuscode=%s reason=%s response=\"%s\"" % (self.stanzaName, objExistsURL, app, res.status_code, res.reason, res.text))
            else:
                #However the fact that we did not get a 404 does not mean it exists in the context we expect it to, perhaps it's global and from another app context?
                #or perhaps it's app level but we're restoring a private object...
                logger.debug("i=\"%s\" Attempting to JSON loads on %s" % (self.stanzaName, res.text))
                resDict = json.loads(res.text)
                for entry in resDict['entry']:
                    sharingLevel = entry['acl']['sharing']
                    appContext = entry['acl']['app']
                    appScope = False
                    userScope = False
                    if sharing == "global" or sharing == "app":
                        appScope = True
                    else:
                        userScope = True
                    if appContext == app and appScope == True and (sharingLevel == 'app' or sharingLevel == 'global'):
                        objExists = True
                    elif appContext == app and userScope == True and sharingLevel == "user":
                        objExists = True
                logger.debug("i=\"%s\" app=%s objExists=%s after re-checking on %s" % (self.stanzaName, app, objExists, objExistsURL))
        
        #This is an existing object we are modifying
        if objExists == True:
            createOrUpdate = "update"
            if origName:
                url = url + "/" + origName
            else:
                url = url + "/" + name
            del config["name"]
            
            #Cannot post type/stanza when updating field extractions or a few other object types, but require them for creation?!
            if 'type' in config:
                del config['type']
            if 'stanza' in config:
                del config['stanza']
        
        #Hack to handle the times (conf-times) not including required attributes for creation in existing entries
        #not sure how this happens but it fails to create in 7.0.5 but works fine in 7.2.x, fixing for the older versions
        if type=="times_conf-times" and "is_sub_menu" not in payload:
            payload["is_sub_menu"] = "0"
        elif type=="collections_kvstore" and 'disabled' in payload:
            del payload['disabled']
        
        logger.debug("i=\"%s\" Attempting to %s type=%s with name=%s on URL=%s with payload=\"%s\" in app=%s proxies_length=%s" % (self.stanzaName, createOrUpdate, type, name, url, payload, app, len(self.proxies)))
        res = requests.post(url, auth=auth, headers=headers, verify=False, data=payload, proxies=self.proxies)
        if (res.status_code != requests.codes.ok and res.status_code != 201):
            logger.error("i=\"%s\" user=%s, name=%s of type=%s with URL=%s statuscode=%s reason=%s, response=\"%s\", in app=%s, owner=%s" % (self.stanzaName, user, name, type, url, res.status_code, res.reason, res.text, app, owner))
            #Saved Searches sometimes fail due to the VSID field, auto-retry in case that solves the problem...
            if type=="savedsearches":
                if 'vsid' in payload:
                    del payload['vsid']
                    res = requests.post(url, auth=auth, headers=headers, verify=False, data=payload, proxies=self.proxies)
                    if (res.status_code != requests.codes.ok and res.status_code != 201):
                        logger.error("i=\"%s\" user=%s, re-attempted without vsid but result for name=%s of type=%s with URL=%s statuscode=%s reason=%s, response=\"%s\", in app=%s, owner=%s" % (self.stanzaName, user, name, type, url, res.status_code, res.reason, res.text, app, owner))
                        result = False
                    else:
                        logger.info("i=\"%s\" user=%s, name=%s of type=%s with URL=%s successfully %s with the vsid field removed, feel free to ignore the previous error" % (self.stanzaName, user, name, type, url, createOrUpdate))
        else:
            logger.debug("i=\"%s\" %s name=%s of type=%s in app=%s with URL=%s result=\"%s\" owner=%s" % (self.stanzaName, createOrUpdate, name, type, app, url, res.text, owner))
            
            #Parse the result to find re-confirm the URL and check for messages from Splunk (and log warnings about them)
            root = ET.fromstring(res.text)
            objURL = None
            for child in root:
                #Working per entry in the results
                if child.tag.endswith("entry"):
                    #Down to each entry level
                    for innerChild in child:
                        #print innerChild.tag
                        if innerChild.tag.endswith("link") and innerChild.attrib["rel"]=="list":
                            objURL = "%s/%s" % (self.splunk_rest, innerChild.attrib["href"])
                            logger.debug("i=\"%s\" name=%s of type=%s in app=%s URL=%s" % (self.stanzaName, name, type, app, objURL))
                elif child.tag.endswith("messages"):
                    for innerChild in child:
                        if innerChild.tag.endswith("msg") and innerChild.attrib["type"]=="ERROR" or "WARN" in innerChild.attrib:
                            logger.warn("i=\"%s\" name=%s of type=%s in app=%s had a warn/error message of '%s' owner=%s" % (self.stanzaName, name, type, app, innerChild.text, owner))
                            #Sometimes the object appears to be create but is unusable which is annoying, at least provide the warning to the logs
            
            if not objURL:
                logger.warn("i=\"%s\" never found objURL so cannot complete ACL change with url=%s, response text=\"%s\" when looking for name=%s, type=%s app=%s, owner=%s" % (self.stanzaName, url, res.text, name, type, app, owner))
                return
            
            #Re-owning it to the previous owner and sharing level
            url = "%s/acl" % (objURL)
            payload = { "owner": owner, "sharing" : sharing }
            logger.info("i=\"%s\" Attempting to change ownership of type=%s with name=%s via URL=%s to owner=%s in app=%s with sharing=%s" % (self.stanzaName, type, name, url, owner, app, sharing))
            res = requests.post(url, auth=auth, headers=headers, verify=False, data=payload, proxies=self.proxies)
            
            #If re-own fails log this for investigation
            if (res.status_code != requests.codes.ok):
                logger.error("i=\"%s\" user=%s, name=%s of type=%s in app=%s with URL=%s statuscode=%s reason=%s, response=\"%s\", owner=%s" % (self.stanzaName, user, name, type, app, url, res.status_code, res.reason, res.text, owner))
                result = False
            else:
                logger.debug("i=\"%s\" user=%s, name=%s of type=%s in app=%s, ownership changed with response=\"%s\", owner=%s, sharing=%s" % (self.stanzaName, user, name, type, app, res.text, owner, sharing))
        
        logger.info("i=\"%s\" %s name=%s of type=%s in app=%s owner=%s sharing=%s" % (self.stanzaName, createOrUpdate, name, type, app, owner, sharing))
        return result
        
    ###########################
    #
    # macroCreation
    #   Runs the required queries to create or update the macro knowledge objects and then re-owns them to the correct user
    # 
    ###########################
    def runRestoreMacro(self, config, app, name, username, restoreAsUser, adminLevel, objExists):
        result = True
        #Only admins can restore objects on behalf of someone else
        if config['owner'] != username and adminLevel == False:
            logger.error("i=\"%s\" Owner of the object is listed as owner=%s, however user=%s requested the restore and is not an admin, rejected" % (self.stanzaName, config['owner'], username))
            return False
        
        #Only admins can restore objects into someone else's name
        if restoreAsUser != "" and restoreAsUser != username and adminLevel == False:
            logger.error("i=\"%s\" restoreAsUser=%s which is not the user=%s, this user is not an admin, rejected" % (self.stanzaName))
            return False

        logger.info("i=\"%s\" Attempting to run macro restore with name=%s, user=%s, restoreAsUser=%s, adminLevel=%s, objExists=%s" % (self.stanzaName, name, username, restoreAsUser, adminLevel, objExists))
        #Change the owner to the new oner
        if restoreAsUser != "" and adminLevel == True:
            config["owner"] = restoreAsUser
    
        sharing = config["sharing"]
        name = config["name"]
        owner = config["owner"]
        
        headers = {}
        auth = None
        if not self.destUsername:
            headers={'Authorization': 'Splunk %s' % self.session_key}
        else:
            auth = HTTPBasicAuth(self.destUsername, self.destPassword)
        
        #We are creating the macro
        if objExists == False:
            url = "%s/servicesNS/%s/%s/properties/macros" % (self.splunk_rest, owner, app)
            logger.info("i=\"%s\" Attempting to create type=macro name=%s on URL=%s in app=%s" % (self.stanzaName, name, url, app))

            payload = { "__stanza" : name }
            #Create macro
            #I cannot seem to get this working on the /conf URL but this works so good enough, and it's in the REST API manual...
            #servicesNS/-/search/properties/macros
            #__stanza = <name>
            
            res = requests.post(url, auth=auth, headers=headers, verify=False, data=payload, proxies=self.proxies)
            if (res.status_code != requests.codes.ok and res.status_code != 201):
                logger.error("i=\"%s\" name=%s of type=macro in app=%s with URL=%s statuscode=%s reason=%s, response=\"%s\", owner=%s" % (self.stanzaName, name, app, url, res.status_code, res.reason, res.text, owner))
                return False
            else:
                #Macros always have the username in this URL context
                objURL = "%s/servicesNS/%s/%s/configs/conf-macros/%s" % (self.splunk_rest, owner, app, name)
                logger.debug("i=\"%s\" name=%s of type=macro in app=%s URL=%s with owner=%s" % (self.stanzaName, name, app, objURL, owner))

            logger.debug("i=\"%s\" name=%s of type=macro in app=%s, received response=\"%s\"" % (self.stanzaName, name, app, res.text))

        #Now we have created the macro, modify it so it has some real content (or it's an existing macro we're fixing)
        #If this is an app or globally scoped object use the nobody in the URL
        url = ""
        if objExists == True and sharing != "user":
            url = "%s/servicesNS/nobody/%s/properties/macros/%s" % (self.splunk_rest, app, name)
        else:
            url = "%s/servicesNS/%s/%s/properties/macros/%s" % (self.splunk_rest, owner, app, name)
        
        #Remove parts that cannot be posted to the REST API, sharing/owner we change later
        del config["sharing"]
        del config["name"]
        del config["owner"]
        payload = config
        
        logger.debug("i=\"%s\" Attempting to modify type=macro name=%s on URL=%s with payload=\"%s\" in app=%s proxies_length=%s" % (self.stanzaName, name, url, payload, app, len(self.proxies)))
        res = requests.post(url, auth=auth, headers=headers, verify=False, data=payload, proxies=self.proxies)
        if (res.status_code != requests.codes.ok and res.status_code != 201):
            logger.error("i=\"%s\" name=%s of type=macro in app=%s with URL=%s statuscode=%s reason=%s, response=\"%s\"" % (self.stanzaName, name, app, url, res.status_code, res.reason, res.text))
            result = False
        else:
            #Re-owning it, I've switched URL's again here but it seems to be working so will not change it
            url = "%s/servicesNS/%s/%s/configs/conf-macros/%s/acl" % (self.splunk_rest, owner, app, name)
            payload = { "owner": owner, "sharing" : sharing }
            logger.info("i=\"%s\" Attempting to change ownership of type=macro name=%s via URL=%s to owner=%s in app=%s with sharing=%s" % (self.stanzaName, name, url, owner, app, sharing))
            res = requests.post(url, auth=auth, headers=headers, verify=False, data=payload, proxies=self.proxies)
            if (res.status_code != requests.codes.ok):
                logger.error("i=\"%s\" name=%s of type=macro in app=%s with URL=%s statuscode=%s reason=%s, response=\"%s\", owner=%s sharing=%s" % (self.stanzaName, name, app, url, res.status_code, res.reason, res.text, owner, sharing))
            else:
                logger.debug("i=\"%s\" name=%s of type=macro in app=%s, ownership changed with response=\"%s\", newOwner=%s and sharing=%s" % (self.stanzaName, name, app, res.text, owner, sharing))
        
        return result
        
    ###########################
    #
    # macros
    # 
    ###########################
    #macro use cases are slightly different to everything else on the REST API
    #enough that this code has not been integrated into the runQuery() function
    def macros(self, app, name, scope, user, restoreAsUser, adminLevel):
        logger.info("i=\"%s\" user=%s, attempting to restore name=%s in app=%s of type=macro in scope=%s, restoreAsUser=%s, adminLevel=%s" % (self.stanzaName, user, name, app, scope, restoreAsUser, adminLevel))
        #servicesNS/-/-/properties/macros doesn't show private macros so using /configs/conf-macros to find all the macros
        #again with count=-1 to find all the available macros
        url = self.splunk_rest + "/servicesNS/-/" + app + "/configs/conf-macros/" + name + "?output_mode=json"
        logger.debug("i=\"%s\" Running requests.get() on url=%s with user=%s in app=%s for type=macro proxies_length=%s" % (self.stanzaName, url, self.destUsername, app, len(self.proxies)))
        
        #Determine scope that we will attempt to restore
        appScope = False
        userScope = False
        if scope == "all":
            appScope = True
            userScope = True
        elif scope == "app":
            appScope = True
        elif scope == "user":
            userScope = True
        else:
            logger.error("i=\"%s\" user=%s, while attempting to restore name=%s, found invalid scope=%s" % (self.stanzaName, user, name, scope))

        headers = {}
        auth = None
        if not self.destUsername:
            headers={'Authorization': 'Splunk %s' % self.session_key}
        else:
            auth = HTTPBasicAuth(self.destUsername, self.destPassword)
        
        #Verify=false is hardcoded to workaround local SSL issues
        res = requests.get(url, auth=auth, headers=headers, verify=False, proxies=self.proxies)
        objExists = False
        if (res.status_code == 404):
            logger.debug("i=\"%s\" URL=%s is throwing a 404, assuming new object creation" % (self.stanzaName, url))
        elif (res.status_code != requests.codes.ok):
            logger.error("i=\"%s\" type=macro in app=%s, URL=%s statuscode=%s reason=%s, response=\"%s\"" % (self.stanzaName, app, url, res.status_code, res.reason, res.text))
        else:
            #However the fact that we did not get a 404 does not mean it exists in the context we expect it to, perhaps it's global and from another app context?
            #or perhaps it's app level but we're restoring a private object...
            logger.debug("i=\"%s\" Attempting to JSON loads on %s" % (self.stanzaName, res.text))
            resDict = json.loads(res.text)
            for entry in resDict['entry']:
                sharingLevel = entry['acl']['sharing']
                appContext = entry['acl']['app']
                if appContext == app and appScope == True and (sharingLevel == 'app' or sharingLevel == 'global'):
                    objExists = True
                elif appContext == app and userScope == True and sharingLevel == "user":
                    objExists = True
        
        configList = []
        
        foundAtAnyScope = False
        #This object is at user scope or may be at user scope
        if userScope == True:
            userDir = self.gitTempDir + "/" + app + "/" + "user"
            #user directory exists
            if os.path.isdir(userDir):
                typeFile = userDir + "/macros"
                #We found the file, now open it to obtain the contents
                if os.path.isfile(typeFile):
                    logger.debug("i=\"%s\" user=%s, name=%s, found typeFile=%s to restore from" % (self.stanzaName, user, name, typeFile))
                    with open(typeFile, 'r') as f:
                        configList = json.load(f)
                        found = False
                        for configItem in configList:
                            #We found the relevant item, now restore it
                            if configItem['name'] == name:
                                logger.debug("i=\"%s\" user=%s, name=%s is found, dictionary=\"%s\"" % (self.stanzaName, user, name, configItem))
                                self.runRestoreMacro(configItem, app, name, user, restoreAsUser, adminLevel, objExists)
                                found = True
                                foundAtAnyScope = True
                        #We never found the relevant item
                        if found == False:
                            logger.info("i=\"%s\" user=%s, name=%s not found at scope=user in typeFile=%s" % (self.stanzaName, user, name, typeFile))
                #The config file did not exist
                else:
                    logger.info("i=\"%s\" user=%s, name=%s, did not find a typeFile=%s to restore from" % (self.stanzaName, user, name, typeFile))
            else:
                #There are no user level objects for this app, therefore the restore will not occur at this scope
                logger.info("i=\"%s\" user directory of dir=%s does not exist" % (self.stanzaName, userDir))

        #The object is either app or globally scoped
        if appScope == True:
            appDir = self.gitTempDir + "/" + app + "/" + "app"
            #app directory exists
            if os.path.isdir(appDir):
                typeFile = appDir + "/macros"
                #We found the file, open it and load the config
                if os.path.isfile(typeFile):
                    logger.debug("i=\"%s\" user=%s, name=%s, found typeFile=%s to restore from" % (self.stanzaName, user, name, typeFile))
                    with open(typeFile, 'r') as f:
                        configList = json.load(f)
                        found = False
                        #We found the item, now restore it
                        for configItem in configList:
                            if configItem['name'] == name:
                                logger.debug("i=\"%s\" user=%s, name=%s is found, dictionary is %s" % (self.stanzaName, user, name, configItem))
                                self.runRestoreMacro(configItem, app, name, user, restoreAsUser, adminLevel, objExists)
                                found = True
                                foundAtAnyScope = True
                        #We never found the item
                        if found == False:
                            logger.info("i=\"%s\" user=%s, name=%s not found at scope=app in typeFile=%s" % (self.stanzaName, user, name, typeFile))
                #We never found the file to restore from
                else:
                    logger.info("i=\"%s\" user=%s, name=%s, did not find a typeFile=%s to restore from" % (self.stanzaName, user, name, typeFile))
            else:
                #There are no app level objects for this app, therefore the restore will not occur at this scope
                logger.info("i=\"%s\" app directory of dir=%s does not exist" % (self.stanzaName, appDir))
            
            globalDir = self.gitTempDir + "/" + app + "/" + "global"
            #global directory exists
            if os.path.isdir(globalDir):
                typeFile = globalDir + "/macros"
                #We found the file, attempt to load the config
                if os.path.isfile(typeFile):
                    logger.debug("i=\"%s\" user=%s, name=%s, found typeFile=%s to restore from" % (self.stanzaName, user, name, typeFile))
                    with open(typeFile, 'r') as f:
                        configList = json.load(f)
                        found = False
                        for configItem in configList:
                            #We found the item,  now restore it
                            if configItem['name'] == name:
                                logger.debug("i=\"%s\" user=%s, name=%s is found, dictionary is %s" % (self.stanzaName, user, name, configItem))
                                self.runRestoreMacro(configItem, app, name, user, restoreAsUser, adminLevel, objExists)
                                found = True
                                foundAtAnyScope = True
                        #We never found the item
                        if found == False:
                            logger.info("i=\"%s\" user=%s, name=%s not found at scope=global in typeFile=%s" % (self.stanzaName, user, name, typeFile))
                #We did not find the file to restore from
                else:
                    logger.info("i=\"%s\" user=%s, name=%s, did not find a typeFile=%s to restore from" % (self.stanzaName, user, name, typeFile))
            else:
                #There are no global level objects for this app, therefore the restore will not occur at this scope
                logger.info("i=\"%s\" global directory of dir=%s does not exist" % (self.stanzaName, globalDir))
        
        if foundAtAnyScope == True:
            logger.info("i=\"%s\" user=%s restore has run successfully for name=%s, type=macro, restoreAsUser=%s, adminLevel=%s" % (self.stanzaName, user, name, restoreAsUser, adminLevel))
            return True
        else:
            logger.warn("i=\"%s\" user=%s attempted to restore name=%s, type=macro, restoreAsUser=%s, adminLevel=%s however the object was not found, the restore was unsuccessful. Perhaps check the restore date, scope & capitalisation before trying again?" % (self.stanzaName, user, name, restoreAsUser, adminLevel))
            return False

    ###########################
    #
    # Migration functions
    #   These functions migrate the various knowledge objects mainly by calling the runQueries
    #   with the appropriate options for that type
    #   Excluding macros, they have their own function
    # 
    ###########################
    ###########################
    #
    # Dashboards
    # 
    ###########################
    def dashboards(self, app, name, scope, username, restoreAsUser, adminLevel):
        return self.runQueries(app, "/data/ui/views", "dashboards", name, scope, username, restoreAsUser, adminLevel)

    ###########################
    #
    # Saved Searches
    # 
    ###########################
    def savedsearches(self, app, name, scope, username, restoreAsUser, adminLevel):
        return self.runQueries(app, "/saved/searches", "savedsearches",name, scope, username, restoreAsUser, adminLevel)

    ###########################
    #
    # field definitions
    # 
    ###########################
    def calcfields(self, app, name, scope, username, restoreAsUser, adminLevel):
        return self.runQueries(app, "/data/props/calcfields", "calcfields", name, scope, username, restoreAsUser, adminLevel)
        
    def fieldaliases(self, app, name, scope, username, restoreAsUser, adminLevel):
        return self.runQueries(app, "/data/props/fieldaliases", "fieldaliases", name, scope, username, restoreAsUser, adminLevel)

    def fieldextractions(self, app, name, scope, username, restoreAsUser, adminLevel):
        return self.runQueries(app, "/data/props/extractions", "fieldextractions", name, scope, username, restoreAsUser, adminLevel)

    def fieldtransformations(self, app, name, scope, username, restoreAsUser, adminLevel):
        return self.runQueries(app, "/data/transforms/extractions", "fieldtransformations", name, scope, username, restoreAsUser, adminLevel)
        
    def workflowactions(self, app, name, scope, username, restoreAsUser, adminLevel):
        return self.runQueries(app, "/data/ui/workflow-actions", "workflow-actions", name, scope, username, restoreAsUser, adminLevel)

    def sourcetyperenaming(self, app, name, scope, username, restoreAsUser, adminLevel):
        return self.runQueries(app, "/data/props/sourcetype-rename", "sourcetype-rename", name, scope, username, restoreAsUser, adminLevel)

    ###########################
    #
    # tags
    # 
    ##########################
    def tags(self, app, name, scope, username, restoreAsUser, adminLevel):
        return self.runQueries(app, "/configs/conf-tags", "tags", name, scope, username, restoreAsUser, adminLevel)

    ###########################
    #
    # eventtypes
    # 
    ##########################
    def eventtypes(self, app, name, scope, username, restoreAsUser, adminLevel):
        return self.runQueries(app, "/saved/eventtypes", "eventtypes", name, scope, username, restoreAsUser, adminLevel)

    ###########################
    #
    # navMenus
    # 
    ##########################
    def navMenu(self, app, name, scope, username, restoreAsUser, adminLevel):
        return self.runQueries(app, "/data/ui/nav", "navMenu", name, scope, username, restoreAsUser, adminLevel)

    ###########################
    #
    # data models
    # 
    ##########################
    def datamodels(self, app, name, scope, username, restoreAsUser, adminLevel):
        return self.runQueries(app, "/datamodel/model", "datamodels", name, scope, username, restoreAsUser, adminLevel)

    ###########################
    #
    # collections
    #
    ##########################
    def collections(self, app, name, scope, username, restoreAsUser, adminLevel):
        return self.runQueries(app, "/storage/collections/config", "collections_kvstore", name, scope, username, restoreAsUser, adminLevel)

    ###########################
    #
    # viewstates
    #
    ##########################
    def viewstates(self, app, name, scope, username, restoreAsUser, adminLevel):
        return self.runQueries(app, "/configs/conf-viewstates", "viewstates", name, scope, username, restoreAsUser, adminLevel)

    ###########################
    #
    # time labels (conf-times)
    #
    ##########################
    def times(self, app, name, scope, username, restoreAsUser, adminLevel):
        return self.runQueries(app, "/configs/conf-times", "times_conf-times", name, scope, username, restoreAsUser, adminLevel)

    ###########################
    #
    # panels
    #
    ##########################
    def panels(self, app, name, scope, username, restoreAsUser, adminLevel):
        return self.runQueries(app, "/data/ui/panels", "pre-built_dashboard_panels", name, scope, username, restoreAsUser, adminLevel)
        
    ###########################
    #
    # lookups (definition/automatic)
    #
    ##########################
    def lookupDefinitions(self, app, name, scope, username, restoreAsUser, adminLevel):
        return self.runQueries(app, "/data/transforms/lookups", "lookup_definition", name, scope, username, restoreAsUser, adminLevel)

    def automaticLookups(self, app, name, scope, username, restoreAsUser, adminLevel):
        return self.runQueries(app, "/data/props/lookups", "automatic_lookups", name, scope, username, restoreAsUser, adminLevel)

    ###########################
    #
    # Helper/utility functions
    #
    ##########################
    #helper function as per https://stackoverflow.com/questions/31433989/return-copy-of-dictionary-excluding-specified-keys
    def without_keys(self, d, keys):
        return {x: d[x] for x in d if x not in keys}

    #Run a Splunk query via the search/jobs endpoint
    def runSearchJob(self, query, earliest_time="-1h"):
        url = self.splunk_rest + "/servicesNS/-/%s/search/jobs" % (self.appName)
        logger.debug("i=\"%s\" Running requests.post() on url=%s with user=%s query=\"%s\" proxies_length=%s" % (self.stanzaName, url, self.destUsername, query, len(self.proxies)))
        data = { "search" : query, "output_mode" : "json", "exec_mode" : "oneshot", "earliest_time" : earliest_time }
        
        #no destUsername, use the session_key method
        headers = {}
        auth = None
        if not self.destUsername:
            headers = {'Authorization': 'Splunk %s' % self.session_key }
        else:
            auth = HTTPBasicAuth(self.destUsername, self.destPassword)
        
        res = requests.post(url, auth=auth, headers=headers, verify=False, data=data, proxies=self.proxies)
        if (res.status_code != requests.codes.ok):
            logger.error("i=\"%s\" URL=%s statuscode=%s reason=%s, response=\"%s\"" % (self.stanzaName, url, res.status_code, res.reason, res.text))
        res = json.loads(res.text)
        
        #Log return messages from Splunk, often these advise of an issue but not always...
        if len(res["messages"]) > 0:
            firstMessage = res["messages"][0]
            if 'type' in firstMessage and firstMessage['type'] == "INFO":
                #This is a harmless info message ,most other messages are likely an issue
                logger.info("i=\"%s\" messages from query=\"%s\" were messages=\"%s\"" % (self.stanzaName, query, res["messages"]))
            else:
                logger.warn("i=\"%s\" messages from query=\"%s\" were messages=\"%s\"" % (self.stanzaName, query, res["messages"]))
        return res

    ###########################
    #
    # Main logic section
    #
    ##########################
    #restlist_override is when we are passed a dictionary with info on the restore requirements rather than obtaining this via a lookup commmand
    #config_override is for when we are passed a configuration dictionary and we do not need to read our config from stdin (i.e. we were not called by Splunk in the normal fashion)
    def run_script(self, restlist_override=None, config_override=None):
        if not config_override:
            config = self.get_config()
        else:
            config = config_override
        
        #If we want debugMode, keep the debug logging, otherwise drop back to INFO level
        if 'debugMode' in config:
            debugMode = config['debugMode'].lower()
            if debugMode == "true" or debugMode == "t":
                logging.getLogger().setLevel(logging.DEBUG)
        
        self.stanzaName = config["name"].replace("splunkversioncontrol_restore://", "")
        useLocalAuth = False
        if 'useLocalAuth' in config:
            useLocalAuth = config['useLocalAuth'].lower()
            if useLocalAuth == "true" or useLocalAuth=="t":
                useLocalAuth = True
                logger.debug("useLocalAuth enabled")
            else:
                useLocalAuth = False
        
        #If we're not using the useLocalAuth we must have a username/password to work with
        if useLocalAuth == False and ('destUsername' not in config or 'destPassword' not in config):
            logger.fatal("i=\"%s\" useLocalAuth is not set to true and destUsername/destPassword not set, exiting with failure" % (self.stanzaName))
            sys.exit(1)
        
        if useLocalAuth == False:
            self.destUsername = config['destUsername']
            self.destPassword = config['destPassword']
        
        if 'remoteAppName' in config:
            self.appName = config['remoteAppName']
         
        auditLogsLookupBackTime = "-1h"
        if 'auditLogsLookupBackTime' in config:
            auditLogsLookupBackTime = config['auditLogsLookupBackTime']
        
        self.gitRepoURL = config['gitRepoURL']
        
        #From server
        self.splunk_rest = config['destURL']
        excludedList = [ "destPassword", "session_key" ]
        cleanArgs = self.without_keys(config, excludedList)
        logger.info("i=\"%s\" Splunk Version Control Restore run with arguments=\"%s\"" % (self.stanzaName, cleanArgs))

        self.session_key = config['session_key']

        if not useLocalAuth and self.destPassword.find("password:") == 0:
            self.destPassword = get_password(self.destPassword[9:], self.session_key, logger)

        knownAppList = []
        self.gitTempDir = config['gitTempDir']
        self.gitRootDir = config['gitTempDir']

        if 'git_command' in config:
            self.git_command = config['git_command'].strip()
            logger.debug("Overriding git command to %s" % (self.git_command))
        else:
            self.git_command = "git"
        if 'ssh_command' in config:
            self.ssh_command = config['ssh_command'].strip()
            logger.debug("Overriding ssh command to %s" % (self.ssh_command))
        else:
            self.ssh_command = "ssh"

        gitFailure = False
        
        if platform.system() == "Windows":
            self.windows = True
        else:
            self.windows = False

        proxies = {}
        if 'proxy' in config:
            proxies['https'] = config['proxy']
            if proxies['https'].find("password:") != -1:
                start = proxies['https'].find("password:") + 9
                end = proxies['https'].find("@")
                logger.debug("Attempting to replace proxy=%s by subsituting=%s with a password" % (proxies['https'], proxies['https'][start:end]))
                temp_password = get_password(proxies['https'][start:end], session_key, logger)
                proxies['https'] = proxies['https'][0:start-9] + temp_password + proxies['https'][end:]

        self.proxies = proxies

        dirExists = os.path.isdir(self.gitTempDir)
        if dirExists and len(os.listdir(self.gitTempDir)) != 0:
            if not ".git" in os.listdir(self.gitTempDir):
                #include the subdirectory which is the git repo
                self.gitTempDir = self.gitTempDir + "/" + os.listdir(self.gitTempDir)[0]
                logger.info("gitTempDir=%s" % (self.gitTempDir))
        else:
            if not dirExists:
                #make the directory and clone under here
                os.mkdir(self.gitTempDir)
            #Initially we must trust our remote repo URL
            (output, stderrout, res) = runOSProcess(self.ssh_command + " -n -o \"BatchMode yes\" -o StrictHostKeyChecking=no " + self.gitRepoURL[:self.gitRepoURL.find(":")], logger)
            if res == False:
                logger.warn("i=\"%s\" Unexpected failure while attempting to trust the remote git repo?! stdout '%s' stderr '%s'" % (self.stanzaName, output, stderrout))
            
            #Clone the remote git repo
            (output, stderrout, res) = runOSProcess("%s clone %s %s" % (self.git_command, self.gitRepoURL, self.gitRootDir), logger, timeout=300)
            if res == False:
                logger.fatal("i=\"%s\" git clone failed for some reason...on url=%s stdout of '%s' with stderrout of '%s'" % (self.stanzaName, self.gitRepoURL, output, stderrout))
                sys.exit(1)
            else:
                logger.debug("i=\"%s\" result from git command: %s, output '%s' with stderroutput of '%s'" % (self.stanzaName, res, output, stderrout))
                logger.info("i=\"%s\" Successfully cloned the git URL=%s into directory dir=%s" % (self.stanzaName, self.gitRepoURL, self.gitTempDir))
                if not ".git" in os.listdir(self.gitTempDir):
                    #include the subdirectory which is the git repo
                    self.gitTempDir = self.gitTempDir + "/" + os.listdir(self.gitTempDir)[0]
                    logger.debug("gitTempDir=%s" % (self.gitTempDir))
            
            if stderrout.find("error:") != -1 or stderrout.find("fatal:") != -1 or stderrout.find("timeout after") != -1: 
                logger.warn("i=\"%s\" error/fatal messages in git stderroutput please review. stderrout=\"%s\"" % (self.stanzaName, stderrout))
                gitFailure = True
        
        if not restlist_override:
            #Version Control File that lists what restore we need to do...
            restoreList = "splunkversioncontrol_restorelist"
            res = self.runSearchJob("| inputlookup %s" % (restoreList))
            resList = res["results"]
        else:
            resList = restlist_override
        
        result = False
        if len(resList) == 0:
            logger.info("i=\"%s\" No restore required at this point in time" % (self.stanzaName))
        else:
            #Do a git pull to ensure we are up-to-date
            if self.windows:
                (output, stderrout, res) = runOSProcess("cd /d %s & %s checkout master & %s pull" % (self.gitTempDir, self.git_command, self.git_command), logger, timeout=300, shell=True)
            else:
                (output, stderrout, res) = runOSProcess("cd %s; %s checkout master; %s pull" % (self.gitTempDir, self.git_command, self.git_command), logger, timeout=300, shell=True)
            if res == False:
                logger.fatal("i=\"%s\" git pull failed for some reason...on url=%s stdout of '%s' with stderrout of '%s'. Wiping the git directory to re-clone" % (self.stanzaName, self.gitRepoURL, output, stderrout))
                shutil.rmtree(self.gitTempDir)
                if self.windows:
                    (output, stderrout, res) = runOSProcess("cd /d %s & %s checkout master & %s pull" % (self.gitTempDir, self.git_command, self.git_command), logger, timeout=300, shell=True)
                else:
                    (output, stderrout, res) = runOSProcess("cd %s; %s checkout master; %s pull" % (self.gitTempDir, self.git_command, self.git_command), logger, timeout=300, shell=True)
                if res == False:
                    logger.fatal("i=\"%s\" git clone failed for some reason...on url=%s stdout of '%s' with stderrout of '%s'" % (self.stanzaName, self.gitRepoURL, output, stderrout))
                    sys.exit(1)
                else:
                    logger.debug("i=\"%s\" result from git command: %s, output '%s' with stderroutput of '%s'" % (self.stanzaName, res, output, stderrout))
                    logger.info("i=\"%s\" Successfully cloned the git URL=%s into directory dir=%s" % (self.stanzaName, self.gitRepoURL, self.gitRootDir))
            else:
                logger.info("i=\"%s\" Successfully ran the git pull for URL=%s from directory dir=%s" % (self.stanzaName, self.gitRepoURL, self.gitRootDir))

            if stderrout.find("error:") != -1 or stderrout.find("fatal:") != -1 or stderrout.find("timeout after") != -1:
                logger.warn("i=\"%s\" error/fatal messages in git stderroutput please review. stderrout=\"%s\"" % (self.stanzaName, stderrout))
                gitFailure = True

            logger.debug("i=\"%s\" The restore list is %s" % (self.stanzaName, resList))
            #Attempt to determine all users involved in this restore so we can run a single query and determine if they are admins or not
            userList = []
            for aRes in resList:
                user = aRes['user']
                userList.append(user)
            #obtain a list of unique user id's
            userList = list(set(userList))
            ldapFilter = None
            usernameFilter = None
            
            for user in userList:
                if not ldapFilter:
                    ldapFilter = "*%s*" % (user)
                    usernameFilter = user
                else:
                    ldapFilter = "%s, *%s*" % (ldapFilter, user)
                    usernameFilter = "%s, %s" % (usernameFilter, user)
            
            #Query Splunk and determine if the mentioned users have the required admin role, if not they can only restore the objects they own
            res = self.runSearchJob("| savedsearch \"SplunkVersionControl CheckAdmin\" ldapFilter=\"%s\", usernameFilter=\"%s\"" % (ldapFilter, usernameFilter))
            userResList = []
            if 'results' not in res:
                logger.warn("i=\"%s\" Unable to run 'SplunkVersionControl CheckAdmin' for some reason with ldapFilter=%s and usernameFilter=%s" % (self.stanzaName, ldapFilter, usernameFilter))
            else:
                userResList = res["results"]
            
            #Create a list of admins
            adminList = []
            for userRes in userResList:
                username = userRes["username"]
                logger.debug("i=\"%s\" Adding user=%s as an admin username" % (self.stanzaName, username))
                adminList.append(username)
            
            if not restlist_override:
                # Run yet another query, this one provides a list of times/usernames at which valid entries were added to the lookup file
                # if the addition to the lookup file was not done via the required report then the restore is not done (as anyone can add a new role
                # and put the username as an admin user!)
                res = self.runSearchJob("| savedsearch \"SplunkVersionControl Audit Query\"", earliest_time=auditLogsLookupBackTime)
                auditEntries = []
                if 'results' not in res:
                    logger.warn("i=\"%s\" Unable to run 'SplunkVersionControl Audit Query' for some reason with earliest_time=%s" % (self.stanzaName, auditLogsLookupBackTime))
                else:
                    auditEntries = res["results"]
                    logger.debug("i=\"%s\" Audit Entries are: '%s'" % (self.stanzaName, auditEntries))
            
            #Cycle through each result from the earlier lookup and run the required restoration
            for aRes in resList:
                if not all (entry in aRes for entry in ('time', 'app', 'name', 'restoreAsUser', 'tag', 'type', 'user', 'scope')):
                    logger.warn("i=\"%s\" this row is invalid, skipping this row of the results, res=\"%s\"" % (self.stanzaName, aRes))
                    continue
                
                time = aRes['time']
                app = aRes['app']
                name = aRes['name']
                restoreAsUser = aRes['restoreAsUser']
                tag = aRes['tag']
                type = aRes['type']
                user = aRes['user']
                scope = aRes['scope']

                logger.info("i=\"%s\" user=%s has requested the object with name=%s of type=%s to be restored from tag=%s and scope=%s, restoreAsUser=%s, this was requested at time=%s in app context of app=%s" % (self.stanzaName, user, name, type, tag, scope, restoreAsUser, time, app))
                
                if not restlist_override:
                    #If we have an entry in the lookup file it should be listed in the audit entries file
                    found = False
                    for entry in auditEntries:
                        #The audit logs are accurate to milliseconds, the lookup *is not* so sometimes it's off by about a second
                        timeEntry = entry['time']
                        timeEntryPlus1 = str(int(entry['time']) + 1)
                        timeEntryMinus1 = str(int(entry['time']) - 1)
                        if timeEntry == time or timeEntryPlus1 == time or timeEntryMinus1 == time:
                            found = True
                            auditUser = entry['user']
                            if user != auditUser:
                                logger.warn("i=\"%s\" user=%s found time entry of time=%s with auditUser=%s, this does not match the expected username (%s), rejecting this entry for name=%s of type=%s in app=%s with restoreAsUser=%s" % (self.stanzaName, user, time, auditUser, user, name, type, app, restoreAsUser))
                                found = False
                            else:
                                logger.debug("i=\"%s\" user=%s, found time entry of time=%s, considering this a valid entry and proceeding to restore" % (self.stanzaName, user, time))
                    
                    if found == False:
                        logger.warn("i=\"%s\" user=%s, unable to find a time entry of time=%s matching the auditEntries list of %s, skipping this entry" % (self.stanzaName, user, time, auditEntries))
                        continue
                #else we were provided with the override list and the username/audit logs were already checked
                
                adminLevel = False
                
                if user in adminList:
                    logger.debug("i=\"%s\" user=%s is an admin and has requested object name=%s of type=%s in app=%s to be restored with user=%s and time=%s" % (self.stanzaName, user, name, type, app, restoreAsUser, time))
                    adminLevel = True
                
                #Only admins can restore objects as another user
                if restoreAsUser != "" and restoreAsUser != user and adminLevel == False:
                    logger.error("i=\"%s\" user=%s is not an admin and has attempted to restore as a different user, requested user=%s, object=%s of type=%s in app=%s to be restored with restoreAsUser=%s time=%s, rejected" % (self.stanzaName, user, restoreAsUser, name, type, app, restoreAsUser, time))
                    continue
                
                #Do a git pull to ensure we are up-to-date
                if self.windows:
                    (output, stderrout, res) = runOSProcess("cd /d %s & %s checkout %s" % (self.gitTempDir, self.git_command, tag), logger, shell=True)
                else:
                    (output, stderrout, res) = runOSProcess("cd %s; %s checkout %s" % (self.gitTempDir, self.git_command, tag), logger, shell=True)
                if res == False:
                    logger.error("i=\"%s\" user=%s, object name=%s, type=%s, time=%s, git checkout of tag=%s failed in directory dir=%s stdout of '%s' with stderrout of '%s'" % (self.stanzaName, user, name, type, time, tag, self.gitTempDir, output, stderrout))
                else:
                    logger.info("i=\"%s\" Successfully ran the git checkout for URL=%s from directory dir=%s" % (self.stanzaName, self.gitRepoURL, self.gitTempDir))
                
                if stderrout.find("error:") != -1 or stderrout.find("fatal:") != -1 or stderrout.find("timeout after") != -1: 
                    logger.warn("i=\"%s\" error/fatal messages in git stderroutput please review. stderrout=\"%s\"" % (self.stanzaName, stderrout))
                    gitFailure = True
                
                knownAppList = []
                if os.path.isdir(self.gitTempDir):
                    #include the subdirectory which is the git repo
                    knownAppList = os.listdir(self.gitTempDir)
                    logger.debug("i=\"%s\" Known app list is %s" % (self.stanzaName, knownAppList))

                #If the app is not known, the restore stops here as we have nothing to restore from!
                if app not in knownAppList:
                    logger.error("i=\"%s\" user=%s requested a restore from app=%s but this is not in the knownAppList therefore restore cannot occur, object=%s of type=%s to be restored with user=%s and time=%s" % (self.stanzaName, user, app, name, type, restoreAsUser, time))
                    continue
                
                #Deal with the different types of restores that might be required, we only do one row at a time...
                if type == "dashboard":
                    result = self.dashboards(app, name, scope, user, restoreAsUser, adminLevel)
                elif type == "savedsearch":
                    result = self.savedsearches(app, name, scope, user, restoreAsUser, adminLevel)
                elif type == "macro":
                    result = self.macros(app, name, scope, user, restoreAsUser, adminLevel)
                elif type == "fieldalias":
                    result = self.fieldaliases(app, name, scope, user, restoreAsUser, adminLevel)
                elif type == "fieldextraction":
                    result = self.fieldextractions(app, name, scope, user, restoreAsUser, adminLevel)
                elif type == "fieldtransformation":
                    result = self.fieldtransformations(app, name, scope, user, restoreAsUser, adminLevel)
                elif type == "navmenu":
                    result = self.navMenu(app, name, scope, user, restoreAsUser, adminLevel)
                elif type == "datamodel":
                    result = self.datamodels(app, name, scope, user, restoreAsUser, adminLevel)
                elif type == "panels":
                    result = self.panels(app, name, scope, user, restoreAsUser, adminLevel)
                elif type == "calcfields":
                    result = self.calcfields(app, name, scope, user, restoreAsUser, adminLevel)
                elif type == "workflowaction":
                    result = self.workflowactions(app, name, scope, user, restoreAsUser, adminLevel)
                elif type == "sourcetyperenaming":
                    result = self.sourcetyperenaming(app, name, scope, user, restoreAsUser, adminLevel)
                elif type == "tags":
                    result = self.tags(app, name, scope, user, restoreAsUser, adminLevel)
                elif type == "eventtypes":
                    result = self.eventtypes(app, name, scope, user, restoreAsUser, adminLevel)
                elif type == "lookupdef":
                    result = self.lookupDefinitions(app, name, scope, user, restoreAsUser, adminLevel)
                elif type == "automaticlookup":
                    result = self.automaticLookups(app, name, scope, user, restoreAsUser, adminLevel)
                elif type == "collection":
                    result = self.collections(app, name, scope, user, restoreAsUser, adminLevel)
                elif type == "viewstate":
                    result = self.viewstates(app, name, scope, user, restoreAsUser, adminLevel)
                elif type == "times":
                    result = self.times(app, name, scope, user, restoreAsUser, adminLevel)
                else:
                    logger.error("i=\"%s\" user=%s, unknown type, no restore will occur for object=%s of type=%s in app=%s to be restored with restoreAsUser=%s and time=%s" % (self.stanzaName, user, name, type, app, restoreAsUser, time))

        if not restlist_override:
            #Wipe the lookup file so we do not attempt to restore these entries again
            if len(resList) != 0:
                if not gitFailure:
                    res = self.runSearchJob("| makeresults | fields - _time | outputlookup %s" % (restoreList))
                    logger.info("i=\"%s\" Cleared the lookup file to ensure we do not attempt to restore the same entries again" % (self.stanzaName))
                else:
                    logger.error("i=\"%s\" git failure occurred during runtime, not wiping the lookup value. This failure  may require investigation, please refer to the WARNING messages in the logs" % (self.stanzaName))
        if gitFailure:
            logger.warn("i=\"%s\" wiping the git directory, dir=%s to allow re-cloning on next run of the script" % (self.stanzaName, self.gitTempDir))
            shutil.rmtree(self.gitTempDir)
        
        logger.info("i=\"%s\" Done" % (self.stanzaName))

        return result
