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
from time import sleep
from subprocess import Popen, PIPE

###########################
#
# Restore Knowledge Objects
#   Query a remote lookup file to determine what items should be restored from git into a Splunk instance
#   In general this will be running against the localhost unless it is been tested as the lookup file will be updated
#   by a user accessible dashboard
#   Basic validation will be done to ensure someone without the required access cannot restore someone else's knowledge objects
# 
###########################

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
    appName = "SplunkVersionControl"
    gitRepoURL = None
    
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

                        params = stanza.getElementsByTagName("param")
                        for param in params:
                            param_name = param.getAttribute("name")
                            logger.debug("XML: found param '%s'" % param_name)
                            if param_name and param.firstChild and \
                               param.firstChild.nodeType == param.firstChild.TEXT_NODE:
                                data = param.firstChild.data
                                config[param_name] = data
                                logger.debug("XML: '%s' -> '%s'" % (param_name, data))

            if not config:
                raise Exception, "Invalid configuration received from Splunk."
        except Exception, e:
            raise Exception, "Error getting Splunk configuration via STDIN: %s" % str(e)

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
        logger.info("User %s, attempting to restore %s in app %s of type %s in scope %s, as user %s, adminLevel %s" % (user, name, app, type, scope, restoreAsUser, adminLevel))
        
        #Check if the object exists or not
        url = self.splunk_rest + "/servicesNS/-/%s%s/%s?output_mode=json" % (app, endpoint, name)
        logger.debug("Running requests.get() on %s with username %s in app %s" % (url, self.destUsername, app))

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
            logger.error("User %s, while attempting to restore %s, found invalid scope of %s" % (user, name, scope))

        headers = {}
        auth = None
        
        if not self.destUsername:
            headers={'Authorization': 'Splunk %s' % self.session_key}
        else:
            auth = HTTPBasicAuth(self.destUsername, self.destPassword)
        
        #Verify=false is hardcoded to workaround local SSL issues
        res = requests.get(url, auth=auth, headers=headers, verify=False)
        objExists = False
        
        #If we get 404 it definitely does not exist
        if (res.status_code == 404):
            logger.debug("URL %s is throwing a 404, assuming new object creation" % (url))
        elif (res.status_code != requests.codes.ok):
            logger.error("URL %s in app %s status code %s reason %s, response: '%s'" % (url, app, res.status_code, res.reason, res.text))
        else:
            #However the fact that we did not get a 404 does not mean it exists in the context we expect it to, perhaps it's global and from another app context?
            #or perhaps it's app level but we're restoring a private object...
            logger.debug("Attempting to JSON loads on %s" % (res.text))
            resDict = json.loads(res.text)
            for entry in resDict['entry']:
                sharingLevel = entry['acl']['sharing']
                appContext = entry['acl']['app']
                if appContext == app and appScope == True and (sharingLevel == 'app' or sharingLevel == 'global'):
                    objExists = True
                elif appContext == app and userScope == True and sharingLevel == "user":
                    objExists = True
        
        configList = []
        
        #We need to work with user scope
        if userScope == True:
            userDir = self.gitTempDir + "/" + app + "/" + "user"
            #user directory exists
            if os.path.isdir(userDir):
                typeFile = userDir + "/" + type
                if os.path.isfile(typeFile):
                    #The file exists, open it and read the config
                    logger.debug("User %s, name %s, found %s file to restore from" % (user, name, typeFile))
                    with open(typeFile, 'r') as f:
                        configList = json.load(f)
                        found = False
                        for configItem in configList:
                            if configItem['name'] == name:
                                #We found the configItem we need, run the restoration
                                logger.debug("User %s, name %s is found, dictionary is %s" % (user, name, configItem))
                                self.runRestore(configItem, type, endpoint, app, name, user, restoreAsUser, adminLevel, objExists)
                                found = True
                        #Let the logs know we never found it at this scope
                        if found == False:
                            logger.info("User %s, name %s not found at user level scope in file %s" % (user, name, typeFile))
                #We never found a file that we could use to restore from  at this scope
                else:
                    logger.info("User %s, name %s, did not find a %s file to restore from" % (user, name, typeFile))
            else:
                #There are no user level objects for this app, therefore the restore will not occur at this scope
                logger.info("user directory of %s does not exist" % (userDir))
        
        #It's either app level of globally scoped
        if appScope == True:
            appDir = self.gitTempDir + "/" + app + "/" + "app"
            #app directory exists
            if os.path.isdir(appDir):
                typeFile = appDir + "/" + type
                if os.path.isfile(typeFile):
                    #The file we need exists
                    logger.debug("User %s, name %s, found %s file to restore from" % (user, name, typeFile))
                    with open(typeFile, 'r') as f:
                        configList = json.load(f)
                        found = False
                        for configItem in configList:
                            #We found the required configuration file, now we restore the object
                            if configItem['name'] == name:
                                logger.debug("User %s, name %s is found, dictionary is %s" % (user, name, configItem))
                                self.runRestore(configItem, type, endpoint, app, name, user, restoreAsUser, adminLevel, objExists)
                                found = True
                        #We never found the object we wanted to restore
                        if found == False:
                            logger.info("User %s, name %s not found at app level scope in file %s" % (user, name, typeFile))
                #We did not find the file we wanted to restore from
                else:
                    logger.info("User %s, name %s, did not find a %s file to restore from" % (user, name, typeFile))
            else:
                #The app level scope directory does not exist for this app
                logger.info("app directory of %s does not exist" % (appDir))
            
            #If could also be a global level restore...
            globalDir = self.gitTempDir + "/" + app + "/" + "global"
            #user directory exists
            if os.path.isdir(globalDir):
                typeFile = globalDir + "/" + type
                if os.path.isfile(typeFile):
                    #We found the file to restore from
                    logger.debug("User %s, name %s, found %s file to restore from" % (user, name, typeFile))
                    with open(typeFile, 'r') as f:
                        configList = json.load(f)
                        found = False
                        for configItem in configList:
                            #We found the relevant piece of configuration to restore, now run the restore
                            if configItem['name'] == name:
                                logger.debug("User %s, name %s is found, dictionary is %s" % (user, name, configItem))
                                self.runRestore(configItem, type, endpoint, app, name, user, restoreAsUser, adminLevel, objExists)
                                found = True
                        #We never found the config we wanted to restore
                        if found == False:
                            logger.info("User %s, name %s not found at global level scope in file %s" % (user, name, typeFile))
                #This type of configuration does not exist at the global level                
                else:
                    logger.info("User %s, name %s, did not find a %s file to restore from" % (user, name, typeFile))
            #The global directory for this app does not exist
            else:
                logger.debug("global directory of %s does not exist" % (globalDir))

    ###########################
    #
    # runRestore (generic version)
    #   Once we have received the required configuration, type, app, endpoint, name et cetera we attempt
    #   to run the post to restore or create the object
    # 
    ###########################
    def runRestore(self, config, type, endpoint, app, name, user, restoreAsUser, adminLevel, objExists):
        #Only an admin can restore an object owned by someone else
        if config['owner'] != user and adminLevel == False:
            logger.error("Owner of the object is listed as %s, however user %s requested the restore and is not an admin, rejected" % (config['owner'], user))
            return
        
        #Only an admin can use the restoreAsUser option
        if restoreAsUser != "" and restoreAsUser != user and adminLevel == False:
            logger.error("restoreAsUser is %s which is not the username of %s, this user is not an admin, rejected")
            return
        
        #Change the owner to the new oner
        if restoreAsUser != "" and adminLevel == True:
            config["owner"] = restoreAsUser
        
        logger.info("Attempting to run restore for %s of type %s with endpoint %s username %s, restoreAsUser %s, adminLevel %s, objExists %s" % (name, type, endpoint, user, restoreAsUser, adminLevel, objExists))

        sharing = config["sharing"]
        owner = config["owner"]

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
        
        #This is an existing object we are modifying
        if objExists == True:
            url = url + "/" + name
            del config["name"]
        
        #Hack to handle the times (conf-times) not including required attributes for creation in existing entries
        #not sure how this happens but it fails to create in 7.0.5 but works fine in 7.2.x, fixing for the older versions
        if type=="times_conf-times" and not payload.has_key("is_sub_menu"):
            payload["is_sub_menu"] = "0"
        
        logger.debug("Attempting to create or update %s with name %s on URL %s with payload '%s' in app %s" % (type, name, url, payload, app))
        res = requests.post(url, auth=auth, headers=headers, verify=False, data=payload)
        if (res.status_code != requests.codes.ok and res.status_code != 201):
            logger.error("%s of type %s with URL %s status code %s reason %s, response '%s', in app %s, owner %s" % (name, type, url, res.status_code, res.reason, res.text, app, owner))
            #Saved Searches sometimes fail due to the VSID field, auto-retry in case that solves the problem...
            if type=="savedsearches":
                if 'vsid' in payload:
                    del payload['vsid']
                    res = requests.post(url, auth=auth, headers=headers, verify=False, data=payload)
                    if (res.status_code != requests.codes.ok and res.status_code != 201):
                        logger.error("Re-attempted without vsid but result was %s of type %s with URL %s status code %s reason %s, response '%s', in app %s, owner %s" % (name, type, url, res.status_code, res.reason, res.text, app, owner))
                    else:
                        logger.info("%s of type %s with URL %s successfully created with the vsid field removed, feel free to ignore the previous error" % (name, type, url))
        else:
            logger.debug("%s of type %s in app %s with URL %s result is: '%s' owner of %s" % (name, type, app, url, res.text, owner))
            
            #Parse the result to find re-confirm the URL and check for messages from Splunk (and log warnings about them)
            root = ET.fromstring(res.text)
            for child in root:
                #Working per entry in the results
                if child.tag.endswith("entry"):
                    #Down to each entry level
                    for innerChild in child:
                        #print innerChild.tag
                        if innerChild.tag.endswith("link") and innerChild.attrib["rel"]=="remove":
                            objURL = "%s/%s" % (self.splunk_rest, innerChild.attrib["href"])
                            logger.debug("%s of type %s in app %s URL as %s" % (name, type, app, objURL))
                elif child.tag.endswith("messages"):
                    for innerChild in child:
                        if innerChild.tag.endswith("msg") and innerChild.attrib["type"]=="ERROR" or innerChild.attrib.has_key("WARN"):
                            logger.warn("%s of type %s in app %s had a warn/error message of '%s' owner of %s" % (name, type, app, innerChild.text, owner))
                            #Sometimes the object appears to be create but is unusable which is annoying, at least provide the warning to the logs
            
            #Re-owning it to the previous owner and sharing level
            url = "%s/acl" % (objURL)
            payload = { "owner": owner, "sharing" : sharing }
            logger.info("Attempting to change ownership of %s with name %s via URL %s to owner %s in app %s with sharing %s" % (type, name, url, owner, app, sharing))
            res = requests.post(url, auth=auth, headers=headers, verify=False, data=payload)
            
            #If re-own fails log this for investigation
            if (res.status_code != requests.codes.ok):
                logger.error("%s of type %s in app %s with URL %s status code %s reason %s, response '%s', owner of %s" % (name, type, app, url, res.status_code, res.reason, res.text, owner))
            else:
                logger.debug("%s of type %s in app %s, ownership changed with response: %s, owner %s, sharing level %s" % (name, type, app, res.text, owner, sharing))
        
        logger.info("Created %s of type %s in app %s owner is %s sharing level %s" % (name, type, app, owner, sharing))

    ###########################
    #
    # macroCreation
    #   Runs the required queries to create or update the macro knowledge objects and then re-owns them to the correct user
    # 
    ###########################
    def runRestoreMacro(self, config, app, name, username, restoreAsUser, adminLevel, objExists):
        #Only admins can restore objects on behalf of someone else
        if config['owner'] != username and adminLevel == False:
            logger.error("Owner of the object is listed as %s, however user %s requested the restore and is not an admin, rejected" % (config['owner'], username))
            return
        
        #Only admins can restore objects into someone else's name
        if restoreAsUser != "" and restoreAsUser != username and adminLevel == False:
            logger.error("restoreAsUser is %s which is not the username of %s, this user is not an admin, rejected")
            return

        logger.info("Attempting to run macro restore with name %s, username %s, restoreAsUser %s, adminLevel %s, objExists %s" % (name, username, restoreAsUser, adminLevel, objExists))            
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
            logger.info("Attempting to create macro %s on URL with name %s in app %s" % (name, url, app))

            payload = { "__stanza" : name }
            #Create macro
            #I cannot seem to get this working on the /conf URL but this works so good enough, and it's in the REST API manual...
            #servicesNS/-/search/properties/macros
            #__stanza = <name>
            
            res = requests.post(url, auth=auth, headers=headers, verify=False, data=payload)
            if (res.status_code != requests.codes.ok and res.status_code != 201):
                logger.error("%s of type macro in app %s with URL %s status code %s reason %s, response '%s', owner %s" % (name, app, url, res.status_code, res.reason, res.text, owner))
            else:
                #Macros always have the username in this URL context
                objURL = "%s/servicesNS/%s/%s/configs/conf-macros/%s" % (self.splunk_rest, owner, app, name)
                logger.debug("%s of type macro in app %s recording deletion URL as %s with owner %s" % (name, app, objURL, owner))

            logger.debug("%s of type macro in app %s, received response of: '%s'" % (name, app, res.text))

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
        
        logger.debug("Attempting to modify macro %s on URL %s with payload '%s' in app %s" % (name, url, payload, app))
        res = requests.post(url, auth=auth, headers=headers, verify=False, data=payload)
        if (res.status_code != requests.codes.ok and res.status_code != 201):
            logger.error("%s of type macro in app %s with URL %s status code %s reason %s, response '%s'" % (name, app, url, res.status_code, res.reason, res.text))
        else:
            #Re-owning it, I've switched URL's again here but it seems to be working so will not change it
            url = "%s/servicesNS/%s/%s/configs/conf-macros/%s/acl" % (self.splunk_rest, owner, app, name)
            payload = { "owner": owner, "sharing" : sharing }
            logger.info("Attempting to change ownership of macro %s via URL %s to owner %s in app %s with sharing %s" % (name, url, owner, app, sharing))
            res = requests.post(url, auth=auth, headers=headers, verify=False, data=payload)
            if (res.status_code != requests.codes.ok):
                logger.error("%s of type macro in app %s with URL %s status code %s reason %s, response '%s', owner %s sharing level %s" % (name, app, url, res.status_code, res.reason, res.text, owner, sharing))
            else:
                logger.debug("%s of type macro in app %s, ownership changed with response '%s', new owner %s and sharing level %s" % (name, app, res.text, owner, sharing))
    
    ###########################
    #
    # macros
    # 
    ###########################
    #macro use cases are slightly different to everything else on the REST API
    #enough that this code has not been integrated into the runQuery() function
    def macros(self, app, name, scope, user, restoreAsUser, adminLevel):
        #servicesNS/-/-/properties/macros doesn't show private macros so using /configs/conf-macros to find all the macros
        #again with count=-1 to find all the available macros
        url = self.splunk_rest + "/servicesNS/-/" + app + "/configs/conf-macros/" + name + "?output_mode=json"
        logger.debug("Running requests.get() on %s with username %s in app %s for type macro" % (url, self.destUsername, app))
        
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
            logger.error("User %s, while attempting to restore %s, found invalid scope of %s" % (user, name, scope))

        headers = {}
        auth = None
        if not self.destUsername:
            headers={'Authorization': 'Splunk %s' % self.session_key}
        else:
            auth = HTTPBasicAuth(self.destUsername, self.destPassword)
        
        #Verify=false is hardcoded to workaround local SSL issues
        res = requests.get(url, auth=auth, headers=headers, verify=False)
        objExists = False
        if (res.status_code == 404):
            logger.debug("URL %s is throwing a 404, assuming new object creation" % (url))
        elif (res.status_code != requests.codes.ok):
            logger.error("Type macro in app %s, URL %s status code %s reason %s, response '%s'" % (app, url, res.status_code, res.reason, res.text))
        else:
            #However the fact that we did not get a 404 does not mean it exists in the context we expect it to, perhaps it's global and from another app context?
            #or perhaps it's app level but we're restoring a private object...
            logger.debug("Attempting to JSON loads on %s" % (res.text))
            resDict = json.loads(res.text)
            for entry in resDict['entry']:
                sharingLevel = entry['acl']['sharing']
                appContext = entry['acl']['app']
                if appContext == app and appScope == True and (sharingLevel == 'app' or sharingLevel == 'global'):
                    objExists = True
                elif appContext == app and userScope == True and sharingLevel == "user":
                    objExists = True
        
        configList = []
        
        #This object is at user scope or may be at user scope
        if userScope == True:
            userDir = self.gitTempDir + "/" + app + "/" + "user"
            #user directory exists
            if os.path.isdir(userDir):
                typeFile = userDir + "/macros"
                #We found the file, now open it to obtain the contents
                if os.path.isfile(typeFile):
                    logger.debug("User %s, name %s, found %s file to restore from" % (user, name, typeFile))
                    with open(typeFile, 'r') as f:
                        configList = json.load(f)
                        found = False
                        for configItem in configList:
                            #We found the relevant item, now restore it
                            if configItem['name'] == name:
                                logger.debug("User %s, name %s is found, dictionary is %s" % (user, name, configItem))
                                self.runRestoreMacro(configItem, app, name, user, restoreAsUser, adminLevel, objExists)
                                found = True
                        #We never found the relevant item
                        if found == False:
                            logger.info("User %s, name %s not found at user level scope in file %s" % (user, name, typeFile))
                #The config file did not exist
                else:
                    logger.info("User %s, name %s, did not find a %s file to restore from" % (user, name, typeFile))
            else:
                #There are no user level objects for this app, therefore the restore will not occur at this scope
                logger.info("user directory of %s does not exist" % (userDir))

        #The object is either app or globally scoped
        if appScope == True:
            appDir = self.gitTempDir + "/" + app + "/" + "app"
            #app directory exists
            if os.path.isdir(appDir):
                typeFile = appDir + "/macros"
                #We found the file, open it and load the config
                if os.path.isfile(typeFile):
                    logger.debug("User %s, name %s, found %s file to restore from" % (user, name, typeFile))
                    with open(typeFile, 'r') as f:
                        configList = json.load(f)
                        found = False
                        #We found the item, now restore it
                        for configItem in configList:
                            if configItem['name'] == name:
                                logger.debug("User %s, name %s is found, dictionary is %s" % (user, name, configItem))
                                self.runRestoreMacro(configItem, app, name, user, restoreAsUser, adminLevel, objExists)
                                found = True
                        #We never found the item
                        if found == False:
                            logger.info("User %s, name %s not found at app level scope in file %s" % (user, name, typeFile))
                #We never found the file to restore from
                else:
                    logger.info("User %s, name %s, did not find a %s file to restore from" % (user, name, typeFile))
            else:
                #There are no app level objects for this app, therefore the restore will not occur at this scope
                logger.info("app directory of %s does not exist" % (appDir))
            
            globalDir = self.gitTempDir + "/" + app + "/" + "global"
            #global directory exists
            if os.path.isdir(globalDir):
                typeFile = globalDir + "/macros"
                #We found the file, attempt to load the config
                if os.path.isfile(typeFile):
                    logger.debug("User %s, name %s, found %s file to restore from" % (user, name, typeFile))
                    with open(typeFile, 'r') as f:
                        configList = json.load(f)
                        found = False
                        for configItem in configList:
                            #We found the item,  now restore it
                            if configItem['name'] == name:
                                logger.debug("User %s, name %s is found, dictionary is %s" % (user, name, configItem))
                                self.runRestoreMacro(configItem, app, name, user, restoreAsUser, adminLevel, objExists)
                                found = True
                        #We never found the item
                        if found == False:
                            logger.info("User %s, name %s not found at global level scope in file %s" % (user, name, typeFile))
                #We did not find the file to restore from
                else:
                    logger.info("User %s, name %s, did not find a %s file to restore from" % (user, name, typeFile))
            else:
                #There are no global level objects for this app, therefore the restore will not occur at this scope
                logger.info("global directory of %s does not exist" % (globalDir))

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
        logger.debug("Running requests.get() on %s with username %s" % (url, self.destUsername))
        data = { "search" : query, "output_mode" : "json", "exec_mode" : "oneshot", "earliest_time" : earliest_time }
        
        #no destUsername, use the session_key method    
        headers = {}
        auth = None
        if not self.destUsername:
            headers = {'Authorization': 'Splunk %s' % self.session_key }
        else:
            auth = HTTPBasicAuth(self.destUsername, self.destPassword)
        
        res = requests.post(url, auth=auth, headers=headers, verify=False, data=data)
        if (res.status_code != requests.codes.ok):
            logger.error("URL %s status code %s reason %s, response '%s'" % (url, res.status_code, res.reason, res.text))
        res = json.loads(res.text)
        
        return res

    ###########################
    #
    # Main logic section
    #
    ##########################    
    def run_script(self):
        config = self.get_config()
        #If we want debugMode, keep the debug logging, otherwise drop back to INFO level
        if 'debugMode' in config:
            debugMode = config['debugMode'].lower()
            if debugMode == "true" or debugMode == "t":
                logging.getLogger().setLevel(logging.DEBUG)        
        
        useLocalAuth = False
        if 'useLocalAuth' in config:
            useLocalAuth = config['useLocalAuth'].lower()
            if useLocalAuth == "true" or useLocalAuth=="t":
                useLocalAuth = True
            else:
                useLocalAuth = False
        
        #If we're not using the useLocalAuth we must have a username/password to work with
        if useLocalAuth == False and ('destUsername' not in config or 'destPassword' not in config):
            logger.fatal("useLocalAuth is not set to true and destUsername/destPassword not set, exiting with failure")
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
        logger.info("Splunk Version Control Restore run with arguments %s" % (cleanArgs))

        self.session_key = config['session_key']
        
        knownAppList = []
        self.gitTempDir = config['gitTempDir']
        if os.path.isdir(self.gitTempDir):
            #include the subdirectory which is the git repo
            self.gitTempDir = self.gitTempDir + "/" + os.listdir(self.gitTempDir)[0]
        else:
            #make the directory and clone under here
            os.mkdir(self.gitTempDir)
            #Initially we must trust our remote repo URL
            (output, stderrout, res) = self.runOSProcess("ssh -n -o \"BatchMode yes\" -o StrictHostKeyChecking=no " + self.gitRepoURL[:self.gitRepoURL.find(":")])
            if res == False:
                logger.warn("Unexpected failure while attempting to trust the remote git repo?! stdout '%s' stderr '%s'" % (output, stderrout))
            
            #Clone the remote git repo
            (output, stderrout, res) = self.runOSProcess("cd %s; git clone %s" % (self.gitTempDir, self.gitRepoURL), timeout=30)
            if res == False:
                logger.fatal("git clone failed for some reason...on url %s stdout of '%s' with stderrout of '%s'" % (self.gitRepoURL, output, stderrout))
                sys.exit(1)
            else:
                logger.debug("result from git command: %s, output '%s' with stderroutput of '%s'" % (res, output, stderrout))
                logger.info("Successfully cloned the git URL from %s into directory %s" % (self.gitRepoURL, self.gitTempDir))
                self.gitTempDir = self.gitTempDir + "/" + os.listdir(self.gitTempDir)[0]
        
        #Version Control File that lists what restore we need to do...
        restoreList = "splunkversioncontrol_restorelist"
        res = self.runSearchJob("| inputlookup %s" % (restoreList))
        resList = res["results"]

        if len(resList) == 0:
            logger.info("No restore required at this point in time")
        else:
            #Do a git pull to ensure we are up-to-date
            (output, stderrout, res) = self.runOSProcess("cd %s; git checkout master; git pull" % (self.gitTempDir), timeout=30)
            if res == False:
                logger.fatal("git pull failed for some reason...on url %s stdout of '%s' with stderrout of '%s'" % (self.gitRepoURL, output, stderrout))
                sys.exit(1)
            else:
                logger.debug("result from git command: %s, output '%s' with stderroutput of '%s'" % (res, output, stderrout))
                logger.info("Successfully ran the git pull for URL %s from directory %s" % (self.gitRepoURL, self.gitTempDir))
            
            logger.debug("The restore list is %s" % (resList))
            
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
                logger.warn("Unable to run 'SplunkVersionControl CheckAdmin' for some reason with ldapFilter %s and usernameFilter %s" % (ldapFilter, usernameFilter))
            else:
                userResList = res["results"]
            
            
            #Create a list of admins
            adminList = []
            for userRes in userResList:
                username = userRes["username"]
                logger.debug("Adding %s as an admin username" % (username))
                adminList.append(username)
            
            # Run yet another query, this one provides a list of times/usernames at which valid entries were added to the lookup file
            # if the addition to the lookup file was not done via the required report then the restore is not done (as anyone can add a new role
            # and put the username as an admin user!)
            res = self.runSearchJob("| savedsearch \"SplunkVersionControl Audit Query\"", earliest_time=auditLogsLookupBackTime)
            auditEntries = []
            if 'results' not in res:
                logger.warn("Unable to run 'SplunkVersionControl Audit Query' for some reason with earliest_time %s" % (auditLogsLookupBackTime))
            else:
                auditEntries = res["results"]
                logger.debug("Audit Entries are: '%s'" % (auditEntries))
            
            #Cycle through each result from the earlier lookup and run the required restoration
            for aRes in resList:
                time = aRes['time']
                app = aRes['app']
                name = aRes['name']
                restoreAsUser = aRes['restoreAsUser']
                tag = aRes['tag']
                type = aRes['type']
                user = aRes['user']
                scope = aRes['scope']

                logger.info("User %s has requested the object with name %s of type %s to be restored from tag %s and scope of %s, restoreAsUser is %s request was requested at %s" % (user, name, type, tag, scope, restoreAsUser, time))                
                
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
                            logger.warn("User %s found time entry of %s with username %s, however expected %s, rejecting this entry for name %s of type %s in app %s with restoreAsUser %s" % (user, time, auditUser, name, type, app, restoreAsUser))
                            continue
                        else:
                            logger.debug("User %s, found time entry of %s, considering this a valid entry and proceeding to restore" % (user, time))
                
                if found == False:
                    logger.warn("Unable to find a time entry of %s matching the auditEntries list of %s, skipping this entry" % (time, auditEntries))
                    continue
                
                adminLevel = False
                
                if user in adminList:
                    logger.debug("User %s is an admin and has requested object %s of type %s in app %s to be restored with username of %s time of %s" % (user, name, type, app, restoreAsUser, time))
                    adminLevel = True
                
                #Only admins can restore objects as another user
                if restoreAsUser != "" and restoreAsUser != user and adminLevel == False:
                    logger.error("User %s is not an admin and has attempted to restore as a different user, requested user is %s, object %s of type %s in app %s to be restored with username of %s time of %s, rejected" % (user, restoreAsUser, name, type, app, restoreAsUser, time))
                    continue
                
                #Do a git pull to ensure we are up-to-date
                (output, stderrout, res) = self.runOSProcess("cd %s; git checkout %s" % (self.gitTempDir, tag))
                if res == False:
                    logger.error("User %s, object name %s, type %s, time %s, git checkout %s failed in directory %s stdout of '%s' with stderrout of '%s'" % (user, name, type, time, tag, self.gitTempDir, output, stderrout))
                else:
                    logger.debug("result from git command: %s, output '%s' with stderroutput of '%s'" % (res, output, stderrout))
                    logger.info("Successfully ran the git checkout for URL %s from directory %s" % (self.gitRepoURL, self.gitTempDir))

                knownAppList = []
                if os.path.isdir(self.gitTempDir):
                    #include the subdirectory which is the git repo
                    knownAppList = os.listdir(self.gitTempDir)
                    logger.debug("Known app list is %s" % (knownAppList))

                #If the app is not known, the restore stops here as we have nothing to restore from!
                if app not in knownAppList:
                    logger.error("User %s requested a restore from app %s but this is not in the knownAppList therefore restore cannot occur, object %s of type %s to be restored with username of %s time of %s" % (user, app, name, type, restoreAsUser, time))
                    continue
                
                #Deal with the different types of restores that might be required, we only do one row at a time...
                if type == "dashboard":
                    self.dashboards(app, name, scope, user, restoreAsUser, adminLevel)
                elif type == "savedsearch":
                    self.savedsearches(app, name, scope, user, restoreAsUser, adminLevel)
                elif type == "macro":
                    self.macros(app, name, scope, user, restoreAsUser, adminLevel)
                elif type == "fieldalias":
                    self.fieldaliases(app, name, scope, user, restoreAsUser, adminLevel)
                elif type == "fieldextraction":
                    self.fieldextractions(app, name, scope, user, restoreAsUser, adminLevel)
                elif type == "fieldtransformation":
                    self.fieldtransformations(app, name, scope, user, restoreAsUser, adminLevel)
                elif type == "navmenu":
                    self.navMenu(app, name, scope, user, restoreAsUser, adminLevel)
                elif type == "datamodel":
                    self.datamodels(app, name, scope, user, restoreAsUser, adminLevel)
                elif type == "panels":
                    self.panels(app, name, scope, user, restoreAsUser, adminLevel)
                elif type == "calcfields":
                    self.calcfields(app, name, scope, user, restoreAsUser, adminLevel)
                elif type == "workflowaction":
                    self.workflowactions(app, name, scope, user, restoreAsUser, adminLevel)
                elif type == "sourcetyperenaming":
                    self.sourcetyperenaming(app, name, scope, user, restoreAsUser, adminLevel)
                elif type == "tags":
                    self.tags(app, name, scope, user, restoreAsUser, adminLevel)
                elif type == "eventtypes":
                    self.eventtypes(app, name, scope, user, restoreAsUser, adminLevel)
                elif type == "lookupdef":
                    self.lookupDefinitions(app, name, scope, user, restoreAsUser, adminLevel)
                elif type == "automaticlookup":
                    self.automaticLookups(app, name, scope, user, restoreAsUser, adminLevel)
                elif type == "collection":
                    self.collections(app, name, scope, user, restoreAsUser, adminLevel)
                elif type == "viewstate":
                    self.viewstates(app, name, scope, user, restoreAsUser, adminLevel)
                elif type == "times":
                    self.times(app, name, scope, user, restoreAsUser, adminLevel)
                else:
                    logger.error("User %s, unknown type, no restore will occur for object %s of type %s in app %s to be restored with username of %s time of %s" % (user, name, type, app, restoreAsUser, time))

        #Wipe the lookup file so we do not attempt to restore these entries again
        if len(resList) != 0:
            res = self.runSearchJob("| makeresults | fields - _time | outputlookup %s" % (restoreList))
            logger.info("Cleared the lookup file to ensure we do not attempt to restore the same entries again")
        
        logger.info("Done")
    
    #Run an OS process with a timeout, this way if a command gets "stuck" waiting for input it is killed
    def runOSProcess(self, command, timeout=10):
        logger.debug("Running command '%s' with timeout %s" % (command, timeout))
        p = Popen(command, stdout=PIPE, stderr=PIPE, shell=True)
        for t in xrange(timeout):
            sleep(1)
            if p.poll() is not None:
                #return p.communicate()
                (stdoutdata, stderrdata) = p.communicate()
                if p.returncode != 0:
                    return stdoutdata, stderrdata, False
                else:
                    return stdoutdata, stderrdata, True
        p.kill()
        return "", "timeout after %s seconds" % (timeout), False