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
# Store Knowledge Objects
#   Attempt to run against the Splunk REST API to obtain various knowledge objects, then persist the knowledge object information required
#   to restore the knowledge object if it was deleted/changed to the filesystem
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
              'filename' : splunkLogsDir + '/splunkversioncontrol_backup.log',
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


class SplunkVersionControlBackup:

    splunk_rest = None
    srcUsername = None
    srcPassword = None
    session_key = None
    noPrivate = False
    noDisabled = False
    includeEntities = None
    excludeEntities = None
    includeOwner = None
    excludeOwner = None
    gitTempDir = None
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
                        shortName = stanza_name.replace("splunkversioncontrol_backup://", "")

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
                raise Exception, "Invalid configuration received from Splunk."
        except Exception, e:
            raise Exception, "Error getting Splunk configuration via STDIN: %s" % str(e)

        return config

    #Query Splunk for a list of all known apps, that way we can compare to what we have backed up
    def getAllAppsList(self):
        appList = []
        url = self.splunk_rest + "/services/apps/local?search=disabled%3D0&count=0&f=title"

        logger.debug("i=\"%s\" Running requests.get() on url=%s with user=%s to obtain a list of all applications" % (self.stanzaName, url, self.srcUsername))
        #no srcUsername, use the session_key method    
        headers = {}
        auth = None
        
        if not self.srcUsername:
            headers={'Authorization': 'Splunk %s' % self.session_key}
        else:
            auth = HTTPBasicAuth(self.srcUsername, self.srcPassword)
        
        #Verify=false is hardcoded to workaround local SSL issues
        res = requests.get(url, auth=auth, headers=headers, verify=False)
        if (res.status_code != requests.codes.ok):
            logger.fatal("i=\"%s\" Could not obtain a list of all apps, URL=%s statuscode=%s reason=%s, response=\"%s\"" % (self.stanzaName, url, res.status_code, res.reason, res.text))
            sys.exit(-1)

        #Splunk returns data in XML format, use the element tree to work through it
        root = ET.fromstring(res.text)
        
        for child in root:
            #Working per entry in the results
            if child.tag.endswith("entry"):
                #Down to each entry level
                for innerChild in child:
                    #name attribute
                    if innerChild.tag.endswith("title"):
                        name = innerChild.text
                        appList.append(name)
                        logger.debug("i=\"%s\" name=%s is the app added to the list" % (self.stanzaName, name))
        return appList
        
    ###########################
    #
    # runQueries (generic version)
    #   For each knowledge object type / app query the remote Splunk instance to obtain the configuration
    #   then persist the required configuration to the filesystem
    # 
    ###########################
    def runQueries(self, app, endpoint, type, fieldIgnoreList, aliasAttributes={}, valueAliases={}, nameOverride="", override=False):
        creationSuccess = []
        #Keep a success list to be returned by this function
        #Use count=-1 to ensure we see all the objects
        url = self.splunk_rest + "/servicesNS/-/" + app + endpoint + "?count=-1"
        logger.debug("i=\"%s\" Running requests.get() on %s user=%s in app=%s" % (self.stanzaName, url, self.srcUsername, app))

        headers = {}
        auth = None
        
        if not self.srcUsername:
            headers={'Authorization': 'Splunk %s' % self.session_key}
        else:
            auth = HTTPBasicAuth(self.srcUsername, self.srcPassword)
        
        #Verify=false is hardcoded to workaround local SSL issues
        res = requests.get(url, auth=auth, headers=headers, verify=False)
        if (res.status_code != requests.codes.ok):
            logger.error("i=\"%s\" URL=%s in app=%s statuscode=%s reason=%s response=\"%s\"" % (self.stanzaName, url, app, res.status_code, res.reason, res.text))
        
        #Splunk returns data in XML format, use the element tree to work through it
        root = ET.fromstring(res.text)

        infoList = {}
        for child in root:
            #Working per entry in the results
            if child.tag.endswith("entry"):
                #Down to each entry level
                info = {}
                #Some lines of data we do not want to keep, assume we want it
                keep = True
                for innerChild in child:
                    #title / name attribute
                    if innerChild.tag.endswith("title"):
                        title = innerChild.text
                        info["name"] = title
                        #Backup the original name if we override it, override works fine for creation
                        #but updates require the original name
                        if 'name' in aliasAttributes.values():
                            info["origName"] = title
                        
                        logger.debug("i=\"%s\" name=%s is the entry for type=%s in app=%s" % (self.stanzaName, title, type, app))
                        #If we have an include/exclude list we deal with that scenario now
                        if self.includeEntities:
                            if not title in self.includeEntities:
                                logger.debug("i=\"%s\" name=%s of type=%s not in includeEntities list in app=%s" % (self.stanzaName, info["name"], type, app))
                                keep = False
                                break
                        if self.excludeEntities:
                            if title in self.excludeEntities:
                                logger.debug("i=\"%s\" name=%s of type=%s in excludeEntities list in app=%s" % (self.stanzaName, info["name"], type, app))
                                keep = False
                                break
                    #Content apepars to be where 90% of the data we want is located
                    elif innerChild.tag.endswith("content"):
                        for theAttribute in innerChild[0]:
                            #acl has the owner, sharing and app level which we required (sometimes there is eai:app but it's not 100% consistent so this is safer
                            #also have switched from author to owner as it's likely the safer option...
                            if theAttribute.attrib['name'] == 'eai:acl':
                                for theList in theAttribute[0]:
                                    if theList.attrib['name'] == 'sharing':
                                        logger.debug("i=\"%s\" name=%s of type=%s has sharing=%s in app=%s" % (self.stanzaName, info["name"], type, theList.text, app))
                                        info["sharing"] = theList.text
                                        if self.noPrivate and info["sharing"] == "user":
                                            logger.debug("i=\"%s\" name=%s of type=%s found but the noPrivate flag is true, excluding this in app=%s" % (self.stanzaName, info["name"], type, app))
                                            keep = False
                                            break
                                    elif theList.attrib['name'] == 'app':
                                        foundApp = theList.text
                                        logger.debug("i=\"%s\" name=%s of type=%s in app context of app=%s belongs to app=%s" % (self.stanzaName, info["name"], type, app, foundApp))
                                        #We can see globally shared objects in our app context, it does not mean we should migrate them as it's not ours...
                                        if app != foundApp:
                                            logger.debug("i=\"%s\" name=%s of type=%s found in app context of app=%s belongs to app context app=%s, excluding from app=%s" % (self.stanzaName, info["name"], type, app, foundApp, app))
                                            keep = False
                                            break
                                    #owner is seen as a nicer alternative to the author variable
                                    elif theList.attrib['name'] == 'owner':
                                        owner = theList.text
                                        
                                        #If we have include or exlcude owner lists we deal with this now
                                        if self.includeOwner:
                                            if not owner in self.includeOwner:
                                                logger.debug("i=\"%s\" name=%s of type=%s with owner=%s not in includeOwner list in app=%s" % (self.stanzaName, info["name"], type, owner, app))
                                                keep = False
                                                break
                                        if self.excludeOwner:
                                            if owner in self.excludeOwner:
                                                logger.debug("i=\"%s\" name=%s of type=%s with owner=%s in excludeOwner list in app=%s" % (self.stanzaName, info["name"], type, owner, app))
                                                keep = False
                                                break
                                        logger.debug("i=\"%s\" name=%s of type=%s has owner=%s in app=%s" % (self.stanzaName, info["name"], type, owner, app))
                                        info["owner"] = owner

                            else:
                                #We have other attributes under content, we want the majority of them
                                attribName = theAttribute.attrib['name']
                                
                                #Under some circumstances we want the attribute and contents but we want to call it a different name...
                                if aliasAttributes.has_key(attribName):
                                    attribName = aliasAttributes[attribName]
                                
                                #If it's disabled *and* we don't want disabled objects we can determine this here
                                if attribName == "disabled" and self.noDisabled and theAttribute.text == "1":
                                    logger.debug("i=\"%s\" name=%s of type=%s is disabled and the noDisabled flag is true, excluding this in app=%s" % (self.stanzaName, info["name"], type, app))
                                    keep = False
                                    break
                                    
                                #Field extractions change from "Uses transform" to "REPORT" And "Inline" to "EXTRACTION" for some strange reason...
                                #therefore we have a list of attribute values that we deal with here which get renamed to the provided values
                                if valueAliases.has_key(theAttribute.text):
                                    theAttribute.text = valueAliases[theAttribute.text]
                                
                                logger.debug("i=\"%s\" name=%s of type=%s found key/value of %s=%s in app context app=%s" % (self.stanzaName, info["name"], type, attribName, theAttribute.text, app))

                                #Yet another hack, this time to deal with collections using accelrated_fields.<value> when looking at it via REST GET requests, but
                                #requiring accelerated_fields to be used when POST'ing the value to create the collection!
                                if type == "collections (kvstore definition)" and attribName.find("accelrated_fields") == 0:
                                    attribName = "accelerated_fields" + attribName[17:]
                                
                                #Hack to deal with datamodel tables not working as expected
                                if attribName == "description" and type=="datamodels" and info.has_key("dataset.type") and info["dataset.type"] == "table":
                                    #For an unknown reason the table datatype has extra fields in the description which must be removed
                                    #however we have to find them first...
                                    res = json.loads(theAttribute.text)
                                    fields = res['objects'][0]['fields']
                                    #We're looking through the dictionary and deleting from it so copy 
                                    #the dictionary so we can safely iterate through while deleting from the 
                                    #real copy
                                    fieldCopy = copy.deepcopy(fields)

                                    for field in fieldCopy:
                                        name = field['fieldName']
                                        logger.debug("i=\"%s\" name=%s" % (self.stanzaName, name))
                                        if name != "RootObject":
                                            index = fields.index(field)
                                            del fields[index]
                                    
                                    res = json.dumps(res)
                                    info[attribName] = res
                                #We keep the attributes that are not None
                                elif theAttribute.text:
                                    info[attribName] = theAttribute.text
                                #A hack related to automatic lookups, where a None / empty value must be sent through as "", otherwise requests will strip the entry from the
                                #post request. In the case of an automatic lookup we want to send through the empty value...
                                elif type=="automatic lookup" and theAttribute.text == None:
                                    info[attribName] = ""
                #If we have not set the keep flag to False
                if keep:
                    if nameOverride != "":
                        #keep a copy of the original name for use when checking if the object exists
                        info["origName"] = info["name"]
                        info["name"] = info[nameOverride]
                        #TODO hack to handle field extractions where they have an extra piece of info in the name
                        #as in the name is prepended with EXTRACT-, REPORT- or LOOKUP-, we need to remove this before creating
                        #the new version
                        if type=="fieldextractions" and info["name"].find("EXTRACT-") == 0:
                            logger.debug("i=\"%s\" Overriding name of name=%s of type=%s in app context app=%s with owner=%s to new name of newname=%s" % (self.stanzaName, info["name"], type, app, info["owner"], info["name"][8:]))
                            info["name"] = info["name"][8:]
                        elif type=="fieldextractions" and info["name"].find("REPORT-") == 0:
                            logger.debug("i=\"%s\" Overriding name of name=%s of type=%s in app context app=%s with owner=%s to new name of newname=%s" % (self.stanzaName, info["name"], type, app, info["owner"], info["name"][7:]))
                            info["name"] = info["name"][7:]
                        elif type=="automatic lookup" and info["name"].find("LOOKUP-") == 0:
                            logger.debug("i=\"%s\" Overriding name of name=%s of type=%s in app context app=%s with owner=%s to new name of newname=%s" % (self.stanzaName, info["name"], type, app, info["owner"], info["name"][7:]))
                            info["name"] = info["name"][7:]
                    
                    #Some attributes are not used to create a new version so we remove them...(they may have been used above first so we kept them until now)
                    for attribName in fieldIgnoreList:
                        if info.has_key(attribName):
                            del info[attribName]
                    
                    #Add this to the infoList
                    sharing = info["sharing"]
                    if not infoList.has_key(sharing):
                        infoList[sharing] = []
                        
                    #REST API does not support the creation of null queue entries as tested in 7.0.5 and 7.2.1, these are also unused on search heads anyway so ignoring these with a warning
                    if type == "fieldtransformations" and info.has_key("FORMAT") and info["FORMAT"] == "nullQueue":
                        logger.info("i=\"%s\" Dropping the backup of name=%s of type=%s in app context app=%s with owner=%s because nullQueue entries cannot be created via REST API (and they are not required in search heads)" % (self.stanzaName, info["name"], type, app, info["owner"]))
                    else:
                        infoList[sharing].append(info)
                        logger.info("i=\"%s\" Recording name=%s info for type=%s in app context app=%s with owner=%s" % (self.stanzaName, info["name"], type, app, info["owner"]))
        
                    creationSuccess.append(info["name"])
        
        #Find the storage directory for this app and create it if required
        appStorageDir = self.gitTempDir + "/" + app
        if not os.path.isdir(appStorageDir):
            os.mkdir(appStorageDir)
        
        #Cycle through each one we need to backup, we do global/app/user as users can duplicate app level objects with the same names
        #but we create everything at user level first then re-own it so global/app must happen first
        if infoList.has_key("global"):            
            #persist global to disk
            globalStorageDir = appStorageDir + "/global"
            logger.debug("i=\"%s\" Now persisting knowledge objects of type=%s with sharing=global in app=%s into dir=%s" % (self.stanzaName, type, app, globalStorageDir))
            if not os.path.isdir(globalStorageDir):
                os.mkdir(globalStorageDir)
            with open(globalStorageDir + "/" + type, 'w') as f:
                json.dump(infoList["global"], f)
        if infoList.has_key("app"):
            #persist app level to disk
            appLevelStorageDir = appStorageDir + "/app"
            logger.debug("i=\"%s\" Now persisting with knowledge objects of type=%s with sharing=app in app=%s into dir=%s" % (self.stanzaName, type, app, appLevelStorageDir))
            if not os.path.isdir(appLevelStorageDir):
                os.mkdir(appLevelStorageDir)
            with open(appLevelStorageDir + "/" + type, 'w') as f:
                json.dump(infoList["app"], f)
        if infoList.has_key("user"):
            #persist user level to disk
            userLevelStorageDir = appStorageDir + "/user"
            logger.debug("i=\"%s\" Now persisting with knowledge objects of type=%s sharing=user (private) in app=%s into dir=%s" % (self.stanzaName, type, app, userLevelStorageDir))
            if not os.path.isdir(userLevelStorageDir):
                os.mkdir(userLevelStorageDir)
            with open(userLevelStorageDir + "/" + type, 'w') as f:
                json.dump(infoList["user"], f)
        return creationSuccess

    ###########################
    #
    # macros
    # 
    ###########################
    #macro use cases are slightly different to everything else on the REST API
    #enough that this code has not been integrated into the runQuery() function
    #This function queries the REST API and stores the macros configuration to disk in JSON format
    def macros(self, app):
        macros = {}
        macroCreationSuccess = []
        
        #servicesNS/-/-/properties/macros doesn't show private macros so using /configs/conf-macros to find all the macros
        #again with count=-1 to find all the available macros
        url = self.splunk_rest + "/servicesNS/-/" + app + "/configs/conf-macros?count=-1"
        logger.debug("i=\"%s\" Running requests.get() on url=%s with user=%s in app=%s for type macro" % (self.stanzaName, url, self.srcUsername, app))
        
        headers = {}
        auth = None
        if not self.srcUsername:
            headers={'Authorization': 'Splunk %s' % self.session_key}
        else:
            auth = HTTPBasicAuth(self.srcUsername, self.srcPassword)
        
        #Verify=false is hardcoded to workaround local SSL issues
        res = requests.get(url, auth=auth, headers=headers, verify=False)
        if (res.status_code != requests.codes.ok):
            logger.error("i=\"%s\" Type macro in app=%s, URL=%s statuscode=%s reason=%s, response=\"%s\"" % (self.stanzaName, app, url, res.status_code, res.reason, res.text))
        
        #Parse the XML tree
        root = ET.fromstring(res.text)
        for child in root:
            #Working per entry in the results
            if child.tag.endswith("entry"):
                #Down to each entry level
                macroInfo = {}
                keep = True
                for innerChild in child:
                    #title is the name
                    if innerChild.tag.endswith("title"):
                        title = innerChild.text
                        macroInfo["name"] = title
                        logger.debug("i=\"%s\" Found type=macro title, name=%s in app=%s" % (self.stanzaName, title, app))
                        #Deal with the include/exclude lists
                        if self.includeEntities:
                            if not title in self.includeEntities:
                                logger.debug("i=\"%s\" name=%s of type=macro not in includeEntities list in app=%s" % (self.stanzaName, macroInfo["name"], app))
                                keep = False
                                break
                        if self.excludeEntities:
                            if title in self.excludeEntities:
                                logger.debug("i=\"%s\" name=%s of type=macro in excludeEntities list in app=%s" % (self.stanzaName, macroInfo["name"], app))
                                keep = False
                                break
                    #Content apepars to be where 90% of the data we want is located
                    elif innerChild.tag.endswith("content"):
                        for theAttribute in innerChild[0]:
                            #acl has the owner, sharing and app level which we required (sometimes there is eai:app but it's not 100% consistent so this is safer
                            #also have switched from author to owner as it's likely the safer option...
                            if theAttribute.attrib['name'] == 'eai:acl':
                                for theList in theAttribute[0]:
                                    if theList.attrib['name'] == 'sharing':
                                        logger.debug("i=\"%s\" name=%s of type=macro sharing=%s in app=%s" % (self.stanzaName, macroInfo["name"], theList.text, app))
                                        macroInfo["sharing"] = theList.text
                                        
                                        #If we are excluding private then check the sharing is not user level (private in the GUI)
                                        if self.noPrivate and macroInfo["sharing"] == "user":
                                            logger.debug("i=\"%s\" name=%s of type=macro found but the noPrivate flag is true, excluding this in app=%s" % (self.stanzaName, macroInfo["name"], app))
                                            keep = False
                                            break
                                    elif theList.attrib['name'] == 'app':
                                        logger.debug("i=\"%s\" macro app=%s" % (self.stanzaName, theList.text))
                                        foundApp = theList.text
                                        #We can see globally shared objects in our app context, it does not mean we should migrate them as it's not ours...
                                        if app != foundApp:
                                            logger.debug("i=\"%s\" name=%s of type macro found in app context of app=%s, belongs to app context app=%s, excluding it" % (self.stanzaName, macroInfo["name"], app, foundApp))
                                            keep = False
                                            break
                                    #owner is used as a nicer alternative to the author
                                    elif theList.attrib['name'] == 'owner':
                                        macroInfo["owner"] = theList.text
                                        owner = theList.text
                                        logger.debug("i=\"%s\" name=%s of type=macro owner=%s" % (self.stanzaName, macroInfo["name"], owner))
                                        if self.includeOwner:
                                            if not owner in self.includeOwner:
                                                logger.debug("i=\"%s\" name=%s of type=macro with owner=%s not in includeOwner list in app=%s" % (self.stanzaName, macroInfo["name"], owner, app))
                                                keep = False
                                                break
                                        if self.excludeOwner:
                                            if owner in self.excludeOwner:
                                                logger.debug("i=\"%s\" name=%s of type=macro with owner=%s in excludeOwner list in app=%s" % (self.stanzaName, macroInfo["name"], owner, app))
                                                keep = False
                                                break
                            else:
                                #We have other attributes under content, we want the majority of them
                                attribName = theAttribute.attrib['name']
                                #Check if we have hit hte disabled attribute and we have a noDisabled flag
                                if attribName == "disabled" and self.noDisabled and theAttribute.text == "1":
                                    logger.debug("i=\"%s\" noDisabled flag is true, name=%s of type=macro is disabled, excluded in app=%s" % (self.stanzaName, theAttribute.attrib['name'], app))
                                    keep = False
                                    break
                                else:
                                    #Otherwise we want this attribute
                                    attribName = theAttribute.attrib['name']
                                    #Some attributes do not work with the REST API or should not be migrated...
                                    logger.debug("i=\"%s\" name=%s of type=macro key/value pair of %s=%s in app=%s" % (self.stanzaName, macroInfo["name"], attribName, theAttribute.text, app))
                                    macroInfo[attribName] = theAttribute.text
                if keep:
                    #Add this to the infoList
                    sharing = macroInfo["sharing"]
                    if not macros.has_key(sharing):
                        macros[sharing] = []
                    macros[sharing].append(macroInfo)
                    logger.info("i=\"%s\" Recording macro info for name=%s in app=%s with owner=%s sharing=%s" % (self.stanzaName, macroInfo["name"], app, macroInfo["owner"], macroInfo["sharing"]))
                    macroCreationSuccess.append(macroInfo["name"])

        #Find the storage directory for this app and create if required
        appStorageDir = self.gitTempDir + "/" + app
        if not os.path.isdir(appStorageDir):
            os.mkdir(appStorageDir)
        
        #Cycle through each one we need to migrate, we do global/app/user as users can duplicate app level objects with the same names
        #but we create everything at user level first then re-own it so global/app must happen first
        if macros.has_key("global"):
            logger.debug("i=\"%s\" Now persisting knowledge objects of type=macro with sharing=global in app=%s" % (self.stanzaName, app))
            #persist global to disk
            globalStorageDir = appStorageDir + "/global"
            if not os.path.isdir(globalStorageDir):
                os.mkdir(globalStorageDir)
            with open(globalStorageDir + "/macros", 'w') as f:
                json.dump(macros["global"], f)
        if macros.has_key("app"):
            logger.debug("i=\"%s\" Now persisting knowledge objects of type=macro with sharing=app in app=%s" % (self.stanzaName, app))
            #persist app level to disk
            appLevelStorageDir = appStorageDir + "/app"
            if not os.path.isdir(appLevelStorageDir):
                os.mkdir(appLevelStorageDir)
            with open(appLevelStorageDir + "/macros", 'w') as f:
                json.dump(macros["app"], f)
        if macros.has_key("user"):
            logger.debug("i=\"%s\" Now persisting knowledge objects of type=macro with sharing=user (private) in app %s" % (self.stanzaName, app))
            #persist user level to disk
            userLevelStorageDir = appStorageDir + "/user"
            if not os.path.isdir(userLevelStorageDir):
                os.mkdir(userLevelStorageDir)
            with open(userLevelStorageDir + "/macros", 'w') as f:
                json.dump(macros["user"], f)
            
        return macroCreationSuccess


    ###########################
    #
    # Backup functions
    #   These functions backup the various knowledge objects mainly by calling the runQueries
    #   with the appropriate options for that type
    #   Excluding macros, they have their own function
    # 
    ###########################
    ###########################
    #
    # Dashboards
    # 
    ###########################
    def dashboards(self, app):
        ignoreList = [ "disabled", "eai:appName", "eai:digest", "eai:userName", "isDashboard", "isVisible", "label", "rootNode", "description" ]
        return self.runQueries(app, "/data/ui/views", "dashboards", ignoreList)

    ###########################
    #
    # Saved Searches
    # 
    ###########################
    def savedsearches(self, app):
        ignoreList = [ "embed.enabled", "triggered_alert_count" ]
            
        return self.runQueries(app, "/saved/searches", "savedsearches", ignoreList)

    ###########################
    #
    # field definitions
    # 
    ###########################
    def calcfields(self, app):
        ignoreList = [ "attribute", "type" ]
        aliasAttributes = { "field.name" : "name" }
        return self.runQueries(app, "/data/props/calcfields", "calcfields", ignoreList, aliasAttributes)
        
    def fieldaliases(self, app):
        ignoreList = [ "attribute", "type", "value" ]
        return self.runQueries(app, "/data/props/fieldaliases", "fieldaliases", ignoreList)

    def fieldextractions(self, app):
        ignoreList = [ "attribute" ]
        return self.runQueries(app, "/data/props/extractions", "fieldextractions", ignoreList, {}, { "Inline" : "EXTRACT", "Uses transform" : "REPORT" }, "attribute")

    def fieldtransformations(self, app):
        ignoreList = [ "attribute", "DEFAULT_VALUE", "DEPTH_LIMIT", "LOOKAHEAD", "MATCH_LIMIT", "WRITE_META", "eai:appName", "eai:userName", "DEST_KEY" ]
        return self.runQueries(app, "/data/transforms/extractions", "fieldtransformations", ignoreList)
        
    def workflowactions(self, app):
        ignoreList = [ "disabled", "eai:appName", "eai:userName" ]
        return self.runQueries(app, "/data/ui/workflow-actions", "workflow-actions", ignoreList)

    def sourcetyperenaming(self, app):
        ignoreList = [ "attribute", "disabled", "eai:appName", "eai:userName", "stanza", "type" ]
        return self.runQueries(app, "/data/props/sourcetype-rename", "sourcetype-rename", ignoreList)

    ###########################
    #
    # tags
    # 
    ##########################
    def tags(self, app):
        ignoreList = [ "disabled", "eai:appName", "eai:userName" ]
        return self.runQueries(app, "/configs/conf-tags", "tags", ignoreList)

    ###########################
    #
    # eventtypes
    # 
    ##########################
    def eventtypes(self, app):
        ignoreList = [ "disabled", "eai:appName", "eai:userName" ]
        return self.runQueries(app, "/saved/eventtypes", "eventtypes", ignoreList)

    ###########################
    #
    # navMenus
    # 
    ##########################
    def navMenu(self, app):
        ignoreList = [ "disabled", "eai:appName", "eai:userName", "eai:digest", "rootNode" ]
        #If override we override the default nav menu of the destination app
        return self.runQueries(app, "/data/ui/nav", "navMenu", ignoreList)

    ###########################
    #
    # data models
    # 
    ##########################
    def datamodels(self, app):
        ignoreList = [ "disabled", "eai:appName", "eai:userName", "eai:digest", "eai:type", "acceleration.allowed" ]
        #If override we override the default nav menu of the destination app
        return self.runQueries(app, "/datamodel/model", "datamodels", ignoreList)

    ###########################
    #
    # collections
    #
    ##########################
    def collections(self, app):
        ignoreList = [ "eai:appName", "eai:userName", "type" ]
        #nobody is the only username that can be used when working with collections
        return self.runQueries(app, "/storage/collections/config", "collections_kvstore", ignoreList)

    ###########################
    #
    # viewstates
    #
    ##########################
    def viewstates(self, app):
        ignoreList = [ "eai:appName", "eai:userName" ]
        #nobody is the only username that can be used when working with collections
        return self.runQueries(app, "/configs/conf-viewstates", "viewstates", ignoreList)

    ###########################
    #
    # time labels (conf-times)
    #
    ##########################
    def times(self, app):
        ignoreList = [ "disabled", "eai:appName", "eai:userName", "header_label" ]
        return self.runQueries(app, "/configs/conf-times", "times_conf-times", ignoreList)

    ###########################
    #
    # panels
    #
    ##########################
    def panels(self, app):
        ignoreList = [ "disabled", "eai:digest", "panel.title", "rootNode", "eai:appName", "eai:userName" ]
        return self.runQueries(app, "/data/ui/panels", "pre-built_dashboard_panels", ignoreList)
        
    ###########################
    #
    # lookups (definition/automatic)
    #
    ##########################
    def lookupDefinitions(self, app):
        ignoreList = [ "disabled", "eai:appName", "eai:userName", "CAN_OPTIMIZE", "CLEAN_KEYS", "DEPTH_LIMIT", "KEEP_EMPTY_VALS", "LOOKAHEAD", "MATCH_LIMIT", "MV_ADD", "SOURCE_KEY", "WRITE_META", "fields_array", "type" ]
        #If override we override the default nav menu of the destination app
        return self.runQueries(app, "/data/transforms/lookups", "lookup_definition", ignoreList)

    def automaticLookups(self, app):
        ignoreList = [ "attribute", "type", "value" ]
        return self.runQueries(app, "/data/props/lookups", "automatic_lookups", ignoreList, {}, {}, "attribute")

    ###########################
    #
    # Logging functions for the output we provide at the end of a migration run
    #
    ##########################
    def logStats(self, successList, type, app):
        logger.info("i=\"%s\" app=%s, %d type=%s successfully saved" % (self.stanzaName, app, len(successList), type))

    ###########################
    #
    # Helper/utility functions
    #
    ##########################
    #helper function as per https://stackoverflow.com/questions/31433989/return-copy-of-dictionary-excluding-specified-keys
    def without_keys(self, d, keys):
        return {x: d[x] for x in d if x not in keys}

    #Run a Splunk query via the search/jobs endpoint
    def runSearchJob(self, query):
        url = self.splunk_rest + "/servicesNS/-/%s/search/jobs" % (self.appName)
        logger.debug("i=\"%s\" Running requests.post() on url=%s with user=%s query=\"%s\"" % (self.stanzaName, url, self.srcUsername, query))
        data = { "search" : query, "output_mode" : "json", "exec_mode" : "oneshot" }
        
        #no srcUsername, use the session_key method    
        headers = {}
        auth = None
        if not self.srcUsername:
            headers = {'Authorization': 'Splunk %s' % self.session_key }
        else:
            auth = HTTPBasicAuth(self.srcUsername, self.srcPassword)
        res = requests.post(url, auth=auth, headers=headers, verify=False, data=data)
        if (res.status_code != requests.codes.ok):
            logger.error("i=\"%s\" URL=%s statuscode=%s reason=%s response=\"%s\"" % (self.stanzaName, url, res.status_code, res.reason, res.text))
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
    
    #We keep a remote excluded app list so we don't backup anything that we are requested not to backup...
    def removeExcludedApps(self, appList):
        res = self.runSearchJob("| inputlookup splunkversioncontrol_globalexclusionlist")
        resList = res["results"]
        for appDict in resList:
            appName = appDict["app"]
            if appName in appList:
                appList.remove(appName)

    #Working on a per app basis, trigger the backup of the relevant types of objects
    def perApp(self, srcApp, macrosRun, tagsRun, eventtypesRun, calcFieldsRun, fieldAliasRun, fieldTransformsRun, fieldExtractionRun, collectionsRun, lookupDefinitionRun, automaticLookupRun, timesRun, viewstatesRun, panelsRun, datamodelsRun, dashboardsRun, savedsearchesRun, workflowActionsRun, sourcetypeRenamingRun, navMenuRun):
        ###########################
        #
        # Success / Failure lists
        #   these are used later in the code to print what worked, what failed et cetera
        #
        ##########################
        savedsearchCreationSuccess = []
        calcfieldsCreationSuccess = []
        fieldaliasesCreationSuccess = []
        fieldextractionsCreationSuccess = []
        dashboardCreationSuccess = []
        fieldTransformationsSuccess = []
        workflowActionsSuccess = []
        sourcetypeRenamingSuccess = []
        tagsSuccess = []
        eventtypesSuccess = []
        navMenuSuccess = []
        datamodelSuccess = []
        lookupDefinitionsSuccess = []
        automaticLookupsSuccess = []
        collectionsSuccess = []
        viewstatesSuccess = []
        timesSuccess = []
        panelsSuccess = []
        macroCreationSuccess = []

        ###########################
        #
        # Run the required functions based on the args
        #   Based on the command line parameters actually run the functions which will migrate the knowledge objects
        #
        ##########################
        if macrosRun:
            logger.info("i=\"%s\" Begin macros transfer for app=%s" % (self.stanzaName, srcApp))
            macroCreationSuccess = self.macros(srcApp)
            logger.info("i=\"%s\" End macros transfer for app=%s" % (self.stanzaName, srcApp))

        if tagsRun:
            logger.info("i=\"%s\" Begin tags transfer for app=%s" % (self.stanzaName, srcApp))
            tagsSuccess = self.tags(srcApp)
            logger.info("i=\"%s\" End tags transfer for app=%s" % (self.stanzaName, srcApp))

        if eventtypesRun:
            logger.info("i=\"%s\" Begin eventtypes transfer for app=%s" % (self.stanzaName, srcApp))
            eventtypesSuccess = self.eventtypes(srcApp)
            logger.info("i=\"%s\" End eventtypes transfer for app=%s" % (self.stanzaName, srcApp))

        if calcFieldsRun:
            logger.info("i=\"%s\" Begin calcFields transfer for app=%s" % (self.stanzaName, srcApp))
            calcfieldsCreationSuccess = self.calcfields(srcApp)
            logger.info("i=\"%s\" End calcFields transfer for app=%s" % (self.stanzaName, srcApp))

        if fieldAliasRun:
            logger.info("i=\"%s\" Begin fieldAlias transfer for app=%s" % (self.stanzaName, srcApp))
            fieldaliasesCreationSuccess = self.fieldaliases(srcApp)
            logger.info("i=\"%s\" End fieldAlias transfer for app=%s" % (self.stanzaName, srcApp))

        if fieldTransformsRun:
            logger.info("i=\"%s\" Begin fieldTransforms transfer for app=%s" % (self.stanzaName, srcApp))
            fieldTransformationsSuccess = self.fieldtransformations(srcApp)
            logger.info("i=\"%s\" End fieldTransforms transfer for app=%s" % (self.stanzaName, srcApp))

        if fieldExtractionRun:
            logger.info("i=\"%s\" Begin fieldExtraction transfer for app=%s" % (self.stanzaName, srcApp))
            fieldextractionsCreationSuccess = self.fieldextractions(srcApp)
            logger.info("i=\"%s\" End fieldExtraction transfer for app=%s" % (self.stanzaName, srcApp))

        if collectionsRun:
            logger.info("i=\"%s\" Begin collections (kvstore definition) transfer for app=%s" % (self.stanzaName, srcApp))
            collectionsSuccess = self.collections(srcApp)
            logger.info("i=\"%s\" End collections (kvstore definition) transfer for app=%s" % (self.stanzaName, srcApp))

        if lookupDefinitionRun:
            logger.info("i=\"%s\" Begin lookupDefinitions transfer for app=%s" % (self.stanzaName, srcApp))
            lookupDefinitionsSuccess = self.lookupDefinitions(srcApp)
            logger.info("i=\"%s\" End lookupDefinitions transfer for app=%s" % (self.stanzaName, srcApp))

        if automaticLookupRun:
            logger.info("i=\"%s\" Begin automaticLookup transfer for app=%s" % (self.stanzaName, srcApp))
            automaticLookupsSuccess = self.automaticLookups(srcApp)
            logger.info("i=\"%s\" End automaticLookup transfer for app=%s" % (self.stanzaName, srcApp))

        if timesRun:
            logger.info("i=\"%s\" Begin times (conf-times) transfer for app=%s" % (self.stanzaName, srcApp))
            timesSuccess = self.times(srcApp)
            logger.info("i=\"%s\" End times (conf-times) transfer for app=%s" % (self.stanzaName, srcApp))

        if viewstatesRun:
            logger.info("i=\"%s\" Begin viewstates transfer for app=%s" % (self.stanzaName, srcApp))
            viewstatesSuccess = self.viewstates(srcApp)
            logger.info("i=\"%s\" End viewstates transfer for app=%s" % (self.stanzaName, srcApp))
            
        if panelsRun:
            logger.info("i=\"%s\" Begin pre-built dashboard panels transfer for app=%s" % (self.stanzaName, srcApp))
            panelsSuccess = self.panels(srcApp)
            logger.info("i=\"%s\" End pre-built dashboard panels transfer for app=%s" % (self.stanzaName, srcApp))
            
        if datamodelsRun:
            logger.info("i=\"%s\" Begin datamodels transfer for app=%s" % (self.stanzaName, srcApp))
            datamodelSuccess = self.datamodels(srcApp)
            logger.info("i=\"%s\" End datamodels transfer for app=%s" % (self.stanzaName, srcApp))

        if dashboardsRun:
            logger.info("i=\"%s\" Begin dashboards transfer for app=%s" % (self.stanzaName, srcApp))
            dashboardCreationSuccess = self.dashboards(srcApp)
            logger.info("i=\"%s\" End dashboards transfer for app=%s" % (self.stanzaName, srcApp))

        if savedsearchesRun:
            logger.info("i=\"%s\" Begin savedsearches transfer for app=%s" % (self.stanzaName, srcApp))
            savedsearchCreationSuccess = self.savedsearches(srcApp)
            logger.info("i=\"%s\" End savedsearches transfer for app=%s" % (self.stanzaName, srcApp))

        if workflowActionsRun:
            logger.info("i=\"%s\" Begin workflowActions transfer for app=%s" % (self.stanzaName, srcApp))
            workflowActionsSuccess = self.workflowactions(srcApp)
            logger.info("i=\"%s\" End workflowActions transfer for app=%s" % (self.stanzaName, srcApp))

        if sourcetypeRenamingRun:
            logger.info("i=\"%s\" Begin sourcetypeRenaming transfer for app=%s" % (self.stanzaName, srcApp))
            sourcetypeRenamingSuccess = self.sourcetyperenaming(srcApp)
            logger.info("i=\"%s\" End sourcetypeRenaming transfer for app=%s" % (self.stanzaName, srcApp))

        if navMenuRun:
            logger.info("i=\"%s\" Begin navMenu transfer for app=%s" % (self.stanzaName, srcApp))
            navMenuSuccess = self.navMenu(srcApp)
            logger.info("i=\"%s\" End navMenu transfer for app=%s" % (self.stanzaName, srcApp))

        self.logStats(macroCreationSuccess, "macros", srcApp)
        self.logStats(tagsSuccess, "tags", srcApp)
        self.logStats(eventtypesSuccess, "eventtypes", srcApp)
        self.logStats(calcfieldsCreationSuccess, "calcfields", srcApp)
        self.logStats(fieldaliasesCreationSuccess, "fieldaliases", srcApp)
        self.logStats(fieldextractionsCreationSuccess, "fieldextractions", srcApp)
        self.logStats(fieldTransformationsSuccess, "fieldtransformations", srcApp)
        self.logStats(lookupDefinitionsSuccess, "lookupdef", srcApp)
        self.logStats(automaticLookupsSuccess, "automatic lookup", srcApp)
        self.logStats(viewstatesSuccess, "viewstates", srcApp)
        self.logStats(datamodelSuccess, "datamodels", srcApp)
        self.logStats(dashboardCreationSuccess, "dashboard", srcApp)
        self.logStats(savedsearchCreationSuccess, "savedsearch", srcApp)
        self.logStats(workflowActionsSuccess, "workflowactions", srcApp)
        self.logStats(sourcetypeRenamingSuccess, "sourcetype-renaming", srcApp)
        self.logStats(navMenuSuccess, "navMenu", srcApp)
        self.logStats(collectionsSuccess, "collections", srcApp)
        self.logStats(timesSuccess, "times (conf-times)", srcApp)
        self.logStats(panelsSuccess, "pre-built dashboard panels", srcApp)    

    ###########################
    #
    # Main logic section
    #
    ##########################    
    def run_script(self):
        config = self.get_config()
        #If we want debugMode, keep the debug logging, otherwise leave this at INFO level
        if 'debugMode' in config:
            debugMode = config['debugMode'].lower()
            if debugMode == "true" or debugMode == "t":
                logging.getLogger().setLevel(logging.DEBUG)
        
        #stanza_name without the splunkversioncontrol_backup://
        self.stanzaName = config["name"].replace("splunkversioncontrol_backup://", "")
        
        ###########################
        #
        # Include/Exclude lists
        #   we have the option of allowing only particular entities, or excluding some entities
        #   we also do the same trick for owners so we can include only some users or exclude some users from migration
        #
        ##########################
        if 'includeEntities' in config:
            self.includeEntities = [x.strip() for x in config['includeEntities'].split(',')]

        if 'excludeEntities' in config:
            self.excludeEntities = [x.strip() for x in config['excludeEntities'].split(',')]
            
        if 'excludeOwner' in config:
            self.excludeOwner = [x.strip() for x in config['excludeOwner'].split(',')]

        if 'includeOwner' in config:
            self.includeOwner = [x.strip() for x in config['includeOwner'].split(',')]
        
        if 'noPrivate' in config:
            self.noPrivate = config['noPrivate'].lower()
            if self.noPrivate == "true" or self.noPrivate=="t":
                self.noPrivate = True
            else:
                self.noPrivate = False
                
        if 'noDisabled' in config:
            self.noDisabled = config['noDisabled'].lower()
            if self.noDisabled == "true" or self.noDisabled=="t":
                self.noDisabled = True
            else:
                self.noDisabled = False
        
        useLocalAuth = False
        if 'useLocalAuth' in config:
            useLocalAuth = config['useLocalAuth'].lower()
            if useLocalAuth == "true" or useLocalAuth=="t":
                useLocalAuth = True
            else:
                useLocalAuth = False
        
        #If we're not using the useLocalAuth we must have a username/password to work with
        if useLocalAuth == False and ('srcUsername' not in config or 'srcPassword' not in config):
            logger.fatal("i=\"%s\" useLocalAuth is not set to true and srcUsername/srcPassword not set, exiting with failure" % (self.stanzaName))
            sys.exit(1)
        
        if useLocalAuth == False:
            self.srcUsername = config['srcUsername']
            self.srcPassword = config['srcPassword']
        
        if 'remoteAppName' in config:
            self.appName = config['remoteAppName']
         
        self.gitRepoURL = config['gitRepoURL']
        
        #From server
        self.splunk_rest = config['srcURL']
        excludedList = [ "srcPassword", "session_key" ]
        cleanArgs = self.without_keys(config, excludedList)
        logger.info("i=\"%s\" Splunk Version Control Backup run with arguments=%s" % (self.stanzaName, cleanArgs))

        currentEpochTime = calendar.timegm(time.gmtime())
        self.session_key = config['session_key']
        
        #Use current epoch to output lookup at the end
        #use lookup to check if we have run before, if so run queries if not just backup everything
        appList = self.getAllAppsList()

        logger.debug("i=\"%s\" AppList is (before trim) %s" % (self.stanzaName, appList))
        self.removeExcludedApps(appList)
        logger.debug("i=\"%s\" AppList is (post trim) %s" % (self.stanzaName, appList))

        self.gitTempDir = config['gitTempDir']
        dirExists = os.path.isdir(self.gitTempDir)
        if dirExists and len(os.listdir(self.gitTempDir)) != 0:
            #include the subdirectory which is the git repo
            self.gitTempDir = self.gitTempDir + "/" + os.listdir(self.gitTempDir)[0]
        else:
            if not dirExists:
                #make the directory and clone under here
                os.mkdir(self.gitTempDir)
            #Initially we must trust our remote repo URL
            (output, stderrout, res) = self.runOSProcess("ssh -n -o \"BatchMode yes\" -o StrictHostKeyChecking=no " + self.gitRepoURL[:self.gitRepoURL.find(":")])
            if res == False:
                logger.warn("i=\"%s\" Unexpected failure while attempting to trust the remote git repo?! stdout '%s' stderr '%s'" % (self.stanzaName, output, stderrout))
            
            (output, stderrout, res) = self.runOSProcess("cd %s; git clone %s" % (self.gitTempDir, self.gitRepoURL), timeout=30)
            if res == False:
                logger.fatal("i=\"%s\" git clone failed for some reason...on url %s stdout of '%s' with stderrout of '%s'" % (self.stanzaName, self.gitRepoURL, output, stderrout))
                sys.exit(1)
            else:
                logger.debug("i=\"%s\" result from git command=%s, output '%s' with stderroutput of '%s'" % (self.stanzaName, res, output, stderrout))
                logger.info("i=\"%s\" Successfully cloned the git URL from %s into directory %s" % (self.stanzaName, self.gitRepoURL, self.gitTempDir))
                self.gitTempDir = self.gitTempDir + "/" + os.listdir(self.gitTempDir)[0]
        
        #Version Control File to record when we last ran
        versionControlFile = "splunkversioncontrol_lastrunepoch"
        res = self.runSearchJob("| inputlookup %s" % (versionControlFile))
        resList = res["results"]
        lastRunEpoch = None

        appsWithChanges = None
        if len(resList) == 0:
            logger.info("i=\"%s\" %s does not exist, running against all apps now" % (self.stanzaName, versionControlFile))
        else:
            appsWithChanges = {}
            lastRunEpoch = resList[0]["earliest"]
            logger.info("i=\"%s\" %s reports a lastrun_epoch=%s using this date in report calls" % (self.stanzaName, versionControlFile, lastRunEpoch))
            
            #Run a query to determine which apps/types of knowledge objects have changed since the last run
            res = self.runSearchJob("savedsearch \"SplunkVersionControl ChangeDetector Directory\" updatedEpoch=%s" % (lastRunEpoch))
            resList = res["results"]
            if len(resList) > 0:
                for aRes in resList:
                    app = aRes["app"]
                    type = aRes["type"]
                    logger.debug("i=\"%s\" Found changes to app=%s of type=%s" % (self.stanzaName, app, type))
                    
                    if not app in appsWithChanges:
                        appsWithChanges[app] = []
                    appsWithChanges[app].append(type)

            #Run a query to determine which apps/types of knowledge objects have changed since the last run
            res = self.runSearchJob("savedsearch \"SplunkVersionControl ChangeDetector Non-Directory\" updatedEpoch=%s" % (lastRunEpoch))
            resList = res["results"]
            if len(resList) > 0:
                for aRes in resList:
                    app = aRes["app"]
                    type = aRes["type"]
                    
                    logger.debug("i=\"%s\" Found changes to app=%s of type=%s" % (self.stanzaName, app, type))
                    
                    if not app in appsWithChanges:
                        appsWithChanges[app] = []
                    appsWithChanges[app].append(type)

        #Always start from master and the current version (just in case changes occurred)
        (output, stderrout, res) = self.runOSProcess("cd %s; git checkout master; git pull" % (self.gitTempDir), timeout=20)
        if res == False:
            logger.warn("i=\"%s\" git checkout master or git pull failed, stdout is '%s' stderrout is '%s'" % (self.stanzaName, output, stderrout))

        knownAppList = []
        knownAppList = os.listdir(self.gitTempDir)
        logger.debug("i=\"%s\" Known app list is %s" % (self.stanzaName, knownAppList))

        for app in appList: 
            macrosRun = False
            tagsRun = False
            eventtypesRun = False
            calcFieldsRun = False
            fieldAliasRun = False
            fieldTransformsRun = False
            fieldExtractionRun = False
            collectionsRun = False
            lookupDefinitionRun = False
            automaticLookupRun = False
            timesRun = False
            viewstatesRun = False
            panelsRun = False
            datamodelsRun = False
            dashboardsRun = False
            savedsearchesRun = False
            workflowActionsRun = False
            sourcetypeRenamingRun = False
            navMenuRun = False

            #We've never seen the app before, download everything
            if app not in knownAppList:
                logger.info("i=\"%s\" Found a new app with no previous history, will download all objects from the app=%s" % (self.stanzaName, app))
                macrosRun = True
                tagsRun = True
                eventtypesRun = True
                calcFieldsRun = True
                fieldAliasRun = True
                fieldTransformsRun = True
                fieldExtractionRun = True
                collectionsRun = True
                lookupDefinitionRun = True
                automaticLookupRun = True
                timesRun = True
                viewstatesRun = True
                panelsRun = True
                datamodelsRun = True
                dashboardsRun = True
                savedsearchesRun = True
                workflowActionsRun = True
                sourcetypeRenamingRun = True
                navMenuRun = True
            #This is our first run, download everything from every app
            elif not lastRunEpoch:
                logger.info("i=\"%s\" This appears to be a first time run as no lastRunEpoch found, downloading from all apps, working with app=%s" % (self.stanzaName, app))
                macrosRun = True
                tagsRun = True
                eventtypesRun = True
                calcFieldsRun = True
                fieldAliasRun = True
                fieldTransformsRun = True
                fieldExtractionRun = True
                collectionsRun = True
                lookupDefinitionRun = True
                automaticLookupRun = True
                timesRun = True
                viewstatesRun = True
                panelsRun = True
                datamodelsRun = True
                dashboardsRun = True
                savedsearchesRun = True
                workflowActionsRun = True
                sourcetypeRenamingRun = True
                navMenuRun = True
            #else case, we have run before, this is not a new app so download changes only
            else:
                if not app in appsWithChanges:
                    logger.info("i=\"%s\" No changes found in app=%s, skipping this apps configuration" % (self.stanzaName, app))
                    continue
                
                typeList = appsWithChanges[app]
                if "macros" in typeList:
                    macrosRun = True
                if "fvtags" in typeList:
                    tagsRun = True
                if "eventtypes" in typeList:
                    eventtypesRun = True
                if "calcfields" in typeList:
                    calcFieldsRun = True
                if "fieldaliases" in typeList:
                    fieldAliasRun = True
                if "transforms-extract" in typeList:
                    fieldTransformsRun = True
                if "props-extract" in typeList:
                    fieldExtractionRun = True
                if "kvstore" in typeList:
                    collectionsRun = True
                if "transforms-lookup" in typeList:
                    lookupDefinitionRun = True
                if "props-lookup" in typeList:
                    automaticLookupRun = True
                if "conf-times" in typeList:
                    timesRun = True
                if "panels" in typeList:
                    panelsRun = True
                if "datamodel" in typeList:
                    datamodelsRun = True
                if "views" in typeList:
                    dashboardsRun = True
                if "savedsearch" in typeList:
                    savedsearchesRun = True
                if "workflow-actions" in typeList:
                    workflowActionsRun = True
                if "sourcetype-rename" in typeList:
                    sourcetypeRenamingRun = True
                if "nav" in typeList:
                    navMenuRun = True

            logger.info("i=\"%s\" Working with app=%s" % (self.stanzaName, app))
            self.perApp(app, macrosRun, tagsRun, eventtypesRun, calcFieldsRun, fieldAliasRun, fieldTransformsRun, fieldExtractionRun, collectionsRun, lookupDefinitionRun, automaticLookupRun, timesRun, viewstatesRun, panelsRun, datamodelsRun, dashboardsRun, savedsearchesRun, workflowActionsRun, sourcetypeRenamingRun, navMenuRun)
            logger.info("i=\"%s\" Completed working with app=%s" % (self.stanzaName, app))

        #Always start from master and the current version (just in case someone was messing around in the temp directory)
        (output, stderrout, res) = self.runOSProcess("cd %s; git checkout master; git pull" % (self.gitTempDir), timeout=20)
        if res == False:
            logger.warn("i=\"%s\" git checkout master or git pull failed, stdout is '%s' stderrout is '%s'" % (self.stanzaName, output, stderrout))
            
        #At this point we've written out the potential updates
        (output, stderrout, res) = self.runOSProcess("cd %s; git status | grep \"nothing to commit\"" % (self.gitTempDir))
        if res == False:
            #We have one or more files to commit, do something
            todaysDate = datetime.datetime.now().strftime("%Y-%m-%d_%H%M")
            (output, stderrout, res) = self.runOSProcess("cd {0}; git add -A; git commit -am \"Updated by Splunk Version Control backup job {1}\"; git tag {2}; git push origin master --tags".format(self.gitTempDir, self.stanzaName, todaysDate), timeout=30)
            if res == False:
                logger.error("i=\"%s\" Failure while commiting the new files, backup completed but git may not be up-to-date, stdout '%s' stderrout of '%s'" % (self.stanzaName, output, stderrout))
        
        #Output the time we did the run so we know where to continue from at next runtime
        res = self.runSearchJob("| makeresults | eval earliest=%s | fields - _time | outputlookup %s" % (currentEpochTime, versionControlFile))       
        logger.info("i=\"%s\" lastrun_epoch=%s written to lookup" % (self.stanzaName, currentEpochTime))
        
        #Append to our tag list so the dashboard shows the new tag as a choice to "restore from"
        res = self.runSearchJob("| makeresults | eval tag=\"%s\" | fields - _time | outputlookup append=t splunkversioncontrol_taglist" % (todaysDate))

        logger.info("i=\"%s\" Done" % (self.stanzaName))
    
    #Run an OS process with a timeout, this way if a command gets "stuck" waiting for input it is killed        
    def runOSProcess(self, command, timeout=10):
        logger.debug("i=\"%s\" Running command=\"%s\" with timeout=%s" % (self.stanzaName, command, timeout))
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
