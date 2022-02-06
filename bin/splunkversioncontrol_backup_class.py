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
from datetime import datetime,timedelta
import shutil
from io import open
import platform
import hashlib
from splunkversioncontrol_utility import runOSProcess, get_password
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

from splunklib import six
from unidiff import PatchSet

"""

 Store Knowledge Objects
   Attempt to run against the Splunk REST API to obtain various knowledge objects, then persist the knowledge object information required
   to restore the knowledge object if it was deleted/changed to the filesystem

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
    gitRootDir = None
    appName = "SplunkVersionControl"
    gitRepoURL = None
    stanzaName = None
    lastRunEpoch = None
    sslVerify = False

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
            config['checkpoint_dir'] = root.getElementsByTagName("checkpoint_dir")[0].firstChild.data
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
                raise Exception("Invalid configuration received from Splunk.")
        except Exception as e:
            raise Exception("Error getting Splunk configuration via STDIN: %s" % str(e))

        return config

    #Query Splunk for a list of all known apps, that way we can compare to what we have backed up
    def getAllAppsList(self):
        appList = []
        url = self.splunk_rest + "/services/apps/local?search=disabled%3D0&count=0&f=title"

        logger.debug("i=\"%s\" Running requests.get() on url=%s with user=%s, proxies_length=%s, sslVerify=%s to obtain a list of all applications" % (self.stanzaName, url, self.srcUsername, len(self.proxies), self.sslVerify))
        #no srcUsername, use the session_key method
        headers = {}
        auth = None

        if not self.srcUsername:
            headers={'Authorization': 'Splunk %s' % self.session_key}
        else:
            auth = HTTPBasicAuth(self.srcUsername, self.srcPassword)

        res = requests.get(url, auth=auth, headers=headers, verify=self.sslVerify, proxies=self.proxies)
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
                        logger.debug("i=\"%s\" name=\"%s\" is the app added to the list" % (self.stanzaName, name))
        return appList

    #As per https://stackoverflow.com/questions/1101508/how-to-parse-dates-with-0400-timezone-string-in-python/23122493#23122493
    def determineTime(self, timestampStr):
        logger.debug("i=\"%s\" attempting to convert %s to timestamp" % (self.stanzaName, timestampStr))
        ret = datetime.strptime(timestampStr[0:19],  "%Y-%m-%dT%H:%M:%S")
        if timestampStr[19]=='+':
            ret-=timedelta(hours=int(timestampStr[20:22]),minutes=int(timestampStr[24:]))
        elif timestampStr[19]=='-':
            ret+=timedelta(hours=int(timestampStr[20:22]),minutes=int(timestampStr[24:]))
        logger.debug("i=\"%s\" converted time is %s from %s" % (self.stanzaName, ret, timestampStr))
        return ret

    ###########################
    #
    # runQueries (generic version)
    #   For each knowledge object type / app query the remote Splunk instance to obtain the configuration
    #   then persist the required configuration to the filesystem
    #
    ###########################
    def runQueries(self, app, endpoint, type, fieldIgnoreList, aliasAttributes={}, valueAliases={}, nameOverride="", override=False, extra_args=""):
        creationSuccess = []
        #Keep a success list to be returned by this function
        #Use count=-1 to ensure we see all the objects
        url = self.splunk_rest + "/servicesNS/-/" + app + endpoint + "?count=-1" + extra_args
        logger.debug("i=\"%s\" Running requests.get() on %s user=%s in app=%s, proxies_length=%s, sslVerify=%s" % (self.stanzaName, url, self.srcUsername, app, len(self.proxies), self.sslVerify))

        headers = {}
        auth = None

        if not self.srcUsername:
            headers={'Authorization': 'Splunk %s' % self.session_key}
        else:
            auth = HTTPBasicAuth(self.srcUsername, self.srcPassword)

        res = requests.get(url, auth=auth, headers=headers, verify=self.sslVerify, proxies=self.proxies)
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
                        if 'name' in list(aliasAttributes.values()):
                            info["origName"] = title

                        logger.debug("i=\"%s\" name=\"%s\" is the entry for type=%s in app=%s" % (self.stanzaName, title, type, app))
                        #If we have an include/exclude list we deal with that scenario now
                        if self.includeEntities:
                            if not title in self.includeEntities:
                                logger.debug("i=\"%s\" name=\"%s\" of type=%s not in includeEntities list in app=%s" % (self.stanzaName, info["name"], type, app))
                                keep = False
                                break
                        if self.excludeEntities:
                            if title in self.excludeEntities:
                                logger.debug("i=\"%s\" name=\"%s\" of type=%s in excludeEntities list in app=%s" % (self.stanzaName, info["name"], type, app))
                                keep = False
                                break
                    #Content apepars to be where 90% of the data we want is located
                    elif innerChild.tag.endswith("content"):

                        # optimisation to deal with the giant display.visualizations... on savedsearches only
                        skip_visualizations = True

                        for theAttribute in innerChild[0]:
                            #acl has the owner, sharing and app level which we required (sometimes there is eai:app but it's not 100% consistent so this is safer
                            #also have switched from author to owner as it's likely the safer option...
                            if theAttribute.attrib['name'] == 'eai:acl':
                                for theList in theAttribute[0]:
                                    if theList.attrib['name'] == 'sharing':
                                        logger.debug("i=\"%s\" name=\"%s\" of type=%s has sharing=%s in app=%s" % (self.stanzaName, info["name"], type, theList.text, app))
                                        info["sharing"] = theList.text
                                        if self.noPrivate and info["sharing"] == "user":
                                            logger.debug("i=\"%s\" name=\"%s\" of type=%s found but the noPrivate flag is true, excluding this in app=%s" % (self.stanzaName, info["name"], type, app))
                                            keep = False
                                            break
                                    elif theList.attrib['name'] == 'app':
                                        foundApp = theList.text
                                        logger.debug("i=\"%s\" name=\"%s\" of type=%s in app context of app=%s belongs to app=%s" % (self.stanzaName, info["name"], type, app, foundApp))
                                        #We can see globally shared objects in our app context, it does not mean we should migrate them as it's not ours...
                                        if app != foundApp:
                                            logger.debug("i=\"%s\" name=\"%s\" of type=%s found in app context of app=%s belongs to app context app=%s, excluding from app=%s" % (self.stanzaName, info["name"], type, app, foundApp, app))
                                            keep = False
                                            break
                                    #owner is seen as a nicer alternative to the author variable
                                    elif theList.attrib['name'] == 'owner':
                                        owner = theList.text

                                        #If we have include or exlcude owner lists we deal with this now
                                        if self.includeOwner:
                                            if not owner in self.includeOwner:
                                                logger.debug("i=\"%s\" name=\"%s\" of type=%s with owner=%s not in includeOwner list in app=%s" % (self.stanzaName, info["name"], type, owner, app))
                                                keep = False
                                                break
                                        if self.excludeOwner:
                                            if owner in self.excludeOwner:
                                                logger.debug("i=\"%s\" name=\"%s\" of type=%s with owner=%s in excludeOwner list in app=%s" % (self.stanzaName, info["name"], type, owner, app))
                                                keep = False
                                                break
                                        logger.debug("i=\"%s\" name=\"%s\" of type=%s has owner=%s in app=%s" % (self.stanzaName, info["name"], type, owner, app))
                                        info["owner"] = owner

                            else:
                                #We have other attributes under content, we want the majority of them
                                attribName = theAttribute.attrib['name']

                                #Under some circumstances we want the attribute and contents but we want to call it a different name...
                                if attribName in aliasAttributes:
                                    attribName = aliasAttributes[attribName]

                                #If it's disabled *and* we don't want disabled objects we can determine this here
                                if attribName == "disabled" and self.noDisabled and theAttribute.text == "1":
                                    logger.debug("i=\"%s\" name=\"%s\" of type=%s is disabled and the noDisabled flag is true, excluding this in app=%s" % (self.stanzaName, info["name"], type, app))
                                    keep = False
                                    break

                                #Field extractions change from "Uses transform" to "REPORT" And "Inline" to "EXTRACTION" for some strange reason...
                                #therefore we have a list of attribute values that we deal with here which get renamed to the provided values
                                if theAttribute.text in valueAliases:
                                    theAttribute.text = valueAliases[theAttribute.text]

                                logger.debug("i=\"%s\" name=\"%s\" of type=%s found key/value of %s=%s in app context app=%s" % (self.stanzaName, info["name"], type, attribName, theAttribute.text, app))

                                #Yet another hack, this time to deal with collections using accelerated_fields.<value> when looking at it via REST GET requests, but
                                #requiring accelerated_fields to be used when POST'ing the value to create the collection!
                                if type == "collections (kvstore definition)" and attribName.find("accelrated_fields") == 0:
                                    attribName = "accelerated_fields" + attribName[17:]

                                #Hack to deal with datamodel tables not working as expected
                                if attribName == "description" and type=="datamodels" and "dataset.type" in info and info["dataset.type"] == "table":
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
                                        logger.debug("i=\"%s\" name=\"%s\"" % (self.stanzaName, name))
                                        if name != "RootObject":
                                            index = fields.index(field)
                                            del fields[index]

                                    res = json.dumps(res)
                                    info[attribName] = res
                                #Optimisation related to savedsearches if we're not a saved search using the visualisations tab, don't backup the display.visualizations...
                                elif type=="savedsearches" and attribName == "display.general.type" and theAttribute.text=="visualizations":
                                    logger.debug("i=\"%s\" name=\"%s\" of type=%s found %s=%s in app context app=%s changing skip_visualizations to false" % (self.stanzaName, info["name"], type, attribName, theAttribute.text, app))
                                    info[attribName] = theAttribute.text
                                    skip_visualizations = False
                                #We keep the attributes that are not None
                                elif theAttribute.text:
                                    if skip_visualizations and attribName.find("display.visualizations.") == 0:
                                        logger.debug("i=\"%s\" name=\"%s\" of type=%s found %s=%s in app context app=%s skipping as skip_visualizations is true" % (self.stanzaName, info["name"], type, attribName, theAttribute.text, app))
                                    else:
                                        info[attribName] = theAttribute.text
                                #A hack related to automatic lookups, where a None / empty value must be sent through as "", otherwise requests will strip the entry from the
                                #post request. In the case of an automatic lookup we want to send through the empty value...
                                elif type=="automatic lookup" and theAttribute.text == None:
                                    info[attribName] = ""
                    elif innerChild.tag.endswith("updated"):
                        info["updated"] = innerChild.text
                #If we have not set the keep flag to False
                if keep:
                    #Updated time was for our reference only, don't try to send that in while creating/updating the object
                    updated = info["updated"]
                    del info["updated"]

                    if nameOverride != "":
                        #keep a copy of the original name for use when checking if the object exists
                        info["origName"] = info["name"]
                        info["name"] = info[nameOverride]
                        #TODO hack to handle field extractions where they have an extra piece of info in the name
                        #as in the name is prepended with EXTRACT-, REPORT- or LOOKUP-, we need to remove this before creating
                        #the new version
                        if type=="fieldextractions" and info["name"].find("EXTRACT-") == 0:
                            logger.debug("i=\"%s\" Overriding name of name=\"%s\" of type=%s in app context app=%s with owner=%s to new name of newname=\"%s\"" % (self.stanzaName, info["name"], type, app, info["owner"], info["name"][8:]))
                            info["name"] = info["name"][8:]
                        elif type=="fieldextractions" and info["name"].find("REPORT-") == 0:
                            logger.debug("i=\"%s\" Overriding name of name=\"%s\" of type=%s in app context app=%s with owner=%s to new name of newname=\"%s\"" % (self.stanzaName, info["name"], type, app, info["owner"], info["name"][7:]))
                            info["name"] = info["name"][7:]
                        elif type=="automatic lookup" and info["name"].find("LOOKUP-") == 0:
                            logger.debug("i=\"%s\" Overriding name of name=\"%s\" of type=%s in app context app=%s with owner=%s to new name of newname=\"%s\"" % (self.stanzaName, info["name"], type, app, info["owner"], info["name"][7:]))
                            info["name"] = info["name"][7:]
                        elif type=="fieldaliases":
                            newName = info["name"]
                            newName = newName[newName.find("FIELDALIAS-")+11:]
                            logger.debug("Overriding name of %s of type %s in app context %s with owner %s to new name of %s" % (info["name"], type, app, info["owner"], newName))
                            info["name"] = newName

                    #Some attributes are not used to create a new version so we remove them...(they may have been used above first so we kept them until now)
                    for attribName in fieldIgnoreList:
                        if attribName in info:
                            del info[attribName]

                    #Add this to the infoList
                    sharing = info["sharing"]
                    if sharing not in infoList:
                        infoList[sharing] = []

                    #REST API does not support the creation of null queue entries as tested in 7.0.5 and 7.2.1, these are also unused on search heads anyway so ignoring these with a warning
                    if type == "fieldtransformations" and "FORMAT" in info and info["FORMAT"] == "nullQueue":
                        logger.info("i=\"%s\" Dropping the backup of name=\"%s\" of type=%s in app context app=%s with owner=%s because nullQueue entries cannot be created via REST API (and they are not required in search heads)" % (self.stanzaName, info["name"], type, app, info["owner"]))
                    else:
                        infoList[sharing].append(info)
                        logger.info("i=\"%s\" Recording name=\"%s\" info for type=%s in app context app=%s with owner=%s" % (self.stanzaName, info["name"], type, app, info["owner"]))

                    logger.debug("Updated time is updated=%s" % (updated))
                    epochUpdatedTime = int((self.determineTime(updated) - datetime(1970,1,1)).total_seconds())
                    logger.debug("epochUpdatedTime=%s" % (epochUpdatedTime))
                    if self.lastRunEpoch == None or int(self.lastRunEpoch) <= epochUpdatedTime:
                        logger.info("i=\"%s\" name=\"%s\" of type=%s in app context app=%s with owner=%s was updated at %s updated=true" % (self.stanzaName, info["name"], type, app, info["owner"], updated))
                    logger.debug("i=\"%s\" name=\"%s\" of type=%s in app context app=%s with owner=%s was updated at %s or epoch of %s compared to lastRunEpoch of %s" % (self.stanzaName, info["name"], type, app, info["owner"], updated, epochUpdatedTime, self.lastRunEpoch))
                    creationSuccess.append(info["name"])

        #Find the storage directory for this app and create it if required
        appStorageDir = self.gitTempDir + "/" + app
        if not os.path.isdir(appStorageDir):
            os.mkdir(appStorageDir)

        #Cycle through each one we need to backup, we do global/app/user as users can duplicate app level objects with the same names
        #but we create everything at user level first then re-own it so global/app must happen first
        if "global" in infoList:
            #persist global to disk
            globalStorageDir = appStorageDir + "/global"
            logger.debug("i=\"%s\" Now persisting knowledge objects of type=%s with sharing=global in app=%s into dir=%s" % (self.stanzaName, type, app, globalStorageDir))
            if not os.path.isdir(globalStorageDir):
                os.mkdir(globalStorageDir)
            if self.file_per_ko:
                # in the file per-ko method we want 1 file per knowledge object...
                global_type_dir = globalStorageDir + "/" + type
                files, dirs = self.write_files(global_type_dir, infoList["global"])
                self.remove_dir_contents(files, dirs, type, "global", self.disable_file_deletion)
            else:
                # in the original method we dumped 1 large file with all objects of this type at this scope
                with open(globalStorageDir + "/" + type, 'w', encoding="utf-8") as f:
                    f.write(six.text_type(json.dumps(infoList["global"], sort_keys=True, indent=0)))
                    # add newline so git doesn't think it's different every commit...
                    f.write("\n")
        if "app" in infoList:
            #persist app level to disk
            appLevelStorageDir = appStorageDir + "/app"
            logger.debug("i=\"%s\" Now persisting with knowledge objects of type=%s with sharing=app in app=%s into dir=%s" % (self.stanzaName, type, app, appLevelStorageDir))
            if not os.path.isdir(appLevelStorageDir):
                os.mkdir(appLevelStorageDir)
            if self.file_per_ko:
                app_type_dir = appLevelStorageDir + "/" + type
                files, dirs = self.write_files(app_type_dir, infoList["app"])
                self.remove_dir_contents(files, dirs, type, "app", self.disable_file_deletion)
            else:
            # in the original method we dumped 1 large file with all objects of this type at this scope
                with open(appLevelStorageDir + "/" + type, 'w', encoding="utf-8") as f:
                    f.write(six.text_type(json.dumps(infoList["app"], sort_keys=True, indent=0)))
                    # add newline so git doesn't think it's different every commit...
                    f.write("\n")
        if "user" in infoList:
            #persist user level to disk
            userLevelStorageDir = appStorageDir + "/user"
            logger.debug("i=\"%s\" Now persisting with knowledge objects of type=%s sharing=user (private) in app=%s into dir=%s" % (self.stanzaName, type, app, userLevelStorageDir))
            if not os.path.isdir(userLevelStorageDir):
                os.mkdir(userLevelStorageDir)
            if self.file_per_ko:
                # in the file per-ko method we want 1 file per knowledge object...
                user_type_dir = userLevelStorageDir + "/" + type
                files, dirs = self.write_files(user_type_dir, infoList["user"])
                self.remove_dir_contents(files, dirs, type, "user", self.disable_file_deletion)
            else:
                # in the original method we dumped 1 large file with all objects of this type at this scope
                with open(userLevelStorageDir + "/" + type, 'w', encoding="utf-8") as f:
                    f.write(six.text_type(json.dumps(infoList["user"], sort_keys=True, indent=0)))
                    # add newline so git doesn't think it's different every commit...
                    f.write("\n")
        return creationSuccess

    ###########################
    #
    # Shared function to list contents of a directory in terms of directories/files
    #
    ###########################
    def list_dir_contents(self, path):
        file_list = []
        dir_list = []
        for root, directories, files in os.walk(path):
            for name in files:
                file_list.append(os.path.join(root, name))
            for name in directories:
                dir_list.append(os.path.join(root, name))
        return file_list, dir_list

    ###########################
    #
    # Shared function to remove old files/directories
    #
    ###########################
    def remove_dir_contents(self, files, dirs, type, scope, disabled):
        # At this point we have zero or more files that may have been deleted from splunk but exist on the filesystem
        logger.info("i=\"%s\" the following files were left after completing the backup at scope=%s for type=%s list=\"%s\"" % (self.stanzaName, scope, type, files))
        if disabled:
            logger.info("i=\"%s\" no files will be removed as requested by disable file deletion option" % (self.stanzaName))
            return
        for a_file in files:
            logger.info("i=\"%s\" removing file=%s" % (self.stanzaName, a_file))
            os.remove(a_file)
            # some files were removed, delete empty directories too
            if len(files) > 0:
                for a_dir in dirs:
                    if len(os.listdir(a_dir)) == 0:
                        logger.info("i=\"%s\" removing empty dir=%s" % (self.stanzaName, a_dir))

    ###########################
    #
    # Shared function to write each individual file out
    #
    ###########################
    def create_file_name(self, file):
        file_name = six.moves.urllib.parse.quote_plus(file)
        # if a file exceeds 255 characters it will result in a file too long error (e.g. really long field extraction names
        if len(file_name) > 254:
            hash = hashlib.md5(file.encode('utf-8')).hexdigest()
            file_name = file_name[0:222] + hash
        return file_name

    def write_files(self, dir, objects):
        if not os.path.isdir(dir):
            os.mkdir(dir)
        files, dirs = self.list_dir_contents(dir)
        for an_object in objects:
            #per-object see if we need to create the directory
            an_object_dir = dir + "/" + an_object["owner"]
            if not os.path.isdir(an_object_dir):
                os.mkdir(an_object_dir)
            file_name = self.create_file_name(an_object["name"])
            an_object_file = an_object_dir + "/" + file_name
            with open(an_object_file, 'w', encoding="utf-8") as f:
                f.write(six.text_type(json.dumps(an_object, sort_keys=True, indent=0)))
                # add newline so git doesn't think it's different every commit...
                f.write(six.text_type("\n"))
            try:
                files.remove(an_object_file)
            except:
                pass
        return files, dirs

    # obtain the macro contents for a specific macro
    def obtain_svc_ko_query_context(self):
        query = "/properties/macros/splunk_vc_ko_query?output_mode=json"
        url = self.splunk_rest + "/servicesNS/nobody/" + self.appName + query

        headers = {}
        auth = None

        if not self.srcUsername:
            headers={'Authorization': 'Splunk %s' % self.session_key}
        else:
            auth = HTTPBasicAuth(self.srcUsername, self.srcPassword)

        res = requests.get(url, auth=auth, headers=headers, verify=self.sslVerify, proxies=self.proxies)
        if (res.status_code != requests.codes.ok):
            logger.warn("i=\"%s\" URL=%s in app=%s statuscode=%s reason=%s response=\"%s\"" % (self.stanzaName, url, app, res.status_code, res.reason, res.text))
            return None

        res = json.loads(res.text)

        #Log return messages from Splunk, often these advise of an issue but not always...
        if 'messages' in res and len(res["messages"]) > 0:
            firstMessage = res["messages"][0]
            if 'type' in firstMessage and firstMessage['type'] == "INFO":
                #This is a harmless info message ,most other messages are likely an issue
                logger.info("i=\"%s\" messages from query=\"%s\" were messages=\"%s\"" % (self.stanzaName, query, res["messages"]))
            else:
                logger.warn("i=\"%s\" messages from query=\"%s\" were messages=\"%s\"" % (self.stanzaName, query, res["messages"]))

        if 'entry' in res:
            entry = res['entry']
            if len(entry) == 0:
                logger.warn("i=\"%s\" unable to obtain macro information from query=\"%s\"" % (self.stanzaName, query))
                return None
            if 'content' in entry[0]:
                return_res = entry[0]['content']
                logger.debug("i=\"%s\" obtained macro information from query=\"%s\", result contained \"%s\"" % (self.stanzaName, query, return_res))
                return return_res
            else:
                logger.warn("i=\"%s\" unable to obtain macro information from query=\"%s\", entry contained: %s" % (self.stanzaName, query, entry[0]))
        else:
            logger.warn("i=\"%s\" unable to obtain macro information from query=\"%s\", result contained: %s" % (self.stanzaName, query, res))

        return None

    # parse the results of the wdiff command
    def parse_wdiff(self, output):
        results = {}
        file=""
        diff=""
        file2=""

        for line in output.split("\n"):
            # look for the b/file changes if has been creatd or exists
            if line.find("{+++ b") == 0 or line.find("{+diff --git a/") == 0:
                end = line.rfind("}")
                start = line.find("{+++ b")
                if start == -1:
                    start = line.find("a/")+2
                    end = line.find(" ",start)+1
                else:
                    start = start + 7
                if file!="":
                    logger.debug("i=\"%s\" recording file=%s, diff=%s" % (self.stanzaName, file, diff))
                    if file in results:
                        diff = results[file] + "\n" + diff
                    results[file] = diff
                else:
                    logger.debug("i=\"%s\" recording file=%s, diff=%s" % (self.stanzaName, file2, diff))
                    if file2 in results:
                        diff = results[file2] + "\n" + diff
                    results[file2] = diff
                file = line[start:end-1]
                diff=""
                file2=""
            # --- shows us the file that changed if it was deleted or already exists
            elif line.find("[--- a") == 0 or line.find("[-diff --git a/") == 0:
                end = line.rfind("]")
                start = line.find("[--- a")
                if start == -1:
                    start = line.find("a/")+2
                    end = line.find(" ",start)+1
                else:
                    start = start + 7
                file2 = line[start:end-1]
            # this file has been deleted
            elif line.find("{+++ /dev/null") == 0:
                if file!="":
                    if file in results:
                        diff = results[file] + "\n" + diff
                    results[file] = diff
                else:
                    if file2 in results:
                        diff = results[file2] + "\n" + diff
                    results[file2] = diff
                file = ""
                diff=""
            # this file has been created
            elif line.find("[--- /dev/null") == 0:
                pass
            # if it's not === and not an empty line then it's related to the diff
            elif line.find("======================================================================") == -1 and line.strip()!="":
                diff=diff + line + "\n"
        # we had more than zero results, record this
        if file!="":
            logger.debug("i=\"%s\" recording file=%s, diff=%s" % (self.stanzaName, file, diff))
            if file in results:
                diff = results[file] + "\n" + diff
            results[file] = diff
        elif file2!="":
            logger.debug("i=\"%s\" recording file=%s, diff=%s" % (self.stanzaName, file2, diff))
            if file2 in results:
                diff = results[file2] + "\n" + diff
            results[file2] = diff

        return results

    # write the contents out from what we have found to have changed
    def process_ko_query_contents(self, results, tag):
        if not 'results' in results:
            logger.warn("i=\"%s\" no results field found in returned results \"%s\" tag=%s" % (self.stanzaName, results, tag))
            return

        file_list, dir_list = self.list_dir_contents(self.gitTempDir)
        str = ""
        for a_result in results['results']:
            stanza = "i=\"%s\" " % (self.stanzaName)
            str = "%s%s" % (str, stanza)
            for key in a_result:
                if key == "scope":
                    pass
                str = '{}{}="{}" '.format(str,key,a_result[key])

            overall_matches = []

            if 'ko_type' in a_result and 'app_name' in a_result and 'scope' in a_result:
                scope_list = a_result['scope'].split(",")
                for a_scope in scope_list:
                    file_str = self.gitTempDir + "/" + a_result['app_name'] + "/" + a_scope + "/" + a_result['ko_type']
                    logger.debug("i=\"%s\" looking for file=%s tag=%s" % (self.stanzaName, file_str, tag))

                    matches = [ entry for entry in file_list if entry.find(file_str) != -1 ]
                    start = len(self.gitTempDir) + 1
                    match = [ match[start:] for match in matches ]
                    overall_matches = overall_matches + match
                    logger.debug("i=\"%s\" overall_matches=\"%s\" tag=%s" % (self.stanzaName, overall_matches, tag))

                    if self.file_per_ko:
                        if not 'ko_name' in a_result:
                            logger.info("i=\"%s\" ko_name is null, cannot identify an exact changed object \"%s\" tag=%s" % (self.stanzaName, a_result, tag))
                            overall_matches_list = []                        
                            if 'user' in a_result:
                                #TODO may not work on Windows
                                find_str = "/" + a_result['user'] + "/"
                                overall_matches_list = [ entry[0:entry.find(find_str)+len(find_str)] for entry in overall_matches if entry.find(find_str) != -1 ]
                            else:
                                find_str = a_result['ko_type']
                                overall_matches_list = [ entry[0:entry.find(find_str)+len(find_str)] for entry in overall_matches if entry.find(find_str) != -1 ]
                            if len(overall_matches_list) > 0:
                                overall_matches = overall_matches + list(set(overall_matches_list))                            
                        else:
                            file_name = self.create_file_name(a_result['ko_name'])
                            logger.debug("i=\"%s\" looking for file_name=%s tag=%s" % (self.stanzaName, file_name, tag))
                            match = []

                            for entry in overall_matches:
                                start = entry.find(file_name)
                                if start != -1 and len(entry[start:]) == len(file_name):
                                    match.append(entry)

                            if len(match) > 0:
                                overall_matches = match
                            else:
                                if 'action' in a_result and "DELETE" in a_result['action']:
                                    logger.warn("i=\"%s\" looking for file_name=%s in file_str=%s tag=%s but did not find a match" % (self.stanzaName, file_name, file_str, tag))
                                else:
                                    deleted_file_str = a_result['app_name'] + "/" + a_scope + "/" + a_result['ko_type'] + "/" + a_result['user'] + "/" + file_name
                                    overall_matches = [ deleted_file_str ]

            str = str + "tag=" + tag
            first = True
            for match in overall_matches:
                if first:
                    first = False
                    str = str + " git_location=" + match
                else:
                    str = str + " OR git_location=" + match

            if self.run_ko_diff:
                diff_str = "cd {0}; ".format(self.gitTempDir)
                if self.use_wdiff:
                    diff_str = diff_str + "{0} --no-pager diff -U0 HEAD~1 | wdiff -d".format(self.git_command)
                else:
                    diff_str = diff_str + "{0} --no-pager diff -U0 HEAD~1".format(self.git_command)
                output, stderrout, res = runOSProcess(diff_str, logger, timeout=300, shell=True)
                # wdiff can return 1 for a change which triggers the res=False line
                if res == False and not self.use_wdiff:
                    logger.error("i=\"%s\" Failure while running git diff HEAD~1, stdout '%s' stderrout of '%s'" % (self.stanzaName, output, stderrout))
                else:
                    if self.use_wdiff:
                        results = self.parse_wdiff(output)
                        for path, diff in results.items():
                            logger.debug("i=\"%s\" checking to see if path=%s exists in the overall_matches list" % (self.stanzaName, path))
                            if path in overall_matches:
                                str = "%s diff=%s" % (str, diff)
                    else:
                        patch = PatchSet(output)
                        for entry in patch:
                            logger.debug("i=\"%s\" checking to see if path=%s exists in the overall_matches list" % (self.stanzaName, entry.path))
                            if entry.path in overall_matches:
                                str = "%s diff=%s" % (str, entry)
            str = str + "\n"
        if str != "":
            str = str.rstrip('\n')
            print(str)
            logger.debug("i=\"%s\" Recording output of: \"%s\"" % (self.stanzaName, str))
        else:
            logger.info("i=\"%s\" No results from ko_query" % (self.stanzaName))

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
        logger.debug("i=\"%s\" Running requests.get() on url=%s with user=%s in app=%s for type macro proxies_length=%s, sslVerify=%s" % (self.stanzaName, url, self.srcUsername, app, len(self.proxies), self.sslVerify))

        headers = {}
        auth = None
        if not self.srcUsername:
            headers={'Authorization': 'Splunk %s' % self.session_key}
        else:
            auth = HTTPBasicAuth(self.srcUsername, self.srcPassword)

        res = requests.get(url, auth=auth, headers=headers, verify=self.sslVerify, proxies=self.proxies)
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
                        logger.debug("i=\"%s\" Found type=macro title, name=\"%s\" in app=%s" % (self.stanzaName, title, app))
                        #Deal with the include/exclude lists
                        if self.includeEntities:
                            if not title in self.includeEntities:
                                logger.debug("i=\"%s\" name=\"%s\" of type=macro not in includeEntities list in app=%s" % (self.stanzaName, macroInfo["name"], app))
                                keep = False
                                break
                        if self.excludeEntities:
                            if title in self.excludeEntities:
                                logger.debug("i=\"%s\" name=\"%s\" of type=macro in excludeEntities list in app=%s" % (self.stanzaName, macroInfo["name"], app))
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
                                        logger.debug("i=\"%s\" name=\"%s\" of type=macro sharing=%s in app=%s" % (self.stanzaName, macroInfo["name"], theList.text, app))
                                        macroInfo["sharing"] = theList.text

                                        #If we are excluding private then check the sharing is not user level (private in the GUI)
                                        if self.noPrivate and macroInfo["sharing"] == "user":
                                            logger.debug("i=\"%s\" name=\"%s\" of type=macro found but the noPrivate flag is true, excluding this in app=%s" % (self.stanzaName, macroInfo["name"], app))
                                            keep = False
                                            break
                                    elif theList.attrib['name'] == 'app':
                                        logger.debug("i=\"%s\" macro app=%s" % (self.stanzaName, theList.text))
                                        foundApp = theList.text
                                        #We can see globally shared objects in our app context, it does not mean we should migrate them as it's not ours...
                                        if app != foundApp:
                                            logger.debug("i=\"%s\" name=\"%s\" of type macro found in app context of app=%s, belongs to app context app=%s, excluding it" % (self.stanzaName, macroInfo["name"], app, foundApp))
                                            keep = False
                                            break
                                    #owner is used as a nicer alternative to the author
                                    elif theList.attrib['name'] == 'owner':
                                        macroInfo["owner"] = theList.text
                                        owner = theList.text
                                        logger.debug("i=\"%s\" name=\"%s\" of type=macro owner=%s" % (self.stanzaName, macroInfo["name"], owner))
                                        if self.includeOwner:
                                            if not owner in self.includeOwner:
                                                logger.debug("i=\"%s\" name=\"%s\" of type=macro with owner=%s not in includeOwner list in app=%s" % (self.stanzaName, macroInfo["name"], owner, app))
                                                keep = False
                                                break
                                        if self.excludeOwner:
                                            if owner in self.excludeOwner:
                                                logger.debug("i=\"%s\" name=\"%s\" of type=macro with owner=%s in excludeOwner list in app=%s" % (self.stanzaName, macroInfo["name"], owner, app))
                                                keep = False
                                                break
                            else:
                                #We have other attributes under content, we want the majority of them
                                attribName = theAttribute.attrib['name']
                                #Check if we have hit hte disabled attribute and we have a noDisabled flag
                                if attribName == "disabled" and self.noDisabled and theAttribute.text == "1":
                                    logger.debug("i=\"%s\" noDisabled flag is true, name=\"%s\" of type=macro is disabled, excluded in app=%s" % (self.stanzaName, theAttribute.attrib['name'], app))
                                    keep = False
                                    break
                                else:
                                    #Otherwise we want this attribute
                                    attribName = theAttribute.attrib['name']
                                    #Some attributes do not work with the REST API or should not be migrated...
                                    logger.debug("i=\"%s\" name=\"%s\" of type=macro key/value pair of %s=%s in app=%s" % (self.stanzaName, macroInfo["name"], attribName, theAttribute.text, app))
                                    macroInfo[attribName] = theAttribute.text
                    elif innerChild.tag.endswith("updated"):
                        macroInfo["updated"] = innerChild.text
                if keep:
                    #Add this to the infoList
                    sharing = macroInfo["sharing"]
                    if sharing not in macros:
                        macros[sharing] = []
                    macros[sharing].append(macroInfo)

                    #Updated time was for our reference only, don't try to send that in while creating/updating the object
                    updated = macroInfo["updated"]
                    del macroInfo["updated"]

                    logger.debug("Updated time is updated=%s" % (updated))
                    epochUpdatedTime = int((self.determineTime(updated) - datetime(1970,1,1)).total_seconds())
                    if self.lastRunEpoch == None or int(self.lastRunEpoch) <= epochUpdatedTime:
                        logger.info("i=\"%s\" name=\"%s\" of type=macro in app context app=%s with owner=%s was updated at %s updated=true" % (self.stanzaName, macroInfo["name"], app, owner, updated))
                    logger.debug("i=\"%s\" name=\"%s\" of type=macro in app context app=%s with owner=%s was updated at %s or epoch of %s compared to lastRunEpoch of %s" % (self.stanzaName, macroInfo["name"], app, owner, updated, epochUpdatedTime, self.lastRunEpoch))
                    logger.info("i=\"%s\" Recording macro info for name=\"%s\" in app=%s with owner=%s sharing=%s" % (self.stanzaName, macroInfo["name"], app, macroInfo["owner"], macroInfo["sharing"]))
                    macroCreationSuccess.append(macroInfo["name"])

        #Find the storage directory for this app and create if required
        appStorageDir = self.gitTempDir + "/" + app
        if not os.path.isdir(appStorageDir):
            os.mkdir(appStorageDir)

        #Cycle through each one we need to migrate, we do global/app/user as users can duplicate app level objects with the same names
        #but we create everything at user level first then re-own it so global/app must happen first
        if "global" in macros:
            logger.debug("i=\"%s\" Now persisting knowledge objects of type=macro with sharing=global in app=%s" % (self.stanzaName, app))
            #persist global to disk
            globalStorageDir = appStorageDir + "/global"
            if not os.path.isdir(globalStorageDir):
                os.mkdir(globalStorageDir)
            if self.file_per_ko:
                # in the file per-ko method we want 1 file per knowledge object...
                global_macro_dir = globalStorageDir + "/macros"
                files, dirs = self.write_files(global_macro_dir, macros["global"])
                self.remove_dir_contents(files, dirs, "macros", "global", self.disable_file_deletion)
            else:
                # in the original method we dumped 1 large file with all macros at this scope
                with open(globalStorageDir + "/macros", 'w', encoding="utf-8") as f:
                    f.write(six.text_type(json.dumps(macros["global"], sort_keys=True, indent=0)))
                    # add newline so git doesn't think it's different every commit...
                    f.write("\n")
        if "app" in macros:
            logger.debug("i=\"%s\" Now persisting knowledge objects of type=macro with sharing=app in app=%s" % (self.stanzaName, app))
            #persist app level to disk
            appLevelStorageDir = appStorageDir + "/app"
            if not os.path.isdir(appLevelStorageDir):
                os.mkdir(appLevelStorageDir)
            if self.file_per_ko:
                # in the file per-ko method we want 1 file per knowledge object...
                app_macro_dir = appLevelStorageDir + "/macros"
                files, dirs = self.write_files(app_macro_dir, macros["app"])
                self.remove_dir_contents(files, dirs, "macros", "app", self.disable_file_deletion)
            else:
                # in the original method we dumped 1 large file with all macros at this scope
                with open(appLevelStorageDir + "/macros", 'w', encoding="utf-8") as f:
                    f.write(six.text_type(json.dumps(macros["app"], sort_keys=True, indent=0)))
                    # add newline so git doesn't think it's different every commit...
                    f.write("\n")
        if "user" in macros:
            logger.debug("i=\"%s\" Now persisting knowledge objects of type=macro with sharing=user (private) in app %s" % (self.stanzaName, app))
            #persist user level to disk
            userLevelStorageDir = appStorageDir + "/user"
            if not os.path.isdir(userLevelStorageDir):
                os.mkdir(userLevelStorageDir)
            if self.file_per_ko:
                # in the file per-ko method we want 1 file per knowledge object...
                user_macro_dir = userLevelStorageDir + "/macros"
                files, dirs = self.write_files(user_macro_dir, macros["user"])
                self.remove_dir_contents(files, dirs, "macros", "user", self.disable_file_deletion)
            else:
                # in the original method we dumped 1 large file with all macros at this scope
                with open(userLevelStorageDir + "/macros", 'w', encoding="utf-8") as f:
                    f.write(six.text_type(json.dumps(macros["user"], sort_keys=True, indent=0)))
                    # add newline so git doesn't think it's different every commit...
                    f.write("\n")

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
        ignoreList = [ "disabled", "eai:appName", "eai:digest", "eai:userName", "isDashboard", "isVisible", "label", "rootNode", "description", "version" ]
        return self.runQueries(app, "/data/ui/views", "dashboards", ignoreList)

    ###########################
    #
    # Saved Searches
    #
    ###########################
    def savedsearches(self, app):
        ignoreList = [ "embed.enabled", "triggered_alert_count", "next_scheduled_time", "qualifiedSearch" ]

        return self.runQueries(app, "/saved/searches", "savedsearches", ignoreList, extra_args="&listDefaultActionArgs=false")

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
        return self.runQueries(app, "/data/props/fieldaliases", "fieldaliases", ignoreList, nameOverride="name")

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
    def runSearchJob(self, query, app_context=None, earliest=None, latest=None):
        if not app_context:
            app_context = self.appName
        url = self.splunk_rest + "/servicesNS/-/%s/search/jobs" % (app_context)
        logger.debug("i=\"%s\" Running requests.post() on url=%s with user=%s query=\"%s\", proxies_length=%s, sslVerify=%s, earliest=%s, latest=%s" % (self.stanzaName, url, self.srcUsername, query, len(self.proxies), self.sslVerify, earliest, latest))
        data = { "search" : query, "output_mode" : "json", "exec_mode" : "oneshot" }

        if earliest:
            data["earliest_time"] = earliest
        if latest:
            data["latest_time"] = latest

        #no srcUsername, use the session_key method
        headers = {}
        auth = None
        if not self.srcUsername:
            headers = {'Authorization': 'Splunk %s' % self.session_key }
        else:
            auth = HTTPBasicAuth(self.srcUsername, self.srcPassword)
        res = requests.post(url, auth=auth, headers=headers, verify=self.sslVerify, data=data, proxies=self.proxies)
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

    # clone the git directory to the filesystem
    def clone_git_dir(self, config):
        if self.windows:
            clone_str = "cd /d {0} & {1} clone {2}".format(self.gitRootDir, self.git_command, self.gitRepoURL)
            if len(self.git_proxies) > 0 and self.gitRepoHTTP:
                clone_str = "set HTTPS_PROXY=" + self.git_proxies["https"] + " & " + clone_str
        else:
            clone_str = "cd {0}; {1} clone {2} 2>&1".format(self.gitRootDir, self.git_command, self.gitRepoURL)
            if len(self.git_proxies) > 0 and self.gitRepoHTTP:
                clone_str = "export HTTPS_PROXY=" + self.git_proxies["https"] + " ; " + clone_str
        (output, stderrout, res) = runOSProcess(clone_str, logger, timeout=300, shell=True)
        return (output, stderrout, res)

    def set_git_details(self, config):
        if self.windows:
            if 'git_name' or 'git_email' in config:
                set_str = "cd /d {0}".format(self.gitTempDir)
                if 'git_name' in config:
                    set_str = set_str + " & {0} config user.name \"".format(self.git_command) + config['git_name'] + "\""
                if 'git_email' in config:
                    set_str = set_str + " & {0} config user.email \"".format(self.git_command) + config['git_email'] + "\""
        else:
            if 'git_name' or 'git_email' in config:
                set_str = "cd {0}".format(self.gitTempDir)
                if 'git_name' in config:
                    set_str = set_str + " ; {0} config user.name \"".format(self.git_command) + config['git_name'] + "\""
                if 'git_email' in config:
                    set_str = set_str + " ; {0} config user.email \"".format(self.git_command) + config['git_email'] + "\""
        if 'git_name' or 'git_email' in config:
            (output, stderrout, res) = runOSProcess(set_str, logger, timeout=300, shell=True)
        else:
            output=""
            stderrout=""
            res=True
        return (output, stderrout, res)

    # run the git pull
    def run_git_pull(self):
        #Always start from the git branch and the current version (just in case changes occurred)
        if self.windows:
            pull_str = "cd /d %s & %s checkout %s & %s pull" % (self.gitTempDir, self.git_command, self.git_branch, self.git_command)
            if len(self.git_proxies) > 0 and self.gitRepoHTTP:
                pull_str = "set HTTPS_PROXY=" + self.git_proxies["https"] + " & " + pull_str
            (output, stderrout, res) = runOSProcess(pull_str, logger, timeout=300, shell=True)
        else:
            pull_str = "cd %s; %s checkout %s; %s pull" % (self.gitTempDir, self.git_command, self.git_branch, self.git_command)
            if len(self.git_proxies) > 0 and self.gitRepoHTTP:
                pull_str = "export HTTPS_PROXY=" + self.git_proxies["https"] + " ; " + pull_str
            (output, stderrout, res) = runOSProcess(pull_str, logger, timeout=300, shell=True)
        return (output, stderrout, res)

    ###########################
    #
    # per-app helper (runs the backup logic per-app)
    #
    ##########################
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
            if debugMode == "true" or debugMode == "t" or debugMode == "1":
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
            if self.noPrivate == "true" or self.noPrivate=="t" or self.noPrivate == "1":
                self.noPrivate = True
            else:
                self.noPrivate = False

        if 'noDisabled' in config:
            self.noDisabled = config['noDisabled'].lower()
            if self.noDisabled == "true" or self.noDisabled=="t" or self.noDisabled == "1":
                self.noDisabled = True
            else:
                self.noDisabled = False

        self.run_ko_query = False
        if 'run_ko_query' in config:
            run_ko_query = config['run_ko_query'].lower()
            if run_ko_query == "true" or run_ko_query=="t" or run_ko_query == "1":
                self.run_ko_query = True

        self.run_ko_diff = False
        if 'run_ko_diff' in config:
            run_ko_diff = config['run_ko_diff'].lower()
            if run_ko_diff == "true" or run_ko_diff=="t" or run_ko_diff == "1":
                self.run_ko_diff = True

        self.use_wdiff = False
        if 'use_wdiff' in config:
            use_wdiff = config['use_wdiff'].lower()
            if use_wdiff == "true" or use_wdiff=="t" or use_wdiff == "1":
                self.use_wdiff = True

        self.disable_file_deletion = False
        if 'disable_file_deletion' in config:
            disable_file_deletion = config['disable_file_deletion'].lower()
            if disable_file_deletion == "true" or disable_file_deletion == "1":
                self.disable_file_deletion = True
                logger.debug("i=\"%s\" useLocalAuth enabled" % (self.stanzaName))

        useLocalAuth = False
        if 'useLocalAuth' in config:
            useLocalAuth = config['useLocalAuth'].lower()
            if useLocalAuth == "true" or useLocalAuth=="t" or useLocalAuth == "1":
                useLocalAuth = True
                logger.debug("i=\"%s\" useLocalAuth enabled" % (self.stanzaName))
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

        self.session_key = config['session_key']

        self.git_password = False
        # a flag for a http/https vs SSH based git repo
        if self.gitRepoURL.find("http") == 0:
            self.gitRepoHTTP = True
            if self.gitRepoURL.find("password:") != -1:
                self.gitRepoURL_logsafe = self.gitRepoURL
                start = self.gitRepoURL.find("password:") + 9
                end = self.gitRepoURL.find("@")
                logger.debug("Attempting to replace self.gitRepoURL=%s by subsituting=%s with a password" % (self.gitRepoURL, self.gitRepoURL[start:end]))
                self.git_password = get_password(self.gitRepoURL[start:end], self.session_key, logger)
                self.gitRepoURL = self.gitRepoURL[0:start-9] + self.git_password + self.gitRepoURL[end:]
            else:
                self.gitRepoURL_logsafe = self.gitRepoURL
        else:
            self.gitRepoHTTP = False
            self.gitRepoURL_logsafe = self.gitRepoURL

        if 'git_command' in config:
            self.git_command = config['git_command'].strip()
            self.git_command = self.git_command.replace("\\","/")
            logger.debug("Overriding git command to %s" % (self.git_command))
        else:
            self.git_command = "git"

        if 'disable_git_ssl_verify' in config:
            if config['disable_git_ssl_verify'].lower() == 'true' or config['disable_git_ssl_verify'].lower() == 't' or config['disable_git_ssl_verify'] == "1":
                self.git_command = "GIT_SSL_NO_VERIFY=true " + self.git_command
                logger.debug('git_command now has GIT_SSL_NO_VERIFY=true because disable_git_ssl_verify: ' + config['disable_git_ssl_verify'])
            elif config['disable_git_ssl_verify'].lower() == 'false' or config['disable_git_ssl_verify'] == "0":
                logger.debug('disable_git_ssl_verify set to boolean False from: ' + config['disable_git_ssl_verify'])
            else:
                logger.warn('disable_git_ssl_verify not set to a valid value, ignoring the setting, please update the setting from: ' + config['disable_git_ssl_verify'])

        if 'ssh_command' in config:
            self.ssh_command = config['ssh_command'].strip()
            self.ssh_command = self.ssh_command.replace("\\","/")
            logger.debug("Overriding ssh command to %s" % (self.ssh_command))
        else:
            self.ssh_command = "ssh"

        if platform.system() == "Windows":
            self.windows = True
        else:
            self.windows = False

        if 'git_branch' in config:
            self.git_branch = config['git_branch'].strip()
            logger.debug("Overriding git branch to %s" % (self.git_branch))
        else:
            self.git_branch = "master"

        proxies = {}
        if 'proxy' in config:
            proxies['https'] = config['proxy']
            if proxies['https'].find("password:") != -1:
                start = proxies['https'].find("password:") + 9
                end = proxies['https'].find("@")
                logger.debug("Attempting to replace proxy=%s by subsituting=%s with a password" % (proxies['https'], proxies['https'][start:end]))
                temp_password = get_password(proxies['https'][start:end], self.session_key, logger)
                proxies['https'] = proxies['https'][0:start-9] + temp_password + proxies['https'][end:]

        self.proxies = proxies

        git_proxies = {}
        if 'git_proxy' in config:
            git_proxies['https'] = config['git_proxy']
            if git_proxies['https'].find("password:") != -1:
                start = git_proxies['https'].find("password:") + 9
                end = git_proxies['https'].find("@")
                logger.debug("Attempting to replace git_proxy=%s by subsituting=%s with a password" % (git_proxies['https'], git_proxies['https'][start:end]))
                temp_password = get_password(git_proxies['https'][start:end], self.session_key, logger)
                git_proxies['https'] = git_proxies['https'][0:start-9] + temp_password + git_proxies['https'][end:]

        self.git_proxies = git_proxies

        if 'sslVerify' in config:
            if config['sslVerify'].lower() == 'true' or config['sslVerify'] == "1":
                self.sslVerify = True
                logger.debug('sslverify set to boolean True from: ' + config['sslVerify'])
            elif config['sslVerify'].lower() == 'false' or config['sslVerify'] == "0":
                self.sslVerify = False
                logger.debug('sslverify set to boolean False from: ' + config['sslVerify'])
            else:
                self.sslVerify = config['sslVerify']
                logger.debug('sslverify set to: ' + config['sslVerify'])

        self.file_per_ko = False
        if 'file_per_ko' in config:
            if config['file_per_ko'].lower() == 'true' or config['file_per_ko'] == "1":
                self.file_per_ko = True
                logger.debug('file_per_ko set to boolean True from: ' + config['file_per_ko'])
            elif config['file_per_ko'].lower() == 'false' or config['file_per_ko'] == "0":
                logger.debug('file_per_ko set to boolean False from: ' + config['file_per_ko'])
            else:
                logger.warn('i=\"%s\" file_per_ko set to unknown value, should be true or false, defaulting to false value=\"%s\"' % (self.stanzaName, config['file_per_ko']))

        self.show_passwords = False
        if 'show_passwords' in config:
            if config['show_passwords'].lower() == 'true' or config['show_passwords'] == "1":
                self.show_passwords = True
                logger.debug('show_passwords is now true due to show_passwords: ' + config['show_passwords'])

        #From server
        self.splunk_rest = config['srcURL']
        excludedList = [ "srcPassword", "session_key" ]
        cleanArgs = self.without_keys(config, excludedList)
        logger.info("i=\"%s\" Splunk Version Control Backup run with arguments=%s" % (self.stanzaName, cleanArgs))

        #Use current epoch to output a checkpoint file at the end
        #If we have not run before just backup everything
        currentEpochTime = calendar.timegm(time.gmtime())

        headers={'Authorization': 'Splunk %s' % config['session_key']}

        url = 'https://localhost:8089/services/shcluster/captain/info?output_mode=json'
        res = requests.get(url, headers=headers, verify=False)
        if (res.status_code == 503):
            logger.debug("i=\"%s\" Non-shcluster / standalone instance, safe to run on this node" % (self.stanzaName))
        elif (res.status_code != requests.codes.ok):
            logger.error("i=\"%s\" unable to determine if this is a search head cluster or not, this is a bug, URL=%s statuscode=%s reason=%s, response=\"%s\". Continuing run" % (self.stanzaName, url, res.status_code, res.reason, res.text))
        elif (res.status_code == 200):
            #We're in a search head cluster, but are we the captain?
            json_dict = json.loads(res.text)
            if json_dict['origin'] != "https://localhost:8089/services/shcluster/captain/info":
                logger.info("i=\"%s\", we are not on the captain, exiting now" % (self.stanzaName))
                return
            else:
                logger.info("i=\"%s\" we are on the captain node, running" % (self.stanzaName))

        if not useLocalAuth and self.srcPassword.find("password:") == 0:
            self.srcPassword = get_password(self.srcPassword[9:], self.session_key, logger)

        if 'appsList' in config and config['appsList']!="":
            appList = [app.strip() for app in config['appsList'].split(',')]
        else:
            appList = self.getAllAppsList()

        logger.debug("i=\"%s\" AppList is (before trim) %s" % (self.stanzaName, appList))
        self.removeExcludedApps(appList)
        logger.debug("i=\"%s\" AppList is (post trim) %s" % (self.stanzaName, appList))

        gitFailure = False

        self.gitTempDir = config['gitTempDir']
        self.gitRootDir = config['gitTempDir']
        dirExists = os.path.isdir(self.gitTempDir)
        if dirExists and len(os.listdir(self.gitTempDir)) != 0:
            if not ".git" in os.listdir(self.gitTempDir):
                #include the subdirectory which is the git repo
                self.gitTempDir = self.gitTempDir + "/" + os.listdir(self.gitTempDir)[0]
                logger.debug("gitTempDir=%s" % (self.gitTempDir))
        else:
            if not dirExists:
                #make the directory and clone under here
                os.mkdir(self.gitTempDir)

            if not self.gitRepoHTTP:
                #Initially we must trust our remote repo URL
                (output, stderrout, res) = runOSProcess(self.ssh_command + " -n -o \"BatchMode yes\" -o StrictHostKeyChecking=no " + self.gitRepoURL[:self.gitRepoURL.find(":")], logger)
                if res == False:
                    if not self.show_passwords and self.git_password:
                        output = output.replace(self.git_password, "password_removed")
                        stderrout = stderrout.replace(self.git_password, "password_removed")
                    logger.warn("i=\"%s\" Unexpected failure while attempting to trust the remote git repo?! stdout '%s' stderr '%s'" % (self.stanzaName, output, stderrout))

            (output, stderrout, res) = self.clone_git_dir(config)
            if res == False:
                if not self.show_passwords and self.git_password:
                    output = output.replace(self.git_password, "password_removed")
                    stderrout = stderrout.replace(self.git_password, "password_removed")
                logger.fatal("i=\"%s\" git clone failed for some reason...on url %s stdout of '%s' with stderrout of '%s'" % (self.stanzaName, self.gitRepoURL_logsafe, output, stderrout))
                sys.exit(1)
            else:
                logger.info("i=\"%s\" Successfully cloned the git URL from %s into directory %s" % (self.stanzaName, self.gitRepoURL_logsafe, self.gitTempDir))
                if not ".git" in os.listdir(self.gitTempDir):
                    #include the subdirectory which is the git repo
                    self.gitTempDir = self.gitTempDir + "/" + os.listdir(self.gitTempDir)[0]
                    logger.debug("gitTempDir=%s" % (self.gitTempDir))

            if stderrout.find("error:") != -1 or stderrout.find("fatal:") != -1 or stderrout.find("timeout after") != -1:
                if not self.show_passwords and self.git_password:
                    stderrout = stderrout.replace(self.git_password, "password_removed")
                logger.warn("i=\"%s\" error/fatal messages in git stderroutput please review. stderrout=\"%s\"" % (self.stanzaName, stderrout))
                gitFailure = True

            (output, stderrout, res) = self.set_git_details(config)
            if res == False:
                logger.error("i=\"%s\" git configuration failed for some reason output=\"%s\", stderrout=\"%s\"" % (self.stanzaName, output, stderrout))

        lastRunEpoch = None
        appsWithChanges = None
        #Version Control File to record when we last ran
        versionControlFile = "%s/splunkversioncontrol_lastrunepoch_%s" % (config['checkpoint_dir'], self.stanzaName)
        if os.path.isfile(versionControlFile):
            logging.debug("i=\"%s\" reading file=%s to determine checkpoint" % (self.stanzaName, versionControlFile))
            fileH = open(versionControlFile, "r")
            lastRunEpoch = fileH.readlines()
            logging.debug("i=\"%s\" from file=%s found these lines %s" % (self.stanzaName, versionControlFile, lastRunEpoch))
            fileH.close()
            if len(lastRunEpoch) != 1:
                logging.warn("i=\"%s\" from file=%s no lines found!? Running against all apps now" % (self.stanzaName, versionControlFile))
            else:
                lastRunEpoch = lastRunEpoch[0].strip()
                self.lastRunEpoch = lastRunEpoch
                appsWithChanges = {}
                logger.info("i=\"%s\" %s reports a lastrun_epoch=%s using this date in report calls" % (self.stanzaName, versionControlFile, lastRunEpoch))

                #Run a query to determine which apps/types of knowledge objects have changed since the last run
                res = self.runSearchJob("savedsearch \"SplunkVersionControl ChangeDetector Directory\" updatedEpoch=%s" % (lastRunEpoch))
                resList = res["results"]
                if len(resList) > 0:
                    logger.debug("i=\"%s\" Result list is %s" % (self.stanzaName, resList))
                    for aRes in resList:
                        if not "app" in aRes or not "type" in aRes:
                            logger.warn("i=\"%s\" This row of the results appears to not have an app/type, aRes=\"%s\"" % (self.stanzaName, aRes))
                            continue
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
                    logger.debug("i=\"%s\" Result list is %s" % (self.stanzaName, resList))
                    for aRes in resList:
                        if not "app" in aRes or not "type" in aRes:
                            logger.warn("i=\"%s\" This row of the results appears to not have an app/type, aRes=\"%s\"" % (self.stanzaName, aRes))
                            continue
                        app = aRes["app"]
                        type = aRes["type"]

                        logger.debug("i=\"%s\" Found changes to app=%s of type=%s" % (self.stanzaName, app, type))

                        if not app in appsWithChanges:
                            appsWithChanges[app] = []
                        appsWithChanges[app].append(type)
        else:
            logger.info("i=\"%s\" %s does not exist, running against all apps now" % (self.stanzaName, versionControlFile))

        #Always start from the git branch and the current version (just in case changes occurred)
        (output, stderrout, res) = self.run_git_pull()
        if res == False:
            if not self.show_passwords and self.git_password:
                output = output.replace(self.git_password, "password_removed")
                stderrout = stderrout.replace(self.git_password, "password_removed")
            logger.warn("i=\"%s\" git checkout %s or git pull failed, stdout is '%s' stderrout is '%s'. Wiping git directory" % (self.stanzaName, self.git_branch, output, stderrout))

            shutil.rmtree(self.gitTempDir)

            (output, stderrout, res) = self.clone_git_dir(config)
            if res == False:
                if not self.show_passwords and self.git_password:
                    output = output.replace(self.git_password, "password_removed")
                    stderrout = stderrout.replace(self.git_password, "password_removed")
                logger.fatal("i=\"%s\" git clone failed for some reason...on url %s stdout of '%s' with stderrout of '%s'" % (self.stanzaName, self.gitRepoURL_logsafe, output, stderrout))
                sys.exit(1)
            else:
                logger.info("i=\"%s\" Successfully cloned the git URL from %s into directory %s" % (self.stanzaName, self.gitRepoURL_logsafe, self.gitTempDir))

            (output2, stderrout2, res) = self.set_git_details(config)
            if res == False:
                logger.error("i=\"%s\" git configuration failed for some reason output=\"%s\", stderrout=\"%s\"" % (self.stanzaName, output2, stderrout2))

        if stderrout.find("error:") != -1 or stderrout.find("fatal:") != -1 or stderrout.find("timeout after") != -1:
            if not self.show_passwords and self.git_password:
                stderrout = stderrout.replace(self.git_password, "password_removed")
            logger.warn("i=\"%s\" error/fatal messages in git stderroutput please review. stderrout=\"%s\"" % (self.stanzaName, stderrout))
            gitFailure = True

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

        #Always start from the git branch and the current version (just in case someone was messing around in the temp directory)
        (output, stderrout, res) = self.run_git_pull()
        if res == False:
            if not self.show_passwords and self.git_password:
                output = output.replace(self.git_password, "password_removed")
                stderrout = stderrout.replace(self.git_password, "password_removed")
            logger.warn("i=\"%s\" git checkout %s or git pull failed, stdout is '%s' stderrout is '%s', wiping git directory and trying again" % (self.stanzaName, self.git_branch, output, stderrout))

            shutil.rmtree(self.gitTempDir)

            (output, stderrout, res) = self.clone_git_dir(config)
            if res == False:
                if not self.show_passwords and self.git_password:
                    output = output.replace(self.git_password, "password_removed")
                    stderrout = stderrout.replace(self.git_password, "password_removed")
                logger.fatal("i=\"%s\" git clone failed for some reason...on url %s stdout of '%s' with stderrout of '%s'" % (self.stanzaName, self.gitRepoURL_logsafe, output, stderrout))
                sys.exit(1)
            else:
                logger.info("i=\"%s\" Successfully cloned the git URL from %s into directory %s" % (self.stanzaName, self.gitRepoURL_logsafe, self.gitTempDir))

            (output2, stderrout2, res) = self.set_git_details(config)
            if res == False:
                logger.error("i=\"%s\" git configuration failed for some reason output=\"%s\", stderrout=\"%s\"" % (self.stanzaName, output2, stderrout2))

        if stderrout.find("error:") != -1 or stderrout.find("fatal:") != -1 or stderrout.find("timeout after") != -1:
            if not self.show_passwords and self.git_password:
                stderrout = stderrout.replace(self.git_password, "password_removed")
            logger.warn("i=\"%s\" error/fatal messages in git stderroutput please review. stderrout=\"%s\"" % (self.stanzaName, stderrout))
            gitFailure = True

        #At this point we've written out the potential updates
        if self.windows:
            (output, stderrout, res) = runOSProcess("cd /d %s & %s status | findstr /C:\"nothing to commit\"" % (self.gitTempDir, self.git_command), logger, shell=True)
        else:
            (output, stderrout, res) = runOSProcess("cd %s; %s status | grep \"nothing to commit\"" % (self.gitTempDir, self.git_command), logger, shell=True)
        if res == False:
            #We have one or more files to commit, do something
            todaysDate = datetime.now().strftime("%Y-%m-%d_%H%M")
            if self.windows:
                push_str = "cd /d {0} & {3} add -A & {3} commit -am \"Updated by Splunk Version Control backup job {1}\" & {3} tag {2} & {3} push origin {4} --tags".format(self.gitTempDir, self.stanzaName, todaysDate, self.git_command, self.git_branch)
                if len(self.git_proxies) > 0 and self.gitRepoHTTP:
                    push_str = "set HTTPS_PROXY=" + self.git_proxies["https"] + " & " + push_str
                (output, stderrout, res) = runOSProcess(push_str, logger, timeout=300, shell=True)
            else:
                push_str = "cd {0}; {3} add -A; {3} commit -am \"Updated by Splunk Version Control backup job {1}\"; {3} tag {2}; {3} push origin {4} --tags".format(self.gitTempDir, self.stanzaName, todaysDate, self.git_command, self.git_branch)
                if len(self.git_proxies) > 0 and self.gitRepoHTTP:
                    push_str = "export HTTPS_PROXY=" + self.git_proxies["https"] + " ; " + push_str
                (output, stderrout, res) = runOSProcess(push_str, logger, timeout=300, shell=True)
                res=True
            if res == False:
                if not self.show_passwords and self.git_password:
                    output = output.replace(self.git_password, "password_removed")
                    stderrout = stderrout.replace(self.git_password, "password_removed")
                logger.error("i=\"%s\" Failure while commiting the new files, backup completed but git may not be up-to-date, stdout '%s' stderrout of '%s'" % (self.stanzaName, output, stderrout))
            else:
                # we want to run a knowledge object query against Splunk to determine "what changed"
                if self.run_ko_query:
                    context = self.obtain_svc_ko_query_context()
                    if context:
                        context_list = context.split(":")
                        app_context = context_list[0]
                        query = context_list[1]
                        res = self.runSearchJob("| savedsearch " + query, app_context, lastRunEpoch, currentEpochTime)
                        self.process_ko_query_contents(res, todaysDate)
                    else:
                        logger.warn("i=\"%s\" unable to obtain the macro required to run the knowledge objects query" % (self.stanzaName))
            if stderrout.find("error:") != -1 or stderrout.find("fatal:") != -1 or stderrout.find("timeout after") != -1:
                if not self.show_passwords and self.git_password:
                    stderrout = stderrout.replace(self.git_password, "password_removed")
                logger.warn("i=\"%s\" error/fatal messages in git stderroutput please review. stderrout=\"%s\"" % (self.stanzaName, stderrout))
                gitFailure = True
            else:
                #Append to our tag list so the dashboard shows the new tag as a choice to "restore from"
                res = self.runSearchJob("| makeresults | eval tag=\"%s\" | fields - _time | outputlookup append=t splunkversioncontrol_taglist" % (todaysDate))

        if not gitFailure:
            #Output the time we did the run so we know where to continue from at next runtime
            with open(versionControlFile, 'w', encoding="utf-8") as checkpointFile:
                checkpointFile.write(six.text_type(currentEpochTime))
            logger.info("i=\"%s\" lastrun_epoch=%s written to checkpoint file=%s" % (self.stanzaName, currentEpochTime, versionControlFile))
        else:
            logger.error("i=\"%s\" git failure occurred during runtime, not updating the epoch value. This failure  may require investigation, please refer to the WARNING messages in the logs" % (self.stanzaName))
            logger.warn("i=\"%s\" wiping the git directory, dir=%s to allow re-cloning on next run of the script" % (self.stanzaName, self.gitTempDir))
            shutil.rmtree(self.gitTempDir)

        logger.info("i=\"%s\" Done" % (self.stanzaName))
