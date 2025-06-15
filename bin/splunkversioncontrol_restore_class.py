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
import hashlib
import fnmatch
import urllib3
from splunkversioncontrol_utility import runOSProcess, get_password

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

from splunklib import six


"""
 Restore Knowledge Objects
   There are two ways this code can be triggered the first option and original version was to:
    Query a remote lookup file to determine what items should be restored from git into a Splunk instance
    In general this will be running against the localhost unless it is been tested as the lookup file will be updated
    by a user accessible dashboard
    Basic validation will be done to ensure someone without the required access cannot restore someone else's knowledge objects
  The second option is via a dashboard which triggers a REST endpoint, the REST endpoint then triggers validation steps and passes in parameters
    such as restlist_override which override some settings specific to when we are called from a REST API
  Both versions trigger the same code to restore the actual knowledge object from git, just in different ways...
"""

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
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
    stanza_name = None
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
    # Shared function to list contents of a directory in terms of directories/files
    #
    ###########################
    def list_dir_contents(self, path):
        file_list = []
        for root, directories, files in os.walk(path):
            for name in files:
                file_list.append(os.path.join(root, name))
        return file_list

    ###########################
    #
    # Shared function to determine filename to restore
    #
    ###########################
    def gen_file_name(self, name):
        file_name = six.moves.urllib.parse.quote_plus(name)
        if len(file_name) > 254:
            hash = hashlib.md5(name.encode('utf-8')).hexdigest()
            file_name = file_name[0:222] + hash
        return file_name


    ###########################
    #
    # Restore an individual knowledge object using a wildcard pattern
    #
    ###########################
    def restore_item_wildcard(self, app, user, name, subdir, obj_type, obj_exists_dict, endpoint, restore_as_user, admin_level):
            config_dir = self.gitTempDir + "/" + app + "/" + subdir
            # if we're looking for global objects our scope is app level for checking for existing objects
            scope = subdir
            if subdir == "global":
                scope = "app"

            #check if config directory exists
            if os.path.isdir(config_dir):
                config_file_dir = config_dir + "/" + obj_type
                return_res = False
                return_msg = ""
                warning_msg = ""
                # if we have the file_per_ko option ticked there may be many files within this directory
                if self.file_per_ko:
                    if os.path.isdir(config_file_dir):
                        logger.debug("i=\"%s\" user=%s, name=%s, found config_file_dir=%s to search for files to restore in (wildcard)" % (self.stanza_name, user, name, config_file_dir))
                        file_list = self.list_dir_contents(config_file_dir)
                        file_name_match = []
                        found = False
                        restore_list = []
                        # there may be one or or more files here
                        for a_file in file_list:
                            with open(a_file, 'r') as f:
                                config_item = json.load(f)
                            config_item_name = config_item['name']
                            if fnmatch.fnmatch(config_item_name, name) or ('origName' in config_item and fnmatch.fnmatch(config_item['origName'], name)):
                                #We found the item we need, run the restoration
                                logger.debug("i=\"%s\" user=%s, wildcard_name=%s matches name=%s, dictionary=%s" % (self.stanza_name, user, name, config_item_name, config_item))
                                #fnmatch.fnmatch(entry_name, name)
                                owner = os.path.basename(os.path.dirname(a_file))
                                if owner == user:
                                    logger.info("i=\"%s\" user=%s, name=%s, found file=%s to restore from" % (self.stanza_name, user, config_item_name, a_file))
                                    found = True
                                    restore_list.append(a_file)
                                else:
                                    # if not owned by the user we can still attempt restore, it will only fail if it's a non-admin attempting to restore the objects
                                    logger.debug("i=\"%s\" owner=%s, user=%s, wildcard_name=%s matches name=%s, found file=%s with non-matching owner to potentially restore from" % (self.stanza_name, owner, user, name, config_item_name, a_file))
                                    restore_list.append(a_file)

                        # if we found something that may need restore
                        if found == True or len(restore_list) > 0:
                            #We found the config we need, run the restoration
                            if found:
                                for file_exact_match in restore_list:
                                    logger.debug("i=\"%s\" user=%s, name=%s is found in file=%s" % (self.stanza_name, user, name, file_exact_match))
                                    with open(file_exact_match, 'r') as f:
                                        config_item = json.load(f)
                                    config_item_name = config_item['name']
                                    # check our listing of objects that exist
                                    if config_item_name in obj_exists_dict[scope] or ('origName' in config_item and config_item['origName'] in obj_exists_dict[scope]):
                                        obj_exists = True
                                    else:
                                        obj_exists = False

                                    # actually attempt restoration of this particular object
                                    logger.debug("Attempting to runRestore for config_item=%s, obj_type=%s, endpoint=%s, app=%s, config_item_name=%s, user=%s, restore_as_user=%s, admin_level=%s, obj_exists=%s, subdir=%s" % (config_item, obj_type, endpoint, app, config_item_name, user, restore_as_user, admin_level, obj_exists, subdir))
                                    restore_result, message = self.runRestore(config_item, obj_type, endpoint, app, config_item_name, user, restore_as_user, admin_level, obj_exists)
                                    if restore_result:
                                        return_res = True
                                        return_msg = "%s Restore succeeded for knowledge_object_name=%s obj_type=%s app=%s user=%s restore_as_user=%s obj_exists=%s scope=%s \n" % (return_msg, config_item_name, obj_type, app, user, restore_as_user, obj_exists, subdir)
                                    else:
                                        warning_msg = warning_msg + " " + message
                            # Since we are wildcard matching the chance of finding a non-exact match is high so check this list as well
                            if len(restore_list) > 0:
                                for a_file in restore_list:
                                    logger.debug("i=\"%s\" user=%s, name=%s is potentially found in file=%s" % (self.stanza_name, user, name, a_file))
                                    with open(a_file, 'r') as f:
                                        config_item = json.load(f)
                                        config_item_name = config_item['name']
                                        # check our listing of objects that exist
                                        if config_item_name in obj_exists_dict[scope] or ('origName' in config_item and config_item['origName'] in obj_exists_dict[scope]):
                                            obj_exists = True
                                        else:
                                            obj_exists = False

                                        # actually attempt restoration
                                        logger.debug("Attempting to runRestore for config_item=%s, obj_type=%s, endpoint=%s, app=%s, config_item_name=%s, user=%s, restore_as_user=%s, admin_level=%s, obj_exists=%s, subdir=%s" % (config_item, obj_type, endpoint, app, config_item_name, user, restore_as_user, admin_level, obj_exists, subdir))
                                        restore_result, message = self.runRestore(config_item, obj_type, endpoint, app, config_item_name, user, restore_as_user, admin_level, obj_exists)
                                        if restore_result:
                                            return_res = True
                                            return_msg = "%s Restore succeeded for knowledge_object_name=%s obj_type=%s app=%s user=%s restore_as_user=%s obj_exists=%s scope=%s \n" % (return_msg, config_item_name, obj_type, app, user, restore_as_user, obj_exists, subdir)
                                        else:
                                            warning_msg = warning_msg + " " + message
                    else:
                        #There are no user level objects for this app, therefore the restore will not occur at this scope
                        logger.info("i=\"%s\" user directory of dir=%s does not have a sub-directory of type=%s" % (self.stanza_name, config_dir, obj_type))
                        warning_msg = warning_msg + "\nNo objects of type=%s found in directory %s\n" % (obj_type, config_dir)
                else:
                    # we are not using the knowledge object per-file so load the file
                    if os.path.isfile(config_file_dir):
                        #The file exists, open it and read the config
                        logger.debug("i=\"%s\" user=%s, name=%s, found config_file_dir=%s to restore from" % (self.stanza_name, user, name, config_file_dir))
                        with open(config_file_dir, 'r') as f:
                            config = json.load(f)
                            found = False
                            for config_item in config:
                                config_item_name = config_item['name']
                                if fnmatch.fnmatch(config_item_name, name) or ('origName' in config_item and fnmatch.fnmatch(config_item['origName'], name)):
                                    #We found the config we need, run the restoration
                                    logger.debug("i=\"%s\" user=%s, name=%s is found, dictionary=%s" % (self.stanza_name, user, name, config_item))
                                    # check our listing of objects that exist
                                    if config_item_name in obj_exists_dict[scope] or ('origName' in config_item and config_item['origName'] in obj_exists_dict[scope]):
                                        obj_exists = True
                                    else:
                                        obj_exists = False

                                    # actually attempt restoration
                                    logger.debug("Attempting to runRestore for config_item=%s, obj_type=%s, endpoint=%s, app=%s, config_item_name=%s, user=%s, restore_as_user=%s, admin_level=%s, obj_exists=%s, subdir=%s" % (config_item, obj_type, endpoint, app, config_item_name, user, restore_as_user, admin_level, obj_exists, subdir))
                                    restore_result, message = self.runRestore(config_item, obj_type, endpoint, app, config_item_name, user, restore_as_user, admin_level, obj_exists)
                                    if restore_result:
                                        return_res = True
                                        return_msg = "%s Restore succeeded for knowledge_object_name=%s obj_type=%s app=%s user=%s restore_as_user=%s obj_exists=%s scope=%s \n" % (return_msg, config_item_name, obj_type, app, user, restore_as_user, obj_exists, subdir)
                                    else:
                                        warning_msg = warning_msg + " " + message
                                    found = True
                            #Let the logs know we never found it at this scope
                            if found == False:
                                logger.info("i=\"%s\" user=%s, name=%s not found at scope=%s in file=%s" % (self.stanza_name, user, name, subdir, config_file_dir))
                    #We never found a file that we could use to restore from  at this scope
                    else:
                        logger.info("i=\"%s\" user=%s, name=%s, did not find a config_file_dir=%s to restore from subdir=%s" % (self.stanza_name, user, name, config_file_dir, subdir))
                        warning_msg = warning_msg + "\nNo objects of type=%s found in directory %s\n" % (obj_type, config_dir)

                # if restore failed add the warnings to the returned message
                if not return_res:
                    return_msg = return_msg + warning_msg
                return return_res, return_msg
            else:
                #There are no <subdir> level objects for this app, therefore the restore will not occur at this scope
                logger.info("i=\"%s\" %s directory of dir=%s does not exist" % (self.stanza_name, subdir, config_dir))
                return False, "Unable to find the subdir=%s in dir=%s" % (subdir, config_dir)

    ###########################
    #
    # Trigger restore based on a wildcard used in the object name
    # Note the obj_exists_dict logic could be flipped to check the object status prior to each restoration attempt
    # rather than using a single REST call to list all objects...
    #
    ###########################
    def restore_wildcard(self, url, app, name, app_scope, user_scope, auth, headers, endpoint, user, restore_as_user, admin_level, obj_type):
        logger.info("i=\"%s\" url=%s app=%s name=%s app_scope=%s user_scope=%s" % (self.stanza_name, url, app, name, app_scope, user_scope))
        
        res = requests.get(url, auth=auth, headers=headers, verify=self.sslVerify, proxies=self.proxies)

        #If we get 404 something is wrong as we expect to get a list of objects of this type... 
        if (res.status_code == 404):
            logger.error("i=\"%s\" URL=%s is throwing a 404, this should not happen with the all objects endpoint" % (self.stanza_name, url))
            return
        elif (res.status_code != requests.codes.ok):
            logger.error("i=\"%s\" URL=%s in app=%s statuscode=%s reason=%s response=\"%s\"" % (self.stanza_name, url, app, res.status_code, res.reason, res.text))
            return

        logger.debug("i=\"%s\" Attempting to JSON loads on (retore_wildcard) %s" % (self.stanza_name, res.text))
        res_dict = json.loads(res.text)

        # objects can be returned from other app contexts if they are global, or other users...
        obj_exists_dict = { "user": [], "app": [] }
        for entry in res_dict['entry']:
            logger.debug(res_dict)
            entry_name = entry['name']
            # fnmatch provides an easy way to wildcard match against each entry
            if fnmatch.fnmatch(entry_name, name):
                sharing_level = entry['acl']['sharing']
                app_context = entry['acl']['app']
                # check to ensure it's from the same app we're restoring to (if we are using an app scoped restore)
                if app_context == app and app_scope == True and (sharing_level == 'app' or sharing_level == 'global'):
                    obj_exists_dict['app'].append(entry_name)
                    logger.debug("i=\"%s\" Adding name=%s into obj_exists_dict at app scope app_context=%s" % (self.stanza_name, entry_name, app_context))
                # check to ensure it is user scoped and from the same app we're restoring to (if we are using a user scoped restore)
                elif app_context == app and user_scope == True and sharing_level == "user":
                    obj_exists_dict['user'].append(entry_name)
                    logger.debug("i=\"%s\" Adding name=%s into obj_exists_dict at user scope app_context=%s" % (self.stanza_name, entry_name, app_context))
        
        overall_res = False
        overall_msg = ""
        #We need to work with user scope
        if user_scope == True:
            logger.debug("Attempting to run restore_item_wildcard at user scope")
            return_res, return_message = self.restore_item_wildcard(app, user, name, "user", obj_type, obj_exists_dict, endpoint, restore_as_user, admin_level)
            if return_res:
                overall_res = True
                overall_msg = return_message + "\n"
        #It's either app level of globally scoped
        if app_scope == True:
            logger.debug("Attempting to run restore_item_wildcard at app scope")
            return_res, return_message = self.restore_item_wildcard(app, user, name, "app", obj_type, obj_exists_dict, endpoint, restore_as_user, admin_level)
            if return_res:
                overall_res = True
                overall_msg = overall_msg + " " + return_message + "\n"
            #If could also be a global level restore...
            logger.debug("Attempting to run restore_item_wildcard at global scope")
            return_res, return_message = self.restore_item_wildcard(app, user, name, "global", obj_type, obj_exists_dict, endpoint, restore_as_user, admin_level)
            if return_res:
                overall_res = True
                overall_msg = overall_msg + " " + return_message + "\n"

        # if restore suceeded at any scope
        if overall_res:
            logger.info("i=\"%s\" user=%s restore has run successfully for name=%s, type=%s, restore_as_user=%s, admin_level=%s. Messages=%s" % (self.stanza_name, user, name, obj_type, restore_as_user, admin_level, overall_msg))
            return True, overall_msg
        else:
            overall_msg = "The object was not found or the restore was unsuccessful. Perhaps check the restore date, scope & capitilisation (case must match exactly) before trying again?\n" + overall_msg
            logger.warn("i=\"%s\" user=%s attempted to restore name=%s, type=%s, restore_as_user=%s, admin_level=%s however the object was not found, the restore was unsuccessful. Perhaps check the restore date, scope & capitilisation (case must match exactly) before trying again?" % (self.stanza_name, user, name, obj_type, restore_as_user, admin_level))
            return False, overall_msg

    ###########################
    #
    # Trigger restore for an exact object name (i.e. no wildcard/ * characters in the name)
    #
    ###########################
    def restore_standard(self, url, app, name, app_scope, user_scope, auth, headers, endpoint, user, restore_as_user, admin_level, obj_type):
        res = requests.get(url, auth=auth, headers=headers, verify=self.sslVerify, proxies=self.proxies)

        obj_exists = False

        #If we get 404 it definitely does not exist or it has a name override
        if (res.status_code == 404):
            logger.debug("i=\"%s\" URL=%s is throwing a 404, assuming new object creation" % (self.stanza_name, url))
        elif (res.status_code != requests.codes.ok):
            logger.error("i=\"%s\" URL=%s in app=%s statuscode=%s reason=%s response=\"%s\"" % (self.stanza_name, url, app, res.status_code, res.reason, res.text))
        else:
            #However the fact that we did not get a 404 does not mean it exists in the context we expect it to, perhaps it's global and from another app context?
            #or perhaps it's app level but we're restoring a private object...
            logger.debug("i=\"%s\" Attempting to JSON loads on (restore_standard) %s" % (self.stanza_name, res.text))
            res_dict = json.loads(res.text)
            for entry in res_dict['entry']:
                sharing_level = entry['acl']['sharing']
                app_context = entry['acl']['app']
                # check to ensure it's from the same app we're restoring to (if we are using an app scoped restore)
                if app_context == app and app_scope == True and (sharing_level == 'app' or sharing_level == 'global'):
                    obj_exists = True
                    logger.debug("i=\"%s\" Found name=%s exists at app scope app_context=%s" % (self.stanza_name, name, app_context))
                # if it's a user scoped restore check that the sharing level is user and the app context is the app we are restoring to
                elif app_context == app and user_scope == True and sharing_level == "user":
                    logger.debug("i=\"%s\" Found name=%s exists at user scope app_context=%s" % (self.stanza_name, name, app_context))
                    obj_exists = True

        configList = []

        overall_res = False
        overall_msg = ""
        #We need to work with user scope
        if user_scope == True:
            logger.debug("Attempt to run restore_item_standard at user scope")
            return_res, return_message = self.restore_item_standard(app, user, name, "user", obj_type, obj_exists, endpoint, restore_as_user, admin_level)
            if return_res:
                overall_res = True
                overall_msg = return_message + "\n"
        #It's either app level of globally scoped
        if app_scope == True:
            logger.debug("Attempt to run restore_item_standard at app scope")
            return_res, return_message = self.restore_item_standard(app, user, name, "app", obj_type, obj_exists, endpoint, restore_as_user, admin_level)
            if return_res:
                overall_res = True
                overall_msg = overall_msg + " " + return_message + "\n"
            #If could also be a global level restore...
            logger.debug("Attempt to run restore_item_standard at global scope")
            return_res, return_message = self.restore_item_standard(app, user, name, "global", obj_type, obj_exists, endpoint, restore_as_user, admin_level)
            if return_res:
                overall_res = True
                overall_msg = overall_msg + " " + return_message + "\n"
        
        # if restore succeeded at any level
        if overall_res:
            logger.info("i=\"%s\" user=%s restore has run successfully for name=%s, type=%s, restore_as_user=%s, admin_level=%s" % (self.stanza_name, user, name, obj_type, restore_as_user, admin_level))
            return True, overall_msg
        else:
            overall_msg = "The object was not found or the restore was unsuccessful. Perhaps check the restore date, scope & capitilisation (case must match exactly) before trying again?\n" + overall_msg
            logger.warn("i=\"%s\" user=%s attempted to restore name=%s, type=%s, restore_as_user=%s, admin_level=%s however the object was not found or the restore was unsuccessful. Perhaps check the restore date, scope & capitilisation (case must match exactly) before trying again?" % (self.stanza_name, user, name, obj_type, restore_as_user, admin_level))
            return False, overall_msg

    ###########################
    #
    # Restore an individual knowledge object with an exact name match (i.e. no wildcard / * characters)
    #
    ###########################
    def restore_item_standard(self, app, user, name, subdir, obj_type, obj_exists, endpoint, restore_as_user, admin_level):
        #We need to work with user scope
        config_dir = self.gitTempDir + "/" + app + "/" + subdir

        # if a file exceeds 255 characters it will result in a file too long error (e.g. really long field extraction names)
        file_name = self.gen_file_name(name)

        #if the user directory exists
        if os.path.isdir(config_dir):
            return_res = False
            return_msg = ""
            warning_msg = ""
            foundAtAnyScope = False
            config_file_dir = config_dir + "/" + obj_type
            # if we have the file_per_ko option ticked there may be many files within this directory
            if self.file_per_ko:
                if os.path.isdir(config_file_dir):
                    logger.debug("i=\"%s\" user=%s, name=%s, found config_file_dir=%s to search for files to restore in" % (self.stanza_name, user, name, config_file_dir))
                    file_list = self.list_dir_contents(config_file_dir)
                    file_name_match = []
                    found = False
                    for a_file in file_list:
                        file_basename = os.path.basename(a_file)
                        if file_name == file_basename:
                            owner = os.path.basename(os.path.dirname(a_file))
                            if owner == user:
                                logger.info("i=\"%s\" user=%s, name=%s, found file=%s to restore from" % (self.stanza_name, user, name, a_file))
                                found = True
                                foundAtAnyScope = True
                                file_exact_match = a_file
                                # we hit the exact file name with the expected owner, leave the loop and restore
                                break
                            else:
                                # if the file is not owned by the user running the restore, it will run if it's an admin user
                                logger.debug("i=\"%s\" owner=%s, user=%s, name=%s, found file=%s with non-matching owner to potentially restore from" % (self.stanza_name, owner, user, name, a_file))
                                file_name_match.append(a_file)
                    if found == True or len(file_name_match) > 0:
                        foundAtAnyScope = True
                        #We found the config we need, run the restoration
                        if found:
                            logger.debug("i=\"%s\" user=%s, name=%s is found in file=%s" % (self.stanza_name, user, name, file_exact_match))
                            with open(file_exact_match, 'r') as f:
                                config = json.load(f)
                                # attempt restoration
                                logger.debug("Attempting to runRestore for config=%s, obj_type=%s, endpoint=%s, app=%s, name=%s, user=%s, restore_as_user=%s, admin_level=%s, obj_exists=%s" % (config, obj_type, endpoint, app, name, user, restore_as_user, admin_level, obj_exists))
                                restore_result, message = self.runRestore(config, obj_type, endpoint, app, name, user, restore_as_user, admin_level, obj_exists)
                                if restore_result:
                                    return_res = True
                                else:
                                    warning_msg = warning_msg + " " + message
                        # We do not have an exact match but many potential matches to restore from
                        # this could be an "if" statement if we want to restore in all matches of the filename irrelevant of the user who own's it
                        # leaving it as elif for now
                        elif len(file_name_match) > 0:
                            for a_file in file_name_match:
                                logger.debug("i=\"%s\" user=%s, name=%s is potentially found in file=%s" % (self.stanza_name, user, name, a_file))
                                with open(a_file, 'r') as f:
                                    config = json.load(f)
                                    logger.debug("Attempting to runRestore for config=%s, obj_type=%s, endpoint=%s, app=%s, name=%s, user=%s, restore_as_user=%s, admin_level=%s, obj_exists=%s" % (config, obj_type, endpoint, app, name, user, restore_as_user, admin_level, obj_exists))
                                    restore_result, message = self.runRestore(config, obj_type, endpoint, app, name, user, restore_as_user, admin_level, obj_exists)
                                    if restore_result:
                                        return_res = True
                                    else:
                                        warning_msg = warning_msg + " " + message
                else:
                    #There are no <subdir> level objects for this app, therefore the restore will not occur at this scope
                    logger.info("i=\"%s\" %s directory of dir=%s does not have a sub-directory of type=%s" % (self.stanza_name, subdir, config_dir, obj_type))
                    warning_msg = warning_msg + "\nNo objects of type=%s found in directory %s\n" % (obj_type, config_dir)
            else:
                # if we're using the older method we have many objects within a file
                if os.path.isfile(config_file_dir):
                    #The file exists, open it and read the config
                    logger.debug("i=\"%s\" user=%s, name=%s, found config_file_dir=%s to restore from" % (self.stanza_name, user, name, config_file_dir))
                    with open(config_file_dir, 'r') as f:
                        config_list = json.load(f)
                        found = False
                        for config_item in config_list:
                            if config_item['name'] == name or ('origName' in config_item and config_item['origName'] == name):
                                #We found the config_item we need, run the restoration
                                logger.debug("i=\"%s\" user=%s, name=%s is found, dictionary is %s" % (self.stanza_name, user, name, config_item))
                                
                                # run the restoration
                                logger.debug("Attempting to runRestore for config=%s, obj_type=%s, endpoint=%s, app=%s, name=%s, user=%s, restore_as_user=%s, admin_level=%s, obj_exists=%s" % (config_item, obj_type, endpoint, app, name, user, restore_as_user, admin_level, obj_exists))
                                restore_result, message = self.runRestore(config_item, obj_type, endpoint, app, name, user, restore_as_user, admin_level, obj_exists)

                                found = True
                                if restore_result:
                                    return_res = True
                        #Let the logs know we never found it at this scope
                        if found == False:
                            logger.info("i=\"%s\" user=%s, name=%s not found at scope=user in file=%s" % (self.stanza_name, user, name, config_file_dir))
                        #We never found a file that we could use to restore from  at this scope
                        else:
                            logger.info("i=\"%s\" user=%s, name=%s, did not find a config_file_dir=%s to restore from" % (self.stanza_name, user, name, config_file_dir))
                            warning_msg = warning_msg + "\nNo objects of type=%s found in directory %s\n" % (obj_type, config_dir)
            if not return_res:
                return_msg = return_msg + warning_msg
            return return_res, return_msg
        else:
            #There are no objects for this app of this type, therefore the restore will not occur at this scope
            logger.info("i=\"%s\" %s directory of dir=%s does not exist" % (self.stanza_name, subdir, config_dir))
            return False, "Unable to find the subdir=%s in dir=%s to use for restoration" % (subdir, config_dir)

    ###########################
    #
    # runQueries (generic version)
    #   This attempts to read the config data from git (stored in json format), if found it will attempt to restore the config to the
    #   destination server
    #   This method works for everything excluding macros which have a different process
    #   Due to variations in the REST API there are a few hacks inside this method to handle specific use cases, however the majority are straightforward
    #
    ###########################
    def runQueries(self, app, endpoint, obj_type, name, scope, user, restore_as_user, admin_level):
        logger.info("i=\"%s\" user=%s, attempting to restore name=%s in app=%s of type=%s in scope=%s, restore_as_user=%s, admin_level=%s" % (self.stanza_name, user, name, app, obj_type, scope, restore_as_user, admin_level))

        url = None
        #Check if the object exists or not
        #Data models require a slightly different URL to just about everything else
        if obj_type=="datamodels" and (scope=="app" or scope=="global"):
            url = self.splunk_rest + "/servicesNS/nobody/%s%s/%s?output_mode=json" % (app, endpoint, name)
        elif obj_type=="datamodels":
            url = self.splunk_rest + "/servicesNS/%s/%s%s/%s?output_mode=json" % (user, app, endpoint, name)
        else:
            url = self.splunk_rest + "/servicesNS/-/%s%s/%s?output_mode=json" % (app, endpoint, name)

        #Data models require a slightly different URL to just about everything else
        if obj_type=="datamodels" and (scope=="app" or scope=="global"):
            all_objects_url = self.splunk_rest + "/servicesNS/nobody/%s%s?output_mode=json&count=0&f=title" % (app, endpoint)
        elif obj_type=="datamodels":
            all_objects_url = self.splunk_rest + "/servicesNS/%s/%s%s?output_mode=json&count=0&f=title" % (user, app, endpoint)
        else:
            all_objects_url = self.splunk_rest + "/servicesNS/-/%s%s?output_mode=json&count=0&f=title" % (app, endpoint)

        #Determine scope that we will attempt to restore
        app_scope = False
        user_scope = False
        if scope == "all":
            app_scope = True
            user_scope = True
        elif scope == "app":
            app_scope = True
        elif scope == "user":
            user_scope = True
        else:
            logger.error("i=\"%s\" user=%s, while attempting to restore name=%s, found invalid scope of scope=%s" % (self.stanza_name, user, name, scope))

        headers = {}
        auth = None

        if not self.destUsername:
            headers={'Authorization': 'Splunk %s' % self.session_key}
        else:
            auth = HTTPBasicAuth(self.destUsername, self.destPassword)

        # at this point if the name includes a wildcard, we have to use the all_objects_url and change the restore logic to restore one or more objects...
        if name.find("*") != -1:
            return_result, return_message = self.restore_wildcard(all_objects_url, app, name, app_scope, user_scope, auth, headers, endpoint, user, restore_as_user, admin_level, obj_type)
            logger.debug("i=\"%s\" return_result=%s return_message=%s from restore_wildcard" % (self.stanza_name, return_result, return_message))
        else:
            return_result, return_message = self.restore_standard(url, app, name, app_scope, user_scope, auth, headers, endpoint, user, restore_as_user, admin_level, obj_type)
            logger.debug("i=\"%s\"  return_result=%s return_message=%s from restore_standard" % (self.stanza_name, return_result, return_message))

        return return_result, return_message

    ###########################
    #
    # runRestore (generic version)
    #   Once we have received the required configuration, type, app, endpoint, name et cetera we attempt
    #   to run the post to restore or create the object
    #
    ###########################
    def runRestore(self, config, obj_type, endpoint, app, name, user, restore_as_user, admin_level, objExists):
        result = True
        #Only an admin can restore an object owned by someone else
        if config['owner'] != user and admin_level == False:
            message = " Owner of the object is listed as owner=%s, app=%s, name=%s, objExists=%s, restore_as_user=%s however user user=%s requested the restore and is not an admin, rejected" % (config['owner'], user, app, name, objExists, restore_as_user)
            logger.error("i=\"" + self.stanza_name + "\"" + message)
            return False, message

        #Only an admin can use the restore_as_user option
        if restore_as_user != "" and restore_as_user != user and admin_level == False:
            message = " restore_as_user=%s which is not user=%s, this user is not an admin, rejected, app=%s, name=%s, objExists=%s" % (restore_as_user, user, app, name, objExists, restore_as_user)
            logger.error("i=\"" + self.stanza_name + "\"" + message)
            return False, message

        #Change the owner to the new oner
        if restore_as_user != "" and admin_level == True:
            config["owner"] = restore_as_user

        logger.info("i=\"%s\" Attempting to run restore for name=%s of type=%s with endpoint=%s user=%s, restore_as_user=%s, admin_level=%s, objExists=%s" % (self.stanza_name, name, obj_type, endpoint, user, restore_as_user, admin_level, objExists))

        sharing = config["sharing"]
        owner = config["owner"]

        message = ""
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
            logger.debug("i=\"%s\" URL=%s re-checking object exists URL due to name override from %s to original name of %s proxies_length=%s" % (self.stanza_name, objExistsURL, name, origName, len(self.proxies)))
            #Verify=false is hardcoded to workaround local SSL issues
            res = requests.get(objExistsURL, auth=auth, headers=headers, verify=self.sslVerify, proxies=self.proxies)

            #If we get 404 it definitely does not exist or it has a name override
            if (res.status_code == 404):
                logger.debug("i=\"%s\" URL=%s is throwing a 404, assuming new object creation" % (self.stanza_name, objExistsURL))
                objExists = False
            elif (res.status_code != requests.codes.ok):
                logger.error("i=\"%s\" URL=%s in app=%s statuscode=%s reason=%s response=\"%s\"" % (self.stanza_name, objExistsURL, app, res.status_code, res.reason, res.text))
            else:
                #However the fact that we did not get a 404 does not mean it exists in the context we expect it to, perhaps it's global and from another app context?
                #or perhaps it's app level but we're restoring a private object...
                logger.debug("i=\"%s\" Attempting to JSON loads on (runRestore) %s" % (self.stanza_name, res.text))
                res_dict = json.loads(res.text)
                for entry in res_dict['entry']:
                    sharing_level = entry['acl']['sharing']
                    app_context = entry['acl']['app']
                    app_scope = False
                    user_scope = False
                    if sharing == "global" or sharing == "app":
                        app_scope = True
                    else:
                        user_scope = True
                    if app_context == app and app_scope == True and (sharing_level == 'app' or sharing_level == 'global'):
                        objExists = True
                    elif app_context == app and user_scope == True and sharing_level == "user":
                        objExists = True
                logger.debug("i=\"%s\" app=%s objExists=%s after re-checking on %s" % (self.stanza_name, app, objExists, objExistsURL))

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

        logger.debug("i=\"%s\" Attempting to %s type=%s with name=%s on URL=%s with payload=\"%s\" in app=%s proxies_length=%s" % (self.stanza_name, createOrUpdate, obj_type, name, url, payload, app, len(self.proxies)))
        res = requests.post(url, auth=auth, headers=headers, verify=self.sslVerify, data=payload, proxies=self.proxies)
        if (res.status_code != requests.codes.ok and res.status_code != 201):
            logger.error("i=\"%s\" user=%s, name=%s of type=%s with URL=%s statuscode=%s reason=%s, response=\"%s\", in app=%s, owner=%s" % (self.stanza_name, user, name, obj_type, url, res.status_code, res.reason, res.text, app, owner))
            #Saved Searches sometimes fail due to the VSID field, auto-retry in case that solves the problem...
            if obj_type=="savedsearches":
                if 'vsid' in payload:
                    del payload['vsid']
                    res = requests.post(url, auth=auth, headers=headers, verify=self.sslVerify, data=payload, proxies=self.proxies)
                    if (res.status_code != requests.codes.ok and res.status_code != 201):
                        logger.error("i=\"%s\" user=%s, re-attempted without vsid but result for name=%s of type=%s with URL=%s statuscode=%s reason=%s, response=\"%s\", in app=%s, owner=%s" % (self.stanza_name, user, name, obj_type, url, res.status_code, res.reason, res.text, app, owner))
                        result = False
                    else:
                        logger.info("i=\"%s\" user=%s, name=%s of type=%s with URL=%s successfully %s with the vsid field removed, feel free to ignore the previous error" % (self.stanza_name, user, name, obj_type, url, createOrUpdate))
        else:
            logger.debug("i=\"%s\" %s name=%s of type=%s in app=%s with URL=%s result=\"%s\" owner=%s" % (self.stanza_name, createOrUpdate, name, obj_type, app, url, res.text, owner))

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
                            logger.debug("i=\"%s\" name=%s of type=%s in app=%s URL=%s" % (self.stanza_name, name, obj_type, app, objURL))
                elif child.tag.endswith("messages"):
                    for innerChild in child:
                        if innerChild.tag.endswith("msg") and innerChild.attrib["type"]=="ERROR" or "WARN" in innerChild.attrib:
                            logger.warn("i=\"%s\" name=%s of type=%s in app=%s had a warn/error message of '%s' owner=%s" % (self.stanza_name, name, obj_type, app, innerChild.text, owner))
                            #Sometimes the object appears to be create but is unusable which is annoying, at least provide the warning to the logs

            if not objURL:
                message = "never found objURL so cannot complete ACL change with url=%s, response text=\"%s\" when looking for name=%s, type=%s app=%s, owner=%s" % (url, res.text, name, obj_type, app, owner)
                logger.warn("i=\"" + self.stanza_name + "\"" + message)
                return False, message

            #Re-owning it to the previous owner and sharing level
            url = "%s/acl" % (objURL)
            payload = { "owner": owner, "sharing" : sharing }
            logger.info("i=\"%s\" Attempting to change ownership of type=%s with name=%s via URL=%s to owner=%s in app=%s with sharing=%s" % (self.stanza_name, obj_type, name, url, owner, app, sharing))
            res = requests.post(url, auth=auth, headers=headers, verify=self.sslVerify, data=payload, proxies=self.proxies)

            #If re-own fails log this for investigation
            if (res.status_code != requests.codes.ok):
                logger.error("i=\"%s\" user=%s, name=%s of type=%s in app=%s with URL=%s statuscode=%s reason=%s, response=\"%s\", owner=%s" % (self.stanza_name, user, name, obj_type, app, url, res.status_code, res.reason, res.text, owner))
                result = False
            else:
                logger.debug("i=\"%s\" user=%s, name=%s of type=%s in app=%s, ownership changed with response=\"%s\", owner=%s, sharing=%s" % (self.stanza_name, user, name, obj_type, app, res.text, owner, sharing))

        logger.info("i=\"%s\" %s name=%s of type=%s in app=%s owner=%s sharing=%s" % (self.stanza_name, createOrUpdate, name, obj_type, app, owner, sharing))
        return result, message

    ###########################
    #
    # macroCreation
    #   Runs the required queries to create or update the macro knowledge objects and then re-owns them to the correct user
    #
    ###########################
    def runRestoreMacro(self, config, app, name, username, restore_as_user, admin_level, objExists):
        result = True
        #Only admins can restore objects on behalf of someone else
        if config['owner'] != username and admin_level == False:
            message = "Owner of the object is listed as owner=%s, however user=%s requested the restore and is not an admin, rejected" % (config['owner'], username)
            logger.error("i=\"" + self.stanza_name + "\"" + message)
            return False, message

        #Only admins can restore objects into someone else's name
        if restore_as_user != "" and restore_as_user != username and admin_level == False:
            message = "restore_as_user=%s which is not the user=%s, this user is not an admin, rejected" % (restore_as_user, username)
            logger.error("i=\"" + self.stanza_name + "\"" + message)
            return False, message

        logger.info("i=\"%s\" Attempting to run macro restore with name=%s, user=%s, restore_as_user=%s, admin_level=%s, objExists=%s" % (self.stanza_name, name, username, restore_as_user, admin_level, objExists))
        #Change the owner to the new oner
        if restore_as_user != "" and admin_level == True:
            config["owner"] = restore_as_user

        sharing = config["sharing"]
        name = config["name"]
        owner = config["owner"]

        headers = {}
        auth = None
        if not self.destUsername:
            headers={'Authorization': 'Splunk %s' % self.session_key}
        else:
            auth = HTTPBasicAuth(self.destUsername, self.destPassword)

        message = ""
        #We are creating the macro
        if objExists == False:
            url = "%s/servicesNS/%s/%s/properties/macros" % (self.splunk_rest, owner, app)
            logger.info("i=\"%s\" Attempting to create type=macro name=%s on URL=%s in app=%s" % (self.stanza_name, name, url, app))

            payload = { "__stanza" : name }
            #Create macro
            #I cannot seem to get this working on the /conf URL but this works so good enough, and it's in the REST API manual...
            #servicesNS/-/search/properties/macros
            #__stanza = <name>

            res = requests.post(url, auth=auth, headers=headers, verify=self.sslVerify, data=payload, proxies=self.proxies)
            if (res.status_code != requests.codes.ok and res.status_code != 201):
                message = "name=%s of type=macro in app=%s with URL=%s statuscode=%s reason=%s, response=\"%s\", owner=%s" % (name, app, url, res.status_code, res.reason, res.text, owner)
                logger.error("i=\"" + self.stanza_name + "\"" + message)
                return False, message
            else:
                #Macros always have the username in this URL context
                objURL = "%s/servicesNS/%s/%s/configs/conf-macros/%s" % (self.splunk_rest, owner, app, name)
                logger.debug("i=\"%s\" name=%s of type=macro in app=%s URL=%s with owner=%s" % (self.stanza_name, name, app, objURL, owner))

            logger.debug("i=\"%s\" name=%s of type=macro in app=%s, received response=\"%s\"" % (self.stanza_name, name, app, res.text))

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

        logger.debug("i=\"%s\" Attempting to modify type=macro name=%s on URL=%s with payload=\"%s\" in app=%s proxies_length=%s" % (self.stanza_name, name, url, payload, app, len(self.proxies)))
        res = requests.post(url, auth=auth, headers=headers, verify=self.sslVerify, data=payload, proxies=self.proxies)
        if (res.status_code != requests.codes.ok and res.status_code != 201):
            logger.error("i=\"%s\" name=%s of type=macro in app=%s with URL=%s statuscode=%s reason=%s, response=\"%s\"" % (self.stanza_name, name, app, url, res.status_code, res.reason, res.text))
            result = False
        else:
            #Re-owning it, I've switched URL's again here but it seems to be working so will not change it
            url = "%s/servicesNS/%s/%s/configs/conf-macros/%s/acl" % (self.splunk_rest, owner, app, name)
            payload = { "owner": owner, "sharing" : sharing }
            logger.info("i=\"%s\" Attempting to change ownership of type=macro name=%s via URL=%s to owner=%s in app=%s with sharing=%s" % (self.stanza_name, name, url, owner, app, sharing))
            res = requests.post(url, auth=auth, headers=headers, verify=self.sslVerify, data=payload, proxies=self.proxies)
            if (res.status_code != requests.codes.ok):
                logger.error("i=\"%s\" name=%s of type=macro in app=%s with URL=%s statuscode=%s reason=%s, response=\"%s\", owner=%s sharing=%s" % (self.stanza_name, name, app, url, res.status_code, res.reason, res.text, owner, sharing))
            else:
                logger.debug("i=\"%s\" name=%s of type=macro in app=%s, ownership changed with response=\"%s\", newOwner=%s and sharing=%s" % (self.stanza_name, name, app, res.text, owner, sharing))

        return result, ""

    ###########################
    #
    # macros
    #
    ###########################
    #macro use cases are slightly different to everything else on the REST API
    #enough that this code has not been integrated into the runQuery() function
    def macros(self, app, name, scope, user, restore_as_user, admin_level):
        logger.info("i=\"%s\" user=%s, attempting to restore name=%s in app=%s of type=macro in scope=%s, restore_as_user=%s, admin_level=%s" % (self.stanza_name, user, name, app, scope, restore_as_user, admin_level))
        #servicesNS/-/-/properties/macros doesn't show private macros so using /configs/conf-macros to find all the macros
        #again with count=-1 to find all the available macros
        url = self.splunk_rest + "/servicesNS/-/" + app + "/configs/conf-macros/" + name + "?output_mode=json"
        logger.debug("i=\"%s\" Running requests.get() on url=%s with user=%s in app=%s for type=macro proxies_length=%s" % (self.stanza_name, url, self.destUsername, app, len(self.proxies)))

        #Determine scope that we will attempt to restore
        app_scope = False
        user_scope = False
        if scope == "all":
            app_scope = True
            user_scope = True
        elif scope == "app":
            app_scope = True
        elif scope == "user":
            user_scope = True
        else:
            logger.error("i=\"%s\" user=%s, while attempting to restore name=%s, found invalid scope=%s" % (self.stanza_name, user, name, scope))

        headers = {}
        auth = None
        if not self.destUsername:
            headers={'Authorization': 'Splunk %s' % self.session_key}
        else:
            auth = HTTPBasicAuth(self.destUsername, self.destPassword)

        res = requests.get(url, auth=auth, headers=headers, verify=self.sslVerify, proxies=self.proxies)
        objExists = False
        if (res.status_code == 404):
            logger.debug("i=\"%s\" URL=%s is throwing a 404, assuming new object creation" % (self.stanza_name, url))
        elif (res.status_code != requests.codes.ok):
            logger.error("i=\"%s\" type=macro in app=%s, URL=%s statuscode=%s reason=%s, response=\"%s\"" % (self.stanza_name, app, url, res.status_code, res.reason, res.text))
        else:
            #However the fact that we did not get a 404 does not mean it exists in the context we expect it to, perhaps it's global and from another app context?
            #or perhaps it's app level but we're restoring a private object...
            logger.debug("i=\"%s\" Attempting to JSON loads on (macros) %s" % (self.stanza_name, res.text))
            res_dict = json.loads(res.text)
            for entry in res_dict['entry']:
                sharing_level = entry['acl']['sharing']
                app_context = entry['acl']['app']
                if app_context == app and app_scope == True and (sharing_level == 'app' or sharing_level == 'global'):
                    objExists = True
                elif app_context == app and user_scope == True and sharing_level == "user":
                    objExists = True

        configList = []

        file_name = self.gen_file_name(name)

        foundAtAnyScope = False
        #This object is at user scope or may be at user scope
        if user_scope == True:
            userDir = self.gitTempDir + "/" + app + "/" + "user"
            #user directory exists
            if os.path.isdir(userDir):
                typeFile = userDir + "/macros"
                if self.file_per_ko:
                    if os.path.isdir(typeFile):
                        logger.debug("i=\"%s\" user=%s, name=%s, found typeFile=%s to search for files to restore in" % (self.stanza_name, user, name, typeFile))
                        file_list = self.list_dir_contents(typeFile)
                        file_name_match = []
                        found = False
                        for a_file in file_list:
                            file = os.path.basename(a_file)
                            if file_name == file:
                                owner = os.path.basename(os.path.dirname(a_file))
                                if owner == user:
                                    logger.info("i=\"%s\" user=%s, name=%s, found file=%s to restore from" % (self.stanza_name, user, name, a_file))
                                    found = True
                                    foundAtAnyScope = True
                                    file_exact_match = a_file
                                    break
                                else:
                                    logger.debug("i=\"%s\" owner=%s, user=%s, name=%s, found file=%s with non-matching owner to potentially restore from" % (self.stanza_name, owner, user, name, a_file))
                                    file_name_match.append(a_file)
                        if found == True or len(file_name_match) > 0:
                            foundAtAnyScope = True
                            #We found the configItem we need, run the restoration
                            if found:
                                logger.debug("i=\"%s\" user=%s, name=%s is found in file=%s" % (self.stanza_name, user, name, file_exact_match))
                                with open(file_exact_match, 'r') as f:
                                    configItem = json.load(f)
                                    (restore_result, message) = self.runRestoreMacro(configItem, app, name, user, restore_as_user, admin_level, objExists)
                            elif len(file_name_match) > 0:
                                for a_file in file_name_match:
                                    logger.debug("i=\"%s\" user=%s, name=%s is potentially found in file=%s" % (self.stanza_name, user, name, a_file))
                                    with open(a_file, 'r') as f:
                                        configItem = json.load(f)
                                        (restore_result, message) = self.runRestoreMacro(configItem, app, name, user, restore_as_user, admin_level, objExists)
                    else:
                        #There are no user level objects for this app, therefore the restore will not occur at this scope
                        logger.info("i=\"%s\" user directory of dir=%s does not have a sub-directory of type=macro" % (self.stanza_name, userDir))
                else:
                    #We found the file, now open it to obtain the contents
                    if os.path.isfile(typeFile):
                        logger.debug("i=\"%s\" user=%s, name=%s, found typeFile=%s to restore from" % (self.stanza_name, user, name, typeFile))
                        with open(typeFile, 'r') as f:
                            configList = json.load(f)
                            found = False
                            for configItem in configList:
                                #We found the relevant item, now restore it
                                if configItem['name'] == name:
                                    logger.debug("i=\"%s\" user=%s, name=%s is found, dictionary=\"%s\"" % (self.stanza_name, user, name, configItem))
                                    (restore_result, message) = self.runRestoreMacro(configItem, app, name, user, restore_as_user, admin_level, objExists)
                                    found = True
                                    foundAtAnyScope = True
                            #We never found the relevant item
                            if found == False:
                                logger.info("i=\"%s\" user=%s, name=%s not found at scope=user in typeFile=%s" % (self.stanza_name, user, name, typeFile))
                    #The config file did not exist
                    else:
                        logger.info("i=\"%s\" user=%s, name=%s, did not find a typeFile=%s to restore from" % (self.stanza_name, user, name, typeFile))
            else:
                #There are no user level objects for this app, therefore the restore will not occur at this scope
                logger.info("i=\"%s\" user directory of dir=%s does not exist" % (self.stanza_name, userDir))

        #The object is either app or globally scoped
        if app_scope == True:
            appDir = self.gitTempDir + "/" + app + "/" + "app"
            #app directory exists
            if os.path.isdir(appDir):
                typeFile = appDir + "/macros"

                if self.file_per_ko:
                    if os.path.isdir(typeFile):
                        logger.debug("i=\"%s\" user=%s, name=%s, found typeFile=%s to search for files to restore in" % (self.stanza_name, user, name, typeFile))
                        file_list = self.list_dir_contents(typeFile)
                        found = False
                        for a_file in file_list:
                            file = os.path.basename(a_file)
                            if file_name == file:
                                logger.info("i=\"%s\" user=%s, name=%s, found file=%s to restore from" % (self.stanza_name, user, name, a_file))
                                found = True
                                foundAtAnyScope = True
                                file_exact_match = a_file
                        if found == True:
                            #We found the configItem we need, run the restoration
                            if found:
                                logger.debug("i=\"%s\" user=%s, name=%s is found in file=%s" % (self.stanza_name, user, name, file_exact_match))
                                with open(file_exact_match, 'r') as f:
                                    configItem = json.load(f)
                                    (restore_result, message) = self.runRestoreMacro(configItem, app, name, user, restore_as_user, admin_level, objExists)
                    else:
                        #There are no app level objects for this app of this type, therefore the restore will not occur at this scope
                        logger.info("i=\"%s\" app directory of dir=%s does not have a sub-directory of type=macro" % (self.stanza_name, appDir))
                else:
                    #We found the file, open it and load the config
                    if os.path.isfile(typeFile):
                        logger.debug("i=\"%s\" user=%s, name=%s, found typeFile=%s to restore from" % (self.stanza_name, user, name, typeFile))
                        with open(typeFile, 'r') as f:
                            configList = json.load(f)
                            found = False
                            #We found the item, now restore it
                            for configItem in configList:
                                if configItem['name'] == name:
                                    logger.debug("i=\"%s\" user=%s, name=%s is found, dictionary is %s" % (self.stanza_name, user, name, configItem))
                                    (restore_result, message) = self.runRestoreMacro(configItem, app, name, user, restore_as_user, admin_level, objExists)
                                    found = True
                                    foundAtAnyScope = True
                            #We never found the item
                            if found == False:
                                logger.info("i=\"%s\" user=%s, name=%s not found at scope=app in typeFile=%s" % (self.stanza_name, user, name, typeFile))
                    #We never found the file to restore from
                    else:
                        logger.info("i=\"%s\" user=%s, name=%s, did not find a typeFile=%s to restore from" % (self.stanza_name, user, name, typeFile))
            else:
                #There are no app level objects for this app, therefore the restore will not occur at this scope
                logger.info("i=\"%s\" app directory of dir=%s does not exist" % (self.stanza_name, appDir))

            globalDir = self.gitTempDir + "/" + app + "/" + "global"
            #global directory exists
            if os.path.isdir(globalDir):
                typeFile = globalDir + "/macros"
                if self.file_per_ko:
                    if os.path.isdir(typeFile):
                        logger.debug("i=\"%s\" user=%s, name=%s, found typeFile=%s to search for files to restore in" % (self.stanza_name, user, name, typeFile))
                        file_list = self.list_dir_contents(typeFile)
                        found = False
                        for a_file in file_list:
                            file = os.path.basename(a_file)
                            if file_name == file:
                                logger.info("i=\"%s\" user=%s, name=%s, found file=%s to restore from" % (self.stanza_name, user, name, a_file))
                                found = True
                                foundAtAnyScope = True
                                file_exact_match = a_file
                        if found == True:
                            #We found the configItem we need, run the restoration
                            if found:
                                logger.debug("i=\"%s\" user=%s, name=%s is found in file=%s" % (self.stanza_name, user, name, file_exact_match))
                                with open(file_exact_match, 'r') as f:
                                    configItem = json.load(f)
                                    (restore_result, message) = self.runRestoreMacro(configItem, app, name, user, restore_as_user, admin_level, objExists)
                    else:
                        #There are no app level objects for this app of this type, therefore the restore will not occur at this scope
                        logger.info("i=\"%s\" app directory of dir=%s does not have a sub-directory of type=macro" % (self.stanza_name, appDir))
                else:
                    #We found the file, attempt to load the config
                    if os.path.isfile(typeFile):
                        logger.debug("i=\"%s\" user=%s, name=%s, found typeFile=%s to restore from" % (self.stanza_name, user, name, typeFile))
                        with open(typeFile, 'r') as f:
                            configList = json.load(f)
                            found = False
                            for configItem in configList:
                                #We found the item,  now restore it
                                if configItem['name'] == name:
                                    logger.debug("i=\"%s\" user=%s, name=%s is found, dictionary is %s" % (self.stanza_name, user, name, configItem))
                                    (restore_result, message) = self.runRestoreMacro(configItem, app, name, user, restore_as_user, admin_level, objExists)
                                    found = True
                                    foundAtAnyScope = True
                            #We never found the item
                            if found == False:
                                logger.info("i=\"%s\" user=%s, name=%s not found at scope=global in typeFile=%s" % (self.stanza_name, user, name, typeFile))
                    #We did not find the file to restore from
                    else:
                        logger.info("i=\"%s\" user=%s, name=%s, did not find a typeFile=%s to restore from" % (self.stanza_name, user, name, typeFile))
            else:
                #There are no global level objects for this app, therefore the restore will not occur at this scope
                logger.info("i=\"%s\" global directory of dir=%s does not exist" % (self.stanza_name, globalDir))

        if foundAtAnyScope == True and restore_result!=False:
            logger.info("i=\"%s\" user=%s restore has run successfully for name=%s, type=macro, restore_as_user=%s, admin_level=%s" % (self.stanza_name, user, name, restore_as_user, admin_level))
            return True, message
        elif restore_result == False and foundAtAnyScope == True:
            logger.warn("i=\"%s\" user=%s attempted to restore name=%s, type=macro, restore_as_user=%s, admin_level=%s the object was found, but the restore was unsuccessful" % (self.stanza_name, user, name, restore_as_user, admin_level))
            return False, message
        else:
            logger.warn("i=\"%s\" user=%s attempted to restore name=%s, type=macro, restore_as_user=%s, admin_level=%s however the object was not found, the restore was unsuccessful. Perhaps check the restore date, scope & capitalisation before trying again?" % (self.stanza_name, user, name, restore_as_user, admin_level))
            return False, message

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
    def dashboards(self, app, name, scope, username, restore_as_user, admin_level):
        return self.runQueries(app, "/data/ui/views", "dashboards", name, scope, username, restore_as_user, admin_level)

    ###########################
    #
    # Saved Searches
    #
    ###########################
    def savedsearches(self, app, name, scope, username, restore_as_user, admin_level):
        return self.runQueries(app, "/saved/searches", "savedsearches",name, scope, username, restore_as_user, admin_level)

    ###########################
    #
    # field definitions
    #
    ###########################
    def calcfields(self, app, name, scope, username, restore_as_user, admin_level):
        return self.runQueries(app, "/data/props/calcfields", "calcfields", name, scope, username, restore_as_user, admin_level)

    def fieldaliases(self, app, name, scope, username, restore_as_user, admin_level):
        return self.runQueries(app, "/data/props/fieldaliases", "fieldaliases", name, scope, username, restore_as_user, admin_level)

    def fieldextractions(self, app, name, scope, username, restore_as_user, admin_level):
        return self.runQueries(app, "/data/props/extractions", "fieldextractions", name, scope, username, restore_as_user, admin_level)

    def fieldtransformations(self, app, name, scope, username, restore_as_user, admin_level):
        return self.runQueries(app, "/data/transforms/extractions", "fieldtransformations", name, scope, username, restore_as_user, admin_level)

    def workflowactions(self, app, name, scope, username, restore_as_user, admin_level):
        return self.runQueries(app, "/data/ui/workflow-actions", "workflow-actions", name, scope, username, restore_as_user, admin_level)

    def sourcetyperenaming(self, app, name, scope, username, restore_as_user, admin_level):
        return self.runQueries(app, "/data/props/sourcetype-rename", "sourcetype-rename", name, scope, username, restore_as_user, admin_level)

    ###########################
    #
    # tags
    #
    ##########################
    def tags(self, app, name, scope, username, restore_as_user, admin_level):
        return self.runQueries(app, "/configs/conf-tags", "tags", name, scope, username, restore_as_user, admin_level)

    ###########################
    #
    # eventtypes
    #
    ##########################
    def eventtypes(self, app, name, scope, username, restore_as_user, admin_level):
        return self.runQueries(app, "/saved/eventtypes", "eventtypes", name, scope, username, restore_as_user, admin_level)

    ###########################
    #
    # navMenus
    #
    ##########################
    def navMenu(self, app, name, scope, username, restore_as_user, admin_level):
        return self.runQueries(app, "/data/ui/nav", "navMenu", name, scope, username, restore_as_user, admin_level)

    ###########################
    #
    # data models
    #
    ##########################
    def datamodels(self, app, name, scope, username, restore_as_user, admin_level):
        return self.runQueries(app, "/datamodel/model", "datamodels", name, scope, username, restore_as_user, admin_level)

    ###########################
    #
    # collections
    #
    ##########################
    def collections(self, app, name, scope, username, restore_as_user, admin_level):
        return self.runQueries(app, "/storage/collections/config", "collections_kvstore", name, scope, username, restore_as_user, admin_level)

    ###########################
    #
    # viewstates
    #
    ##########################
    def viewstates(self, app, name, scope, username, restore_as_user, admin_level):
        return self.runQueries(app, "/configs/conf-viewstates", "viewstates", name, scope, username, restore_as_user, admin_level)

    ###########################
    #
    # time labels (conf-times)
    #
    ##########################
    def times(self, app, name, scope, username, restore_as_user, admin_level):
        return self.runQueries(app, "/configs/conf-times", "times_conf-times", name, scope, username, restore_as_user, admin_level)

    ###########################
    #
    # panels
    #
    ##########################
    def panels(self, app, name, scope, username, restore_as_user, admin_level):
        return self.runQueries(app, "/data/ui/panels", "pre-built_dashboard_panels", name, scope, username, restore_as_user, admin_level)

    ###########################
    #
    # lookups (definition/automatic)
    #
    ##########################
    def lookupDefinitions(self, app, name, scope, username, restore_as_user, admin_level):
        return self.runQueries(app, "/data/transforms/lookups", "lookup_definition", name, scope, username, restore_as_user, admin_level)

    def automaticLookups(self, app, name, scope, username, restore_as_user, admin_level):
        return self.runQueries(app, "/data/props/lookups", "automatic_lookups", name, scope, username, restore_as_user, admin_level)

    ###########################
    #
    # Helper/utility functions
    #
    ##########################
    #helper function as per https://stackoverflow.com/questions/31433989/return-copy-of-dictionary-excluding-specified-keys
    def without_keys(self, d, keys):
        return {x: d[x] for x in d if x not in keys}

    #Run a Splunk query via the search/v2/jobs endpoint
    def runSearchJob(self, query, earliest_time="-1h"):
        url = self.splunk_rest + "/servicesNS/-/%s/search/v2/jobs" % (self.appName)
        logger.debug("i=\"%s\" Running requests.post() on url=%s with user=%s query=\"%s\" proxies_length=%s" % (self.stanza_name, url, self.destUsername, query, len(self.proxies)))
        data = { "search" : query, "output_mode" : "json", "exec_mode" : "oneshot", "earliest_time" : earliest_time }

        #no destUsername, use the session_key method
        headers = {}
        auth = None
        if not self.destUsername:
            headers = {'Authorization': 'Splunk %s' % self.session_key }
        else:
            auth = HTTPBasicAuth(self.destUsername, self.destPassword)

        res = requests.post(url, auth=auth, headers=headers, verify=self.sslVerify, data=data, proxies=self.proxies)
        if (res.status_code != requests.codes.ok):
            logger.error("i=\"%s\" URL=%s statuscode=%s reason=%s, response=\"%s\"" % (self.stanza_name, url, res.status_code, res.reason, res.text))
        res = json.loads(res.text)

        #Log return messages from Splunk, often these advise of an issue but not always...
        if len(res["messages"]) > 0:
            firstMessage = res["messages"][0]
            if 'type' in firstMessage and firstMessage['type'] == "INFO":
                #This is a harmless info message ,most other messages are likely an issue
                logger.info("i=\"%s\" messages from query=\"%s\" were messages=\"%s\"" % (self.stanza_name, query, res["messages"]))
            else:
                logger.warn("i=\"%s\" messages from query=\"%s\" were messages=\"%s\"" % (self.stanza_name, query, res["messages"]))
        return res

    def clone_git_dir(self):
        if not os.path.isdir(self.gitRootDir):
            #make the directory and clone under here
            os.mkdir(self.gitRootDir)

        #Clone the remote git repo
        if self.windows:
            clone_str = "cd /d {0} & {1} clone {2}".format(self.gitRootDir, self.git_command, self.gitRepoURL)
            if len(self.git_proxies) > 0 and self.gitRepoHTTP:
                clone_str = "set HTTPS_PROXY=" + self.git_proxies["https"] + " & " + clone_str
        else:
            clone_str = "cd {0}; {1} clone {2} 2>&1".format(self.gitRootDir, self.git_command, self.gitRepoURL)
            if len(self.git_proxies) > 0 and self.gitRepoHTTP:
                clone_str = "export HTTPS_PROXY=" + self.git_proxies["https"] + " ; " + clone_str

        (output, stderrout, res) = runOSProcess(clone_str, logger, timeout=300)
        return (output, stderrout, res)

    def git_pull(self, branch_or_tag, pull=False):
        #Do a git pull to ensure we are up-to-date
        if self.windows:
            pull_str = "cd /d %s & %s checkout %s & " % (self.gitTempDir, self.git_command, branch_or_tag)
            if pull:
                pull_str = pull_str + self.git_command + " pull"
            if len(self.git_proxies) > 0 and self.gitRepoHTTP:
                pull_str = "set HTTPS_PROXY=" + self.git_proxies["https"] + " & " + pull_str
            (output, stderrout, res) = runOSProcess(pull_str, logger, timeout=300, shell=True)
        else:
            pull_str = "cd %s; %s checkout %s " % (self.gitTempDir, self.git_command, branch_or_tag)
            if pull:
                pull_str = pull_str + ";" + self.git_command + " pull"
            if len(self.git_proxies) > 0 and self.gitRepoHTTP:
                pull_str = "export HTTPS_PROXY=" + self.git_proxies["https"] + " ; " + pull_str
            (output, stderrout, res) = runOSProcess(pull_str, logger, timeout=300, shell=True)

        return (output, stderrout, res)

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
            debugMode = config['debugMode']
            if isinstance(debugMode, bool) and debugMode:
                logging.getLogger().setLevel(logging.DEBUG)
            elif isinstance(debugMode, bool) and not debugMode:
                pass
            elif debugMode.lower() == "true" or debugMode.lower() == "t" or debugMode == "1":
                logging.getLogger().setLevel(logging.DEBUG)

        self.stanza_name = config["name"].replace("splunkversioncontrol_restore://", "")
        useLocalAuth = False
        if 'useLocalAuth' in config:
            useLocalAuth = config['useLocalAuth']
            if isinstance(useLocalAuth, bool) and useLocalAuth:
                useLocalAuth = True
            elif isinstance(useLocalAuth, bool) and not useLocalAuth:
                useLocalAuth = False
            elif useLocalAuth.lower() == "true" or useLocalAuth.lower()=="t" or useLocalAuth == "1":
                useLocalAuth = True
            else:
                useLocalAuth = False

        #If we're not using the useLocalAuth we must have a username/password to work with
        if useLocalAuth == False and ('destUsername' not in config or 'destPassword' not in config):
            logger.fatal("i=\"%s\" useLocalAuth is not set to true and destUsername/destPassword not set, exiting with failure" % (self.stanza_name))
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

        self.session_key = config['session_key']

        if 'sslVerify' in config:
            sslVerify = config['sslVerify']
            if isinstance(sslVerify, bool) and sslVerify:
                self.sslVerify = True
                logger.debug('sslverify set to boolean True from: %s' % (sslVerify))
            elif isinstance(sslVerify, bool) and not sslVerify:
                self.sslVerify = False
                logger.debug('sslverify set to boolean True from: %s' % (sslVerify))
            elif sslVerify.lower() == 'true' or sslVerify == "1":
                self.sslVerify = True
                logger.debug('sslverify set to boolean True from: ' + sslVerify)
            elif sslVerify.lower() == 'false' or sslVerify == "0":
                self.sslVerify = False
                logger.debug('sslverify set to boolean False from: ' + sslVerify)
            else:
                self.sslVerify = sslVerify
                logger.debug('sslverify set to: %s' % (sslVerify))

        self.git_password = False
        # a flag for a http/https vs SSH based git repo
        if self.gitRepoURL.find("http") == 0:
            self.gitRepoHTTP = True
            if self.gitRepoURL.find("password:") != -1:
                self.gitRepoURL_logsafe = self.gitRepoURL
                start = self.gitRepoURL.find("password:") + 9
                end = self.gitRepoURL.find("@")
                logger.debug("Attempting to replace self.gitRepoURL=%s by subsituting=%s with a password" % (self.gitRepoURL, self.gitRepoURL[start:end]))
                self.git_password = get_password(self.gitRepoURL[start:end], self.session_key, logger, self.sslVerify)
                self.gitRepoURL = self.gitRepoURL[0:start-9] + self.git_password + self.gitRepoURL[end:]
            else:
                self.gitRepoURL_logsafe = self.gitRepoURL
        else:
            self.gitRepoHTTP = False
            self.gitRepoURL_logsafe = self.gitRepoURL

        #From server
        self.splunk_rest = config['destURL']
        excludedList = [ "destPassword", "session_key" ]
        cleanArgs = self.without_keys(config, excludedList)
        logger.info("i=\"%s\" Splunk Version Control Restore run with arguments=\"%s\"" % (self.stanza_name, cleanArgs))

        if not useLocalAuth and self.destPassword.find("password:") == 0:
            self.destPassword = get_password(self.destPassword[9:], self.session_key, logger, self.sslVerify)

        knownAppList = []
        self.gitTempDir = config['gitTempDir']
        self.gitRootDir = config['gitTempDir']

        if 'git_command' in config:
            self.git_command = config['git_command'].strip()
            self.git_command = self.git_command.replace("\\","/")
            logger.debug("Overriding git command to %s" % (self.git_command))
        else:
            self.git_command = "git"

        if 'disable_git_ssl_verify' in config:
            disable_git_ssl_verify = config['disable_git_ssl_verify']
            if isinstance(disable_git_ssl_verify, bool) and disable_git_ssl_verify:
                disable_git_ssl_verify_bool = True
            elif isinstance(disable_git_ssl_verify, bool) and not disable_git_ssl_verify:
                disable_git_ssl_verify_bool = False
            elif disable_git_ssl_verify.lower() == "true" or disable_git_ssl_verify.lower()=="t" or disable_git_ssl_verify == "1":
                disable_git_ssl_verify_bool = True
            else:
                disable_git_ssl_verify_bool = False

            if disable_git_ssl_verify_bool:
                self.git_command = "GIT_SSL_NO_VERIFY=true " + self.git_command
                logger.debug('git_command now has GIT_SSL_NO_VERIFY=true because disable_git_ssl_verify: %s' % (disable_git_ssl_verify))

        if 'ssh_command' in config:
            self.ssh_command = config['ssh_command'].strip()
            self.ssh_command = self.ssh_command.replace("\\","/")
            logger.debug("Overriding ssh command to %s" % (self.ssh_command))
        else:
            self.ssh_command = "ssh"

        if 'git_branch' in config:
            self.git_branch = config['git_branch'].strip()
            logger.debug("Overriding git branch to %s" % (self.git_branch))
        else:
            self.git_branch = "master"

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
                temp_password = get_password(proxies['https'][start:end], self.session_key, logger, self.sslVerify)
                proxies['https'] = proxies['https'][0:start-9] + temp_password + proxies['https'][end:]

        self.proxies = proxies

        git_proxies = {}
        if 'git_proxy' in config:
            git_proxies['https'] = config['git_proxy']
            if git_proxies['https'].find("password:") != -1:
                start = git_proxies['https'].find("password:") + 9
                end = git_proxies['https'].find("@")
                logger.debug("Attempting to replace git_proxy=%s by subsituting=%s with a password" % (git_proxies['https'], git_proxies['https'][start:end]))
                temp_password = get_password(git_proxies['https'][start:end], self.session_key, logger, self.sslVerify)
                git_proxies['https'] = git_proxies['https'][0:start-9] + temp_password + git_proxies['https'][end:]

        self.git_proxies = git_proxies

        self.file_per_ko = False
        if 'file_per_ko' in config:
            file_per_ko = config['file_per_ko']
            if isinstance(file_per_ko, bool) and file_per_ko:
                self.file_per_ko = True
                logger.debug('file_per_ko set to boolean True from: %s' % (file_per_ko))
            elif isinstance(file_per_ko, bool) and not file_per_ko:
                self.file_per_ko = False
                logger.debug('file_per_ko set to boolean False from: %s' % (file_per_ko))
            elif file_per_ko.lower() == 'true' or file_per_ko == "1":
                self.file_per_ko = True
                logger.debug('file_per_ko set to boolean True from: %s' % (file_per_ko))
            elif file_per_ko.lower() == 'false' or file_per_ko == "0":
                logger.debug('file_per_ko set to boolean False from: %s' % (file_per_ko))
            else:
                logger.warn('i="%s" file_per_ko set to unknown value, should be true or false, defaulting to false value="%s"') % (self.stanza_name, config['file_per_ko'])

        self.show_passwords = False
        if 'show_passwords' in config:
            show_passwords = config['show_passwords']
            if isinstance(show_passwords, bool) and show_passwords:
                self.show_passwords = True
            elif isinstance(show_passwords, bool) and not show_passwords:
                pass
            elif show_passwords.lower() == 'true' or show_passwords == "1":
                self.show_passwords = True
                logger.debug('i="%s" show_passwords is now true due to show_passwords: %s' % (self.stanza_name, config['show_passwords']))

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

            if not self.gitRepoHTTP:
                #Initially we must trust our remote repo URL
                (output, stderrout, res) = runOSProcess(self.ssh_command + " -n -o \"BatchMode yes\" -o StrictHostKeyChecking=no " + self.gitRepoURL[:self.gitRepoURL.find(":")], logger)
                if res == False:
                    if not self.show_passwords and self.git_password:
                        output = output.replace(self.git_password, "password_removed")
                        stderrout = stderrout.replace(self.git_password, "password_removed")
                    logger.warn("i=\"%s\" Unexpected failure while attempting to trust the remote git repo?! stdout '%s' stderr '%s'" % (self.stanza_name, output, stderrout))

            #Clone the remote git repo
            (output, stderrout, res) = self.clone_git_dir()
            if res == False:
                if not self.show_passwords and self.git_password:
                    output = output.replace(self.git_password, "password_removed")
                    stderrout = stderrout.replace(self.git_password, "password_removed")
                logger.fatal("i=\"%s\" git clone failed for some reason...on url=%s stdout of '%s' with stderrout of '%s'" % (self.stanza_name, self.gitRepoURL_logsafe, output, stderrout))
                sys.exit(1)
            else:
                logger.debug("i=\"%s\" result from git command: %s, output '%s' with stderroutput of '%s'" % (self.stanza_name, res, output, stderrout))
                logger.info("i=\"%s\" Successfully cloned the git URL=%s into directory dir=%s" % (self.stanza_name, self.gitRepoURL_logsafe, self.gitTempDir))
                if not ".git" in os.listdir(self.gitTempDir):
                    #include the subdirectory which is the git repo
                    self.gitTempDir = self.gitTempDir + "/" + os.listdir(self.gitTempDir)[0]
                    logger.debug("gitTempDir=%s" % (self.gitTempDir))

            if stderrout.find("error:") != -1 or stderrout.find("fatal:") != -1 or stderrout.find("timeout after") != -1:
                if not self.show_passwords and self.git_password:
                    stderrout = stderrout.replace(self.git_password, "password_removed")
                logger.warn("i=\"%s\" error/fatal messages in git stderroutput please review. stderrout=\"%s\"" % (self.stanza_name, stderrout))
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
            logger.info("i=\"%s\" No restore required at this point in time" % (self.stanza_name))
        else:
            #Do a git pull to ensure we are up-to-date
            (output, stderrout, res) = self.git_pull(self.git_branch, pull=True)
            if res == False:
                if not self.show_passwords and self.git_password:
                    output = output.replace(self.git_password, "password_removed")
                    stderrout = stderrout.replace(self.git_password, "password_removed")
                logger.warn("i=\"%s\" git pull failed for some reason...on url=%s stdout of '%s' with stderrout of '%s'. Wiping the git directory to re-clone" % (self.stanza_name, self.gitRepoURL_logsafe, output, stderrout))
                shutil.rmtree(self.gitTempDir)
                #Clone the remote git repo
                (output, stderrout, res) = self.clone_git_dir()
                if res == False:
                    if not self.show_passwords and self.git_password:
                        output = output.replace(self.git_password, "password_removed")
                        stderrout = stderrout.replace(self.git_password, "password_removed")
                    logger.fatal("i=\"%s\" git clone failed for some reason...on url=%s stdout of '%s' with stderrout of '%s'" % (self.stanza_name, self.gitRepoURL_logsafe, output, stderrout))
                    sys.exit(1)
                else:
                    logger.debug("i=\"%s\" result from git command: %s, output '%s' with stderroutput of '%s'" % (self.stanza_name, res, output, stderrout))
                    logger.info("i=\"%s\" Successfully cloned the git URL=%s into directory dir=%s" % (self.stanza_name, self.gitRepoURL_logsafe, self.gitRootDir))
            else:
                logger.info("i=\"%s\" Successfully ran the git pull for URL=%s from directory dir=%s" % (self.stanza_name, self.gitRepoURL_logsafe, self.gitRootDir))

            if stderrout.find("error:") != -1 or stderrout.find("fatal:") != -1 or stderrout.find("timeout after") != -1:
                if not self.show_passwords and self.git_password:
                    stderrout = stderrout.replace(self.git_password, "password_removed")             
                logger.warn("i=\"%s\" error/fatal messages in git stderroutput please review. stderrout=\"%s\"" % (self.stanza_name, stderrout))
                gitFailure = True
                if stderrout.find("timeout after") != -1:
                    return (False, "git command timed out")

            logger.debug("i=\"%s\" The restore list is %s" % (self.stanza_name, resList))

            #Attempt to determine all users involved in this restore so we can run a single query and determine if they are admins or not
            userList = []
            for aRes in resList:
                user = aRes['user']
                userList.append(user)
            #obtain a list of unique user id's
            userList = list(set(userList))
            usernameFilter = None

            for user in userList:
                usernameFilter = user + ","

            #Query Splunk and determine if the mentioned users have the required admin role, if not they can only restore the objects they own
            res = self.runSearchJob("| savedsearch \"SplunkVersionControl CheckAdmin\" usernameFilter=\"%s\"" % (usernameFilter))
            userResList = []
            if 'results' not in res:
                logger.warn("i=\"%s\" Unable to run 'SplunkVersionControl CheckAdmin' for some reason with usernameFilter=%s" % (self.stanza_name, usernameFilter))
            else:
                userResList = res["results"]

            #Create a list of admins
            adminList = []
            for userRes in userResList:
                username = userRes["username"]
                logger.debug("i=\"%s\" Adding user=%s as an admin username" % (self.stanza_name, username))
                adminList.append(username)

            if not restlist_override:
                # Run yet another query, this one provides a list of times/usernames at which valid entries were added to the lookup file
                # if the addition to the lookup file was not done via the required report then the restore is not done (as anyone can add a new role
                # and put the username as an admin user!)
                res = self.runSearchJob("| savedsearch \"SplunkVersionControl Audit Query\"", earliest_time=auditLogsLookupBackTime)
                auditEntries = []
                if 'results' not in res:
                    logger.warn("i=\"%s\" Unable to run 'SplunkVersionControl Audit Query' for some reason with earliest_time=%s" % (self.stanza_name, auditLogsLookupBackTime))
                else:
                    auditEntries = res["results"]
                    logger.debug("i=\"%s\" Audit Entries are: '%s'" % (self.stanza_name, auditEntries))

            #Cycle through each result from the earlier lookup and run the required restoration
            for aRes in resList:
                if not all (entry in aRes for entry in ('time', 'app', 'name', 'restoreAsUser', 'tag', 'type', 'user', 'scope')):
                    logger.warn("i=\"%s\" this row is invalid, skipping this row of the results, res=\"%s\"" % (self.stanza_name, aRes))
                    continue

                time = aRes['time']
                app = aRes['app']
                name = aRes['name']
                restore_as_user = aRes['restoreAsUser']
                tag = aRes['tag']
                obj_type = aRes['type']
                user = aRes['user']
                scope = aRes['scope']

                logger.info("i=\"%s\" user=%s has requested the object with name=%s of type=%s to be restored from tag=%s and scope=%s, restore_as_user=%s, this was requested at time=%s in app context of app=%s" % (self.stanza_name, user, name, obj_type, tag, scope, restore_as_user, time, app))

                if not restlist_override:
                    #If we have an entry in the lookup file it should be listed in the audit entries file
                    found = False
                    for entry in auditEntries:
                        #The audit logs are accurate to milliseconds, the lookup *is not* so sometimes it's off by about a second
                        timeEntry = entry['time']
                        # when testing SplunkCloud on 2022-09-22 the logs appeared approx 10 seconds later..., leaving +30 for some flexibility here
                        timeEntryEnd = int(timeEntry) + 30
                        timeEntryStart = int(timeEntry) - 1
                        if timeEntry == time or (int(timeEntry) > timeEntryStart and int(timeEntry) < timeEntryEnd):
                            found = True
                            auditUser = entry['user']
                            if user != auditUser:
                                logger.warn("i=\"%s\" user=%s found time entry of time=%s with auditUser=%s, this does not match the expected username (%s), rejecting this entry for name=%s of type=%s in app=%s with restore_as_user=%s" % (self.stanza_name, user, time, auditUser, user, name, obj_type, app, restore_as_user))
                                found = False
                            else:
                                logger.debug("i=\"%s\" user=%s, found time entry of time=%s, considering this a valid entry and proceeding to restore" % (self.stanza_name, user, time))

                    if found == False:
                        logger.warn("i=\"%s\" user=%s, unable to find a time entry of time=%s matching the auditEntries list of %s, skipping this entry" % (self.stanza_name, user, time, auditEntries))
                        continue
                #else we were provided with the override list and the username/audit logs were already checked

                admin_level = False

                if user in adminList:
                    logger.debug("i=\"%s\" user=%s is an admin and has requested object name=%s of type=%s in app=%s to be restored with user=%s and time=%s" % (self.stanza_name, user, name, obj_type, app, restore_as_user, time))
                    admin_level = True

                #Only admins can restore objects as another user
                if restore_as_user != "" and restore_as_user != user and admin_level == False:
                    logger.error("i=\"%s\" user=%s is not an admin and has attempted to restore as a different user, requested user=%s, object=%s of type=%s in app=%s to be restored with restore_as_user=%s time=%s, rejected" % (self.stanza_name, user, restore_as_user, name, obj_type, app, restore_as_user, time))
                    continue

                #Do a git pull to ensure we are up-to-date
                (output, stderrout, res) = self.git_pull(tag)
                if res == False:
                    if not self.show_passwords and self.git_password:
                        output = output.replace(self.git_password, "password_removed")
                        stderrout = stderrout.replace(self.git_password, "password_removed")
                    logger.error("i=\"%s\" user=%s, object name=%s, type=%s, time=%s, git checkout of tag=%s failed in directory dir=%s stdout of '%s' with stderrout of '%s'" % (self.stanza_name, user, name, obj_type, time, tag, self.gitTempDir, output, stderrout))
                else:
                    logger.info("i=\"%s\" Successfully ran the git checkout for URL=%s from directory dir=%s" % (self.stanza_name, self.gitRepoURL_logsafe, self.gitTempDir))

                if stderrout.find("error:") != -1 or stderrout.find("fatal:") != -1 or stderrout.find("timeout after") != -1:
                    if not self.show_passwords and self.git_password:
                        stderrout = stderrout.replace(self.git_password, "password_removed")
                    logger.warn("i=\"%s\" error/fatal messages in git stderroutput please review. stderrout=\"%s\"" % (self.stanza_name, stderrout))
                    gitFailure = True
                    if stderrout.find("timeout after") != -1:
                        return (False, "git command timed out")

                knownAppList = []
                if os.path.isdir(self.gitTempDir):
                    #include the subdirectory which is the git repo
                    knownAppList = os.listdir(self.gitTempDir)
                    logger.debug("i=\"%s\" Known app list is %s" % (self.stanza_name, knownAppList))

                #If the app is not known, the restore stops here as we have nothing to restore from!
                if app not in knownAppList:
                    logger.error("i=\"%s\" user=%s requested a restore from app=%s but this is not in the knownAppList therefore restore cannot occur, object=%s of type=%s to be restored with user=%s and time=%s" % (self.stanza_name, user, app, name, obj_type, restore_as_user, time))
                    message = f"i=\"{self.stanza_name}\" user={user} requested a restore from app={app} but this is not in the knownAppList therefore restore cannot occur, object={name} of type={obj_type} to be restored with user={restore_as_user} and time={time}"
                    continue

                #Deal with the different types of restores that might be required, we only do one row at a time...
                if obj_type == "dashboard":
                    (result, message) = self.dashboards(app, name, scope, user, restore_as_user, admin_level)
                elif obj_type == "savedsearch":
                    (result, message) = self.savedsearches(app, name, scope, user, restore_as_user, admin_level)
                elif obj_type == "macro":
                    (result, message) = self.macros(app, name, scope, user, restore_as_user, admin_level)
                elif obj_type == "fieldalias":
                    (result, message) = self.fieldaliases(app, name, scope, user, restore_as_user, admin_level)
                elif obj_type == "fieldextraction":
                    (result, message) = self.fieldextractions(app, name, scope, user, restore_as_user, admin_level)
                elif obj_type == "fieldtransformation":
                    (result, message) = self.fieldtransformations(app, name, scope, user, restore_as_user, admin_level)
                elif obj_type == "navmenu":
                    (result, message) = self.navMenu(app, name, scope, user, restore_as_user, admin_level)
                elif obj_type == "datamodel":
                    (result, message) = self.datamodels(app, name, scope, user, restore_as_user, admin_level)
                elif obj_type == "panels":
                    (result, message) = self.panels(app, name, scope, user, restore_as_user, admin_level)
                elif obj_type == "calcfields":
                    (result, message) = self.calcfields(app, name, scope, user, restore_as_user, admin_level)
                elif obj_type == "workflowaction":
                    (result, message) = self.workflowactions(app, name, scope, user, restore_as_user, admin_level)
                elif obj_type == "sourcetyperenaming":
                    (result, message) = self.sourcetyperenaming(app, name, scope, user, restore_as_user, admin_level)
                elif obj_type == "tags":
                    (result, message) = self.tags(app, name, scope, user, restore_as_user, admin_level)
                elif obj_type == "eventtypes":
                    (result, message) = self.eventtypes(app, name, scope, user, restore_as_user, admin_level)
                elif obj_type == "lookupdef":
                    (result, message) = self.lookupDefinitions(app, name, scope, user, restore_as_user, admin_level)
                elif obj_type == "automaticlookup":
                    (result, message) = self.automaticLookups(app, name, scope, user, restore_as_user, admin_level)
                elif obj_type == "collection":
                    (result, message) = self.collections(app, name, scope, user, restore_as_user, admin_level)
                elif obj_type == "viewstate":
                    (result, message) = self.viewstates(app, name, scope, user, restore_as_user, admin_level)
                elif obj_type == "times":
                    (result, message) = self.times(app, name, scope, user, restore_as_user, admin_level)
                else:
                    logger.error("i=\"%s\" user=%s, unknown type, no restore will occur for object=%s of type=%s in app=%s to be restored with restore_as_user=%s and time=%s" % (self.stanza_name, user, name, obj_type, app, restore_as_user, time))
                    message = "unknown knowledge object with type=%s" % obj_type

        if not restlist_override:
            #Wipe the lookup file so we do not attempt to restore these entries again
            if len(resList) != 0:
                if not gitFailure:
                    res = self.runSearchJob("| makeresults | fields - _time | outputlookup %s" % (restoreList))
                    logger.info("i=\"%s\" Cleared the lookup file to ensure we do not attempt to restore the same entries again" % (self.stanza_name))
                else:
                    logger.error("i=\"%s\" git failure occurred during runtime, not wiping the lookup table. This failure  may require investigation, please refer to the WARNING messages in the logs" % (self.stanza_name))
        if gitFailure:
            logger.warn("i=\"%s\" wiping the git directory, dir=%s to allow re-cloning on next run of the script" % (self.stanza_name, self.gitTempDir))
            shutil.rmtree(self.gitTempDir)

        logger.info("i=\"%s\" Done" % (self.stanza_name))
        if len(resList) == 0:
            message = "Empty restore list?"

        return (result, message)
