from __future__ import print_function
import requests
import xml.etree.ElementTree as ET
import logging
from logging.config import dictConfig
import os
import sys
import xml.dom.minidom, xml.sax.saxutils
from splunkversioncontrol_backup_class import SplunkVersionControlBackup
from splunkversioncontrol_utility import runOSProcess, get_password

"""

 Store Knowledge Objects
   Attempt to run against the Splunk REST API to obtain various knowledge objects, then persist the knowledge object information required
   to restore the knowledge object if it was deleted/changed to the filesystem
 
"""

#Define the XML scheme for the inputs page
SCHEME = """<scheme>
    <title>Splunk Version Control Backup</title>
    <description>Store Splunk knowledge objects in the git version control system (backup only)</description>
    <use_external_validation>true</use_external_validation>
    <streaming_mode>simple</streaming_mode>
    <endpoint>
        <args>
            <arg name="srcURL">
                <title>srcURL</title>
                <description>This the URL to be used for the REST API access of the Splunk instance, https://localhost:8089/ for example (does not have to be localhost)</description>
            </arg>
            <arg name="srcUsername">
                <title>srcUsername</title>
                <description>username to use for REST API of srcURL argument (required if not using useLocalAuth)</description>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="srcPassword">
                <title>srcPassword</title>
                <description>password to use for REST API of srcURL argument (required if not using useLocalAuth). If started with password: the name after the : symbol (password:mypass) is searched for in passwords.conf</description>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="gitTempDir">
                <title>gitTempDir</title>
                <description>location where to store the output of the script on the filesystem (note this directory will be deleted/re-created but the parent dir must exist)</description>
            </arg>
            <arg name="gitRepoURL">
                <title>gitRepoURL</title>
                <description>git repository URL to store the objects (SSH URL only)</description>
            </arg>
            <arg name="noPrivate">
                <title>noPrivate</title>
                <description>disable the backup of user level / private objects (true/false), default false</description>
                <validation>is_bool('noPrivate')</validation>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="noDisabled">
                <title>noDisabled</title>
                <description>disable the backup of objects with a disabled status in Splunk (true/false), default false</description>
                <validation>is_bool('noDisabled')</validation>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="includeEntities">
                <title>includeEntities</title>
                <description>comma separated list of object values to include</description>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="excludeEntities">
                <title>excludeEntities</title>
                <description>comma separated list of object values to exclude</description>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="includeOwner">
                <title>includeOwner</title>
                <description>comma separated list of owners objects that should be transferred</description>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="excludeOwner">
                <title>excludeOwner</title>
                <description>comma separated list of owners objects that should be transferred</description>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="debugMode">
                <title>debugMode</title>
                <description>turn on DEBUG level logging (defaults to INFO) (true/false), default false</description>
                <validation>is_bool('debugMode')</validation>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="useLocalAuth">
                <title>useLocalAuth</title>
                <description>Instead of using the srcUsername/srcPassword, use the session_key of the user running the modular input instead (works on localhost only) (true/false), default false</description>
                <validation>is_bool('useLocalAuth')</validation>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="remoteAppName">
                <title>remoteAppName</title>
                <description>defaults to SplunkVersionControl, this app needs to contain the savedsearches and potentially the splunkversioncontrol_globalexclusionlist, use SplunkVersionControlCloud on a cloud-based instance</description>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="appsList">
                <title>appsList</title>
                <description>Comma separated list of apps, this changes Splunk Version Control to not list all applications and instead only runs a backup on the specified apps</description>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="git_command">
                <title>git_command</title>
                <description>defaults to 'git', can be overriden (for example on a Windows server) to use a full path to the git command</description>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="ssh_command">
                <title>ssh_command</title>
                <description>defaults to 'ssh', can be overriden (for example on a Windows server) to use a full path to the ssh command</description>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="proxy">
                <title>proxy</title>
                <description>If supplied provides a proxy setting to use to access the srcURL (https proxy). Use https://user:password:passwordinpasswordsconf@10.10.1.0:3128 and the application will obtain the password for the entry 'passwordinpasswordsconf'. If password: is not used the password is used as per a normal proxy setting, for example https://user:password@10.10.1.0:3128</description>
                <required_on_create>false</required_on_create>
            </arg>
        </args>
    </endpoint>
</scheme>
"""

#Get the XML for validation
def get_validation_data():
    val_data = {}

    # read everything from stdin
    val_str = sys.stdin.read()

    # parse the validation XML
    doc = xml.dom.minidom.parseString(val_str)
    root = doc.documentElement
    session_key = root.getElementsByTagName("session_key")[0].firstChild.data
    val_data['session_key'] = session_key

    logger.debug("XML: found items")
    item_node = root.getElementsByTagName("item")[0]
    if item_node:
        logger.debug("XML: found item")

        name = item_node.getAttribute("name")
        val_data["stanza"] = name

        params_node = item_node.getElementsByTagName("param")
        for param in params_node:
            name = param.getAttribute("name")
            logger.debug("Found param %s" % name)
            if name and param.firstChild and \
               param.firstChild.nodeType == param.firstChild.TEXT_NODE:
                val_data[name] = param.firstChild.data

    return val_data

# prints XML error data to be consumed by Splunk
def print_error(s):
    print("<error><message>%s</message></error>" % xml.sax.saxutils.escape(s))
    logger.error(s)

#Validate the arguments to the app to ensure this will work...
def validate_arguments():
    val_data = get_validation_data()
    
    if 'debugMode' in val_data:
        debugMode = val_data['debugMode'].lower()
        if debugMode == "true" or debugMode == "t":
            logging.getLogger().setLevel(logging.DEBUG)

    session_key = val_data['session_key']

    useLocalAuth = False
    if 'useLocalAuth' in val_data:
        useLocalAuth = val_data['useLocalAuth'].lower()
        if useLocalAuth == "true" or useLocalAuth == "t":
            useLocalAuth = True
            logger.debug("useLocalAuth enabled")
            if val_data['srcURL'] != "https://localhost:8089":
                print_error("Expected srcURL of https://localhost:8089 since useLocalAuth=True")
                sys.exit(1)
        elif useLocalAuth == "false" or useLocalAuth == "f":
            useLocalAuth = False
        else:
            print_error("useLocalAuth argument should be true or false, invalid config")
            sys.exit(2)
    
    #If we're not using the useLocalAuth we must have a username/password to work with
    if not useLocalAuth and ('srcUsername' not in val_data or 'srcPassword' not in val_data):
        print_error("useLocalAuth is not set to true and srcUsername/srcPassword not set, invalid config")
        sys.exit(3)

    appName = "SplunkVersionControl"
    if 'remoteAppName' in val_data:
        appName = val_data['remoteAppName']

    if 'git_command' in val_data:
        git_command = val_data['git_command'].strip()
        logger.debug("Overriding git command to %s" % (git_command))
    else:
        git_command = "git"
    if 'ssh_command' in val_data:
        ssh_command = val_data['ssh_command'].strip()
        logger.debug("Overriding ssh command to %s" % (ssh_command))
    else:
        ssh_command = "ssh"

    #Run a sanity check and make sure we can connect into the remote Splunk instance
    if not useLocalAuth:
        url = val_data['srcURL'] + "/servicesNS/nobody/%s/search/jobs/export?search=makeresults" % (appName)
        #Verify=false is hardcoded to workaround local SSL issues
        srcUsername = val_data['srcUsername']
        srcPassword = val_data['srcPassword']
        if srcPassword.find("password:") == 0:
            srcPassword = get_password(srcPassword[9:], session_key, logger)

        proxies = {}
        if 'proxy' in val_data:
            proxies["https"] = val_data['proxy']
            if proxies['https'].find("password:") != -1:
                start = proxies['https'].find("password:") + 9
                end = proxies['https'].find("@")
                logger.debug("Attempting to replace proxy=%s by subsituting=%s with a password" % (proxies['https'], proxies['https'][start:end]))
                temp_password = get_password(proxies['https'][start:end], session_key, logger)
                proxies['https'] = proxies['https'][0:start-9] + temp_password + proxies['https'][end:]

        try:
            logger.debug("Running query against URL %s with username %s proxies_length=%s" % (url, srcUsername, len(proxies)))
            res = requests.get(url, auth=(srcUsername, srcPassword), verify=False, proxies=proxies)
            logger.debug("End query against URL %s with username %s" % (url, srcUsername))

            if (res.status_code != requests.codes.ok):
                print_error("Attempt to validate access to Splunk failed with code %s, reason %s, text %s, on URL %s" % (res.status_code, res.reason, res.text, url))
                sys.exit(4)
        except requests.exceptions.RequestException as e:
            print_error("Attempt to validate access to Splunk failed with error %s" % (e))
            sys.exit(5)

    gitRepoURL = val_data['gitRepoURL']
    (stdout, stderr, res) = runOSProcess("%s ls-remote %s" % (git_command, gitRepoURL), logger)
    #If we didn't manage to ls-remote perhaps we just need to trust the fingerprint / this is the first run?
    if res == False:
        (stdout, stderrout, res) = runOSProcess(ssh_command + " -n -o \"BatchMode yes\" -o StrictHostKeyChecking=no " + gitRepoURL[:gitRepoURL.find(":")], logger)
        (stdout, stderr, res) = runOSProcess("%s ls-remote %s" % (git_command, gitRepoURL), logger)
    
    if res == False:
        print_error("Failed to validate the git repo URL, stdout of '%s', stderr of '%s'" % (stdout, stderr))
        sys.exit(6)


#Print the scheme
def do_scheme():
    print(SCHEME)    

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

# Script must implement these args: scheme, validate-arguments
if __name__ == '__main__':
    if len(sys.argv) > 1:
        if sys.argv[1] == "--scheme":
            do_scheme()
        elif sys.argv[1] == "--validate-arguments":
            validate_arguments()
        else:
            pass
    else:
        vc = SplunkVersionControlBackup()
        vc.run_script()

    sys.exit(0)
