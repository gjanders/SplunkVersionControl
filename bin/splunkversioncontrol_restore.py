import requests
import xml.etree.ElementTree as ET
import logging
from logging.config import dictConfig
import os
import sys
import xml.dom.minidom, xml.sax.saxutils
from splunkversioncontrol_restore_class import SplunkVersionControlRestore
from splunkversioncontrol_utility import runOSProcess

"""

 Restore Knowledge Objects
   Query a remote lookup file to determine what items should be restored from git into a Splunk instance
   In general this will be running against the localhost unless it is been tested as the lookup file will be updated
   by a user accessible dashboard
   Basic validation will be done to ensure someone without the required access cannot restore someone else's knowledge objects
 
"""

#Define the scheme for the inputs page to use
SCHEME = """<scheme>
    <title>Splunk Version Control Restore</title>
    <description>Restore Splunk knowledge objects from the git version control system (restore only)</description>
    <use_external_validation>true</use_external_validation>
    <streaming_mode>simple</streaming_mode>
    <endpoint>
        <args>
            <arg name="destURL">
                <title>destURL</title>
                <description>This the URL to be used for the REST API access of the Splunk instance, https://localhost:8089/ for example (does not have to be localhost)</description>
            </arg>
            <arg name="destUsername">
                <title>destUsername</title>
                <description>username to use for REST API of destURL argument (only required if not using useLocalAuth)</description>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="destPassword">
                <title>destPassword</title>
                <description>password to use for REST API of destURL argument (only required if not using useLocalAuth)</description>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="gitTempDir">
                <title>gitTempDir</title>
                <description>location where to store the output of the script on the filesystem</description>
            </arg>
            <arg name="gitRepoURL">
                <title>gitRepoURL</title>
                <description>git repository URL to store the objects (SSH URL only)</description>
            </arg>
            <arg name="auditLogsLookupBackTime">
                <title>auditLogsLookupBackTime</title>
                <description>This is how far back the audit logs will be checked to ensure that a restore entry is valid, this should be set to your interval time or slightly more, defaults to -1h (use Splunk format)</description>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="debugMode">
                <title>debugMode</title>
                <description>turn on DEBUG level logging (defaults to INFO) (true/false)</description>
                <validation>is_bool('debugMode')</validation>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="useLocalAuth">
                <title>useLocalAuth</title>
                <description>Instead of using the destUsername/destPassword, use the session_key of the user running the modular input instead (works on localhost only) (true/false)</description>
                <validation>is_bool('useLocalAuth')</validation>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="remoteAppName">
                <title>remoteAppName</title>
                <description>defaults to SplunkVersionControl, this app needs to contain the savedsearches and potentially the splunkversioncontrol_globalexclusionlist</description>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="timewait">
                <title>timewait</title>
                <description>defaults to 600, if the kvstore contains an entry advising there is a restore running, how many seconds should pass before the entry is deleted and the restore happens anyway?</description>
                <required_on_create>false</required_on_create>
            </arg>
        </args>
    </endpoint>
</scheme>
"""

#Obtain the validation XML
def get_validation_data():
    val_data = {}

    # read everything from stdin
    val_str = sys.stdin.read()

    # parse the validation XML
    doc = xml.dom.minidom.parseString(val_str)
    root = doc.documentElement

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
    print "<error><message>%s</message></error>" % xml.sax.saxutils.escape(s)
    logger.error(s)
    
#Validate the arguments to the app to ensure this will work...
def validate_arguments():
    val_data = get_validation_data()
    useLocalAuth = False
    if 'useLocalAuth' in val_data:
        useLocalAuth = val_data['useLocalAuth'].lower()
        if useLocalAuth == "true" or useLocalAuth == "t":
            useLocalAuth = True
            if val_data['destURL'] != "https://localhost:8089":
                print_error("Expected destURL of https://localhost:8089 since useLocalAuth=True")
                sys.exit(1)
        elif useLocalAuth == "false" or useLocalAuth == "f":
            useLocalAuth = False
        else:
            print_error("useLocalAuth argument should be true or false, invalid config")
            sys.exit(1)
    
    #If we're not using the useLocalAuth we must have a username/password to work with
    if not useLocalAuth and ('destUsername' not in val_data or 'destPassword' not in val_data):
        print_error("useLocalAuth is not set to true and destUsername/destPassword not set, invalid config")
        sys.exit(1)
    
    appName = "SplunkVersionControl"
    if 'remoteAppName' in val_data:
        appName = val_data['remoteAppName']
    
    if 'timewait' in val_data:
        try:
            int(val_data['timewait'])
        except ValueError:
            print_error("Unable to convert timewait field to a valid value, this must be an integer value in seconds, value provided was %s" % (val_data['timewait']))
            sys.exit(1)
    
    #Run a sanity check and make sure we can connect into the remote Splunk instance
    if not useLocalAuth:
        url = val_data['destURL'] + "/servicesNS/nobody/%s/search/jobs/export?search=makeresults" % (appName)
        #Verify=false is hardcoded to workaround local SSL issues
        destUsername = val_data['destUsername']
        destPassword = val_data['destPassword']
        try:
            logger.debug("Running query against URL %s with username %s" % (url, destUsername))
            res = requests.get(url, auth=(destUsername, destPassword), verify=False)
            logger.debug("End query against URL %s with username %s" % (url, destUsername))
            if (res.status_code != requests.codes.ok):
                print_error("Attempt to validate access to Splunk failed with code %s, reason %s, text %s on URL %s" % (res.status_code, res.reason, res.text, url))
                sys.exit(1)
        except requests.exceptions.RequestException as e:
            print_error("Attempt to validate access to Splunk failed with error %s" % (e))
            sys.exit(1)
        logger.warn("done")
    gitRepoURL = val_data['gitRepoURL']

    (stdout, stderr, res) = runOSProcess(["git ls-remote %s" % (gitRepoURL) ], logger)
    #If we didn't manage to ls-remote perhaps we just need to trust the fingerprint / this is the first run?
    if res == False:
        (stdout, stderrout, res) = runOSProcess("ssh -n -o \"BatchMode yes\" -o StrictHostKeyChecking=no " + gitRepoURL[:gitRepoURL.find(":")], logger)
        (stdout, stderr, res) = runOSProcess(["git ls-remote %s" % (gitRepoURL) ], logger)
    
    if res == False:
        print_error("Failed to validate the git repo URL, stdout of '%s', stderr of '%s'" % (stdout, stderr))
        sys.exit(1)
    
#Print the scheme
def do_scheme():
    print SCHEME

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
        vc = SplunkVersionControlRestore()
        vc.run_script()

    sys.exit(0)
