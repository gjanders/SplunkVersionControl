from __future__ import print_function
import requests
import xml.etree.ElementTree as ET
import logging
from logging.config import dictConfig
import os
import sys
import xml.dom.minidom, xml.sax.saxutils
import platform
from splunkversioncontrol_restore_class import SplunkVersionControlRestore
from splunkversioncontrol_utility import runOSProcess, get_password

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
                <description>password to use for REST API of destURL argument (only required if not using useLocalAuth). If started with password: the name after the : symbol (password:mypass) is searched for in passwords.conf</description>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="gitTempDir">
                <title>gitTempDir</title>
                <description>location where to store the output of the script on the filesystem (note this directory will be deleted/re-created but the parent dir must exist)</description>
            </arg>
            <arg name="gitRepoURL">
                <title>gitRepoURL</title>
                <description>git repository URL to store the objects. password:passwordinpasswordsconf can be used for token/password substitution if required for http/https URL's</description>
            </arg>
            <arg name="sslVerify">
                <title>sslVerify</title>
                <description>Set to 'true' or 'false' to enable/disable SSL verification for REST requests to `srcUrl`. Set to a path to specify a file with valid CA. (https://2.python-requests.org/en/master/user/advanced/#ssl-cert-verification)</description>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="auditLogsLookupBackTime">
                <title>auditLogsLookupBackTime</title>
                <description>This is how far back the audit logs will be checked to ensure that a restore entry is valid, this should be set to your interval time or slightly more, defaults to -1h (use Splunk format)</description>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="debugMode">
                <title>debugMode</title>
                <description>turn on DEBUG level logging (defaults to INFO) (true/false), default false</description>
                <validation>is_bool('debugMode')</validation>
                <required_on_create>false</required_on_create>
                <data_type>boolean</data_type>
            </arg>
            <arg name="show_passwords">
                <title>show_passwords</title>
                <description>Show passwords in the DEBUG/ERROR logs (hidden by default)</description>
                <validation>is_bool('show_passwords')</validation>
                <required_on_create>false</required_on_create>
                <data_type>boolean</data_type>
            </arg>
            <arg name="useLocalAuth">
                <title>useLocalAuth</title>
                <description>Instead of using the destUsername/destPassword, use the session_key of the user running the modular input instead (works on localhost only) (true/false), default false</description>
                <validation>is_bool('useLocalAuth')</validation>
                <required_on_create>false</required_on_create>
                <data_type>boolean</data_type>
            </arg>
            <arg name="remoteAppName">
                <title>remoteAppName</title>
                <description>defaults to SplunkVersionControl, this app needs to contain the savedsearches and potentially the splunkversioncontrol_globalexclusionlist, use SplunkVersionControlCloud on a cloud-based instance</description>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="timewait">
                <title>timewait</title>
                <description>defaults to 600, if the kvstore contains an entry advising there is a restore running, how many seconds should pass before the entry is deleted and the restore happens anyway?</description>
                <required_on_create>false</required_on_create>
                <data_type>number</data_type>
                <validation>is_pos_int('timewait')</validation>
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
                <description>If supplied provides a proxy setting to use to access the destURL (https proxy). Use https://user:password:passwordinpasswordsconf@10.10.1.0:3128 and the application will obtain the password for the entry 'passwordinpasswordsconf'. If password: is not used the password is used as per a normal proxy setting, for example https://user:password@10.10.1.0:3128</description>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="git_proxy">
                <title>git_proxy</title>
                <description>If supplied provides a proxy setting to use to access the git repository (https proxy). Use https://user:password:passwordinpasswordsconf@10.10.1.0:3128 and the application will obtain the password for the entry 'passwordinpasswordsconf'. If password: is not used the password is used as per a normal proxy setting, for example https://user:password@10.10.1.0:3128</description>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="git_branch">
                <title>git_branch</title>
                <description>Sets the git branch to use, defaults to master</description>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="file_per_ko">
                <title>file_per_ko</title>
                <description>Do you want one file per knowledge object? Or a combined file? Defaults to false (i.e. 1 large file for global dashboards in an app)</description>
                <required_on_create>false</required_on_create>
                <data_type>boolean</data_type>
                <validation>is_bool('file_per_ko')</validation>
            </arg>
            <arg name="disable_git_ssl_verify">
                <title>disable_git_ssl_verify</title>
                <description>Use GIT_SSL_NO_VERIFY=true on all git commands</description>
                <required_on_create>false</required_on_create>
                <data_type>boolean</data_type>
                <validation>is_bool('disable_git_ssl_verify')</validation>
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

#Run an OS process with a timeout, this way if a command gets "stuck" waiting for input it is killed
#    logger.warn("OS timeout after %s seconds while running %s" % (timeout, command))
#    return "", "timeout after %s seconds" % (timeout), False

#Validate the arguments to the app to ensure this will work...
def validate_arguments():
    val_data = get_validation_data()

    if 'debugMode' in val_data:
        debugMode = val_data['debugMode'].lower()
        if debugMode == "true" or debugMode == "t" or debugMode == "1":
            logging.getLogger().setLevel(logging.DEBUG)

    useLocalAuth = False
    if 'useLocalAuth' in val_data:
        useLocalAuth = val_data['useLocalAuth'].lower()
        if useLocalAuth == "true" or useLocalAuth == "t" or useLocalAuth == "1":
            useLocalAuth = True
            logger.debug("useLocalAuth enabled")
            if val_data['destURL'] != "https://localhost:8089":
                print_error("Expected destURL of https://localhost:8089 since useLocalAuth=True")
                sys.exit(1)
        elif useLocalAuth == "false" or useLocalAuth == "f" or useLocalAuth == "0":
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
            print_error("Unable to convert timeout field to a valid value, this must be an integer value in seconds, value provided was %s" % (val_data['timewait']))
            sys.exit(1)

    sslVerify = False
    if 'sslVerify' in val_data:
        if val_data['sslVerify'].lower() == 'true' or val_data['sslVerify'] == "1":
            sslVerify = True
            logger.debug('sslverify set to boolean True from: ' + val_data['sslVerify'])
        elif val_data['sslVerify'].lower() == 'false' or val_data['sslVerify'] == "0":
            sslVerify = False
            logger.debug('sslverify set to boolean False from: ' + val_data['sslVerify'])
        else:
            sslVerify = val_data['sslVerify']
            logger.debug('sslverify set to: ' + val_data['sslVerify'])

    session_key = val_data['session_key']

    #Run a sanity check and make sure we can connect into the remote Splunk instance
    if not useLocalAuth:
        url = val_data['destURL'] + "/servicesNS/nobody/%s/search/jobs/export?search=makeresults" % (appName)
        destUsername = val_data['destUsername']
        destPassword = val_data['destPassword']

        if destPassword.find("password:") == 0:
            destPassword = get_password(destPassword[9:], session_key, logger)
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
            logger.debug("Running query against URL %s with username %s proxies_length=%s sslVerify=%s" % (url, destUsername, len(proxies), sslVerify))
            res = requests.get(url, auth=(destUsername, destPassword), verify=sslVerify, proxies=proxies)
            logger.debug("End query against URL %s with username %s" % (url, destUsername))
            if (res.status_code != requests.codes.ok):
                print_error("Attempt to validate access to Splunk failed with code %s, reason %s, text %s on URL %s" % (res.status_code, res.reason, res.text, url))
                sys.exit(1)
        except requests.exceptions.RequestException as e:
            print_error("Attempt to validate access to Splunk failed with error %s" % (e))
            sys.exit(1)

    gitRepoURL = val_data['gitRepoURL']

    if 'git_command' in val_data:
        git_command = val_data['git_command'].strip()
        git_command = git_command.replace("\\","/")
        logger.debug("Overriding git command to %s" % (git_command))
    else:
        git_command = "git"
    if 'ssh_command' in val_data:
        ssh_command = val_data['ssh_command'].strip()
        ssh_command = ssh_command.replace("\\","/")
        logger.debug("Overriding ssh command to %s" % (ssh_command))
    else:
        ssh_command = "ssh"

    disable_git_ssl_verify = False
    if 'disable_git_ssl_verify' in val_data:
        if val_data['disable_git_ssl_verify'].lower() == 'true' or val_data['disable_git_ssl_verify'] == "1":
            git_command = "GIT_SSL_NO_VERIFY=true " + git_command
            logger.debug('git_command now has GIT_SSL_NO_VERIFY=true because disable_git_ssl_verify: ' + val_data['disable_git_ssl_verify'])
            disable_git_ssl_verify = True
        elif val_data['disable_git_ssl_verify'].lower() == 'false' or val_data['disable_git_ssl_verify'] == "0":
            logger.debug('disable_git_ssl_verify set to boolean False from: ' + val_data['disable_git_ssl_verify'])
        else:
            logger.warn('disable_git_ssl_verify not set to a valid value, ignoring the setting, please update the setting from: ' + val_data['disable_git_ssl_verify'])

    git_proxies = {}
    if 'git_proxy' in val_data:
        git_proxies["https"] = val_data['git_proxy']
        if git_proxies['https'].find("password:") != -1:
            start = git_proxies['https'].find("password:") + 9
            end = git_proxies['https'].find("@")
            logger.debug("Attempting to replace git_proxy=%s by subsituting=%s with a password" % (git_proxies['https'], git_proxies['https'][start:end]))
            temp_password = get_password(git_proxies['https'][start:end], session_key, logger)
            git_proxies['https'] = git_proxies['https'][0:start-9] + temp_password + git_proxies['https'][end:]

    git_password = False
    if gitRepoURL.find("http") == 0:
        gitRepoHTTP = True
        if gitRepoURL.find("password:") != -1:
            start = gitRepoURL.find("password:") + 9
            end = gitRepoURL.find("@")
            logger.debug("Attempting to replace gitRepoURL=%s by subsituting=%s with a password" % (gitRepoURL, gitRepoURL[start:end]))
            git_password = get_password(gitRepoURL[start:end], session_key, logger)
            gitRepoURL = gitRepoURL[0:start-9] + git_password + gitRepoURL[end:]
    else:
        gitRepoHTTP = False

    show_passwords = False
    if 'show_passwords' in val_data:
        if val_data['show_passwords'].lower() == 'true' or val_data['show_passwords'] == "1":
            show_passwords = True
            logger.debug('show_passwords is now true due to show_passwords: ' + val_data['show_passwords'])

    proxy_command = ""

    if gitRepoHTTP and len(git_proxies) > 0:
        logger.debug("Adding environment variable HTTPS_PROXY before git commands")
        proxy_command = "HTTPS_PROXY=" + git_proxies["https"]
        if platform.system() == "Windows":
            proxy_command = "set " + proxy_command + " & "
        else:
            proxy_command = "export " + proxy_command + " ; "

    (stdout, stderr, res) = runOSProcess("%s %s ls-remote %s" % (proxy_command, git_command, gitRepoURL), logger)

    #If we didn't manage to ls-remote perhaps we just need to trust the fingerprint / this is the first run?
    if res == False and not gitRepoHTTP:
        (stdout, stderrout, res) = runOSProcess(ssh_command + " -n -o \"BatchMode yes\" -o StrictHostKeyChecking=no " + gitRepoURL[:gitRepoURL.find(":")], logger)
        (stdout, stderr, res) = runOSProcess("%s ls-remote %s" % (git_command), logger)

    if res == False:
        if show_passwords and not git_password:
            stdout = stdout.replace(git_password, "password_removed")
            stderr = stderr.replace(git_password, "password_removed")

        print_error("Failed to validate the git repo URL, stdout of '%s', stderr of '%s'" % (stdout, stderr))
        sys.exit(1)

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
