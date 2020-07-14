[splunkversioncontrol_backup://<name>]
srcURL = <value>
* This the URL to be used for the REST API access of the Splunk instance, https://localhost:8089/ for example (does not have to be localhost)
srcUsername = <value>
* username to use for REST API of srcURL argument (required if not using useLocalAuth)
srcPassword = <value>
* password to use for REST API of srcURL argument (required if not using useLocalAuth), use 'password:<name in passwords.conf>' and the app will attempt to find the password in your passwords.conf file
gitTempDir = <value>
* location where to store the output of the script on the filesystem (note this directory will be deleted/re-created but the parent dir must exist)
gitRepoURL = <value>
* git repository URL to store the objects (SSH URL only)
noPrivate = <boolean>
* disable the backup of user level / private objects (true/false), default false
noDisabled = <boolean>
* disable the backup of objects with a disabled status in Splunk (true/false), default false
includeEntities = <value>
* comma separated list of object values to include
excludeEntities = <value>
* comma separated list of object values to exclude
includeOwner = <value>
* comma separated list of owners objects that should be transferred
excludeOwner = <value>
* comma separated list of owners objects that should be transferred
debugMode = <boolean>
* turn on DEBUG level logging (defaults to INFO) (true/false), default false
useLocalAuth = <boolean>
* do not use the srcUsername/srcPassword, use the session_key of the user running the modular input instead (works on localhost only) (true/false), default false
remoteAppName = <value>
* defaults to SplunkVersionControl, this app needs to contain the savedsearches and potentially the splunkversioncontrol_globalexclusionlist, use SplunkVersionControlCloud on a cloud-based instance
appsList = <value>
* Comma separated list of apps, this changes Splunk Version Control to not list all applications and instead only runs a backup on the specified apps
git_command = <value>
* defaults to 'git', can be overriden (for example on a Windows server) to use a full path to the git command
ssh_command = <value> 
* defaults to 'ssh', can be overriden (for example on a Windows server) to use a full path to the ssh command
proxy = <value>
* If supplied provides a proxy setting to use to access the srcURL (https proxy). Use https://user:password:passwordinpasswordsconf@10.10.1.0:3128 and the application will obtain the password for the entry 'passwordinpasswordsconf'. If password: is not used the password is used as per a normal proxy setting, for example https://user:password@10.10.1.0:3128

[splunkversioncontrol_restore://<name>]
destURL = <value>
* This the URL to be used for the REST API access of the Splunk instance, https://localhost:8089/ for example (does not have to be localhost)
destUsername = <value>
* username to use for REST API of srcURL argument (only required if not using useLocalAuth)
destPassword = <value>
* password to use for REST API of srcURL argument (only required if not using useLocalAuth), use 'password:<name in passwords.conf>' and the app will attempt to find the password in your passwords.conf file
gitTempDir = <value>
* location where to store the output of the script on the filesystem (note this directory will be deleted/re-created but the parent dir must exist)
gitRepoURL = <value>
* git repository URL to store the objects (SSH URL only)
auditLogsLookupBackTime = <value>
* This is how far back the audit logs will be checked to ensure that a restore entry is valid, this should be set to your interval time or slightly more, defaults to -1h (use Splunk format)
debugMode = <boolean>
* turn on DEBUG level logging (defaults to INFO) (true/false), default false
useLocalAuth = <boolean>
* do not use the srcUsername/srcPassword, use the session_key of the user running the modular input instead (works on localhost only) (true/false), default false
remoteAppName = <value>
* defaults to SplunkVersionControl, this app needs to contain the savedsearches and potentially the splunkversioncontrol_globalexclusionlist, use SplunkVersionControlCloud on a cloud-based instance
timewait = <value>
* defaults to 600, if the kvstore contains an entry advising there is a restore running, how many seconds should pass before the entry is deleted and the restore happens anyway?
git_command = <value>
* defaults to 'git', can be overriden (for example on a Windows server) to use a full path to the git command
ssh_command = <value>
* defaults to 'ssh', can be overriden (for example on a Windows server) to use a full path to the ssh command
proxy = <value>
* If supplied provides a proxy setting to use to access the destURL (https proxy). Use https://user:password:passwordinpasswordsconf@10.10.1.0:3128 and the application will obtain the password for the entry 'passwordinpasswordsconf'. If password: is not used the password is used as per a normal proxy setting, for example https://user:password@10.10.1.0:3128
