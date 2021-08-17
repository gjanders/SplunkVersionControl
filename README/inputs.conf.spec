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
* git repository URL to store the objects. password:passwordinpasswordsconf can be used for token/password substitution if required for http/https URL's
sslVerify = <boolean>
* Set to 'true' or 'false' to enable/disable SSL verification for REST requests to `srcUrl`. Set to a path to specify a file with valid CA. (https://2.python-requests.org/en/master/user/advanced/#ssl-cert-verification)
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
show_passwords = <boolean>
* Show passwords in the DEBUG/ERROR logs (hidden by default)
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
git_name = <value>
* If set this runs git config user.name '<value>' once the backup git repo is cloned
git_email = <value>
* If set this runs git config user.email '<value>' once the backup git repo is cloned
git_branch = <value>
* Sets the git branch to use, defaults to master
git_proxy  = <value>
* If supplied provides a proxy setting to use to access the git repository (https proxy). Use https://user:password:passwordinpasswordsconf@10.10.1.0:3128 and the application will obtain the password for the entry 'passwordinpasswordsconf'. If password: is not used the password is used as per a normal proxy setting, for example https://user:password@10.10.1.0:3128</description>
file_per_ko = <boolean>
* Do you want one file per knowledge object? Or a combined file? Defaults to false (i.e. 1 large file for global dashboards in an app). Note that if you change this you will need to re-create or wipe the repository as the files are stored differently...Note this setting should match in both backup and restore modular inputs for a particular repo
run_ko_query = <boolean>
* Do you want to run a Splunk query to determine which knowledge objects changed? macro 'splunk_vc_ko_query' (defaults to false)
run_ko_diff = <boolean>
* Should output of the modular input include diff information (requires run_ko_query to be true, defaults to false)
disable_git_ssl_verify = <boolean>
* Use GIT_SSL_NO_VERIFY=true on all git commands
use_wdiff = <boolean>
* Enables the diff HEAD~1 to be passed to wdiff for improved formatting if run_ko_diff is enabled
disable_file_deletion = <boolean>
* By default if the app or file no longer exists than it is deleted from the git repo, this stops the deletion from occurring

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
* git repository URL to restore the objects from. password:passwordinpasswordsconf can be used for token/password substitution if required for http/https URL's
sslVerify = <boolean>
* Set to 'true' or 'false' to enable/disable SSL verification for REST requests to `srcUrl`. Set to a path to specify a file with valid CA. (https://2.python-requests.org/en/master/user/advanced/#ssl-cert-verification)
auditLogsLookupBackTime = <value>
* This is how far back the audit logs will be checked to ensure that a restore entry is valid, this should be set to your interval time or slightly more, defaults to -1h (use Splunk format)
debugMode = <boolean>
* turn on DEBUG level logging (defaults to INFO) (true/false), default false
show_passwords = <boolean>
* Show passwords in the DEBUG/ERROR logs (hidden by default)
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
git_branch = <value>
* Sets the git branch to use, defaults to master
git_proxy  = <value>
* If supplied provides a proxy setting to use to access the git repository (https proxy). Use https://user:password:passwordinpasswordsconf@10.10.1.0:3128 and the application will obtain the password for the entry 'passwordinpasswordsconf'. If password: is not used the password is used as per a normal proxy setting, for example https://user:password@10.10.1.0:3128</description>
file_per_ko = <boolean>
* Do you want one file per knowledge object? Or a combined file? Defaults to false (i.e. 1 large file for global dashboards in an app). Note that if you change this you will need to re-create or wipe the repository as the files are stored differently...Note this setting should match in both backup and restore modular inputs for a particular repo
disable_git_ssl_verify = <boolean>
* Use GIT_SSL_NO_VERIFY=true on all git commands
