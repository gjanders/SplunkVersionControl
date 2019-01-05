[splunkversioncontrol://<name>]
srcURL = <value>
* This the URL to be used for the REST API access of the Splunk instance, https://localhost:8089/ for example (does not have to be localhost)
srcUsername = <value>
* username to use for REST API of srcURL argument
srcPassword = <value>
* password to use for REST API of srcURL argument
gitTempDir = <value>
* location where to store the output of the script on the filesystem
noPrivate = <boolean>
* disable the backup of user level / private objects (true/false)
noDisabled = <boolean>
* disable the backup of objects with a disabled status in Splunk (true/false)
includeEntities = <value>
* comma separated list of object values to include
excludeEntities = <value>
* comma separated list of object values to exclude
includeOwner = <value>
* comma separated list of owners objects that should be transferred
excludeOwner = <value>
* comma separated list of owners objects that should be transferred
debugMode = <boolean>
* turn on DEBUG level logging (defaults to INFO) (true/false)
useLocalAuth = <boolean>
* do not use the srcUsername/srcPassword, use the session_key of the user running the modular input instead (works on localhost only) (true/false)