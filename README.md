# Splunk Version Control

## What does this app do?

This app allows you to back up and use version control to manage your Splunk knowledge objects, such as saved searches and macros.

## Why?
Splunk (as of the time of writing in January 2019) has no native ability to use version control on its knowledge objects. This can lead to issues where an object is accidentally changed or deleted and there is no way to restore them beyond using OS-level backups, which are difficult to use in a search head cluster.

## How does the app function?

The app uses two modular inputs to back up and restore configurations, Splunk Version Control Backup (or `splunkversioncontrol_backup`) and and Splunk Version Control Restore (or `splunkversioncontrol_restore`). 

The backup portion of the app provides a Splunk modular input with the ability to serialize various Splunk knowledge objects into JSON format, which is then stored in a remote git repository and tagged based on each change to the backup.

These two inputs do not have to be on the same machine, however, they must be pointing to the same git repository and the gitTempDir must be unique on the filesystem if sharing the same machine.

The restore portion provides a Splunk modular input and a dashboard (SplunkVersionControl Restore) that can be used to request the restoration of a knowledge object.

## How do I restore a knowledge object?

Use the SplunkVersionControl Restore dashboard to request that a knowledge object be restored to a prior version. You must be the author of the knowledge objects you wish to restore, or have the admin role. The application with the knowledge object in it must still exist on the Splunk server.

There are two unique dashboards with two different restoration methods, the original version is described below:
When a knowledge object restore is requested the dashboard (SplunkVersionControl Restore) outputs the knowledge object information to a lookup with the definition splunkversioncontrol_restorelist. The modular input then triggers the restore based on the contents of this lookup, the modular input either creates or updates the knowledge object with the requested git tag, or logs the failure to find the object in the logs.

Note that the above option is the option used with Splunk Cloud, the below option can be used on on-prem instances...

The newer dynamic version follows a similar process, but instead of adding the knowledge object restore information to a lookup file it runs a Splunk custom command `postversioncontrolrestore` that hits a REST endpoint on either a local or a remote server.
The REST endpoint then performs a few functions:
- Queries the source system and passes in the authentication token of the current user, this includes restore information and the `splunkversioncontrol_restore` input stanza name
- The remote system then sends a query back to the source ip it received the request from, using the token to check the username logged in 
- The remote system then looks up the login information for the relevant `splunkversioncontrol_restore` input stanza and runs a remote query against it
- The said remote query runs a saved search named `Splunk Version Control Audit Query POST`
- To prevent issues just before running the above query there is a sleep period involved (configurable via the `splunk_vc_timeout` macro)
- If the report confirms the relevant user did indeed request a restore of some kind, the restore continues
- The restore now followed the previous process from this point triggering a restore process
- If multiple users attempt to run the restore at the same time, one of them will receive an error to advise a restore is in progress and to try again later  

## Security Concerns
The ability to restore/create configuration opens up a few obvious issues:
- What if the lookup file storing the list of objects to restore and the user who is performing the restoration is manually edited to add additional rows?
- What if a user attempts to restore the objects of another user?
- What if a user attempts to restore an object but re-own it to a different user?

To address these issues, a report named "SplunkVersionControl Audit Query" runs a query against the audit logs to determine if the lookup was updated by the saved search "SplunkVersionControl AddToLookup". This audit query returns a username and a time (it looks back/forwards one second from when the lookup was created).

The restoration script then validates that the username entered in the lookup file and the time match those found in the audit log. If they do not match then the restoration is rejected.

If you are using the dynamic version of the restore dashboard (custom command `postversioncontrolrestore`, an alternative report named "Splunk Version Control Audit Query POST" runs to check the audit logs, this report determines if the restoration request was made by the user in question. The report returns 0 or more results and if it returns results for the particular user, the restore proceeds.

Due to the above there is the possiblity that multiple users may trigger a restore while a restore is in progress, a kvstore is used to prevent this from occurring and an additional restore attempt when the restore process is in progress results in an error message to try again.

If a user attempts to restore the objects of another user, or attempts to restore the objects as a different user, this is allowed if the user has the admin role (which is determined by the saved search "SplunkVersionControl CheckAdmin").

## Why use a lookup file and not trigger a remote command execution?
A custom command named postversioncontrolrestore and the accompanying dashboard `splunkversioncontrolrestore_dynamic` were created for this purpose in version 1.0.7

However this version wil not work in Splunk Cloud as it would require connectivity to an on-prem instance that can perform the backup/restore modular input functions

## What is required for this application to work with a remote git repository?
The following assumptions are made:
- git is accessible on the command line, this has been tested on Linux & Windows with git for Windows installed 
- git is using an SSH-based URL and the remote git repository allows the machine running the SplunkVersionControl application to remotely access the repository without a username/password prompt (i.e. SSH keys are in use)
- git will work from the user running the Splunk process over SSH, note that on Windows this will be the system account by default, on Linux the splunk user

## Do the modular input backup and restore tasks need to be on the same Splunk instance?
No. However, the backup/restore modular input must have access to its own git temporary directory on the OS filesystem, the temporary directory should be unique for both backup and restore operations

## When will a full application backup occur?
During the first run of the script (at which point the lookup file is empty) all applications and all objects will be backed up.

During each subsequent run of the script, if an application is found in the Splunk system but not on the filesystem then the backup of all objects within that application will occur

Otherwise an incremental backup of knowledge objects occurs (see below)

## What gets backed up on each modular input run (incremental runs)?
There are two searches used to determine "what" has changed since the last run of the modular input:
- SplunkVersionControl ChangeDetector Non-Directory
- SplunkVersionControl ChangeDetector Directory

These two searches are passed in an epoch value, they then return a list of applications and the type of config that has changed.

For example if application search has had macros changed, then all macros in the search app will be backed up, however the savedsearches/dashboards/et cetera will not be backed up unless at least one of them in that app has changed.

## How does the version control work?
Each backup run that results in more than 0 file changes will auto-commit all changes into git and tag with the current date/time including the minute of the hour. This will create tags such as 2019-01-10_0136, these tags can later be used to "restore from" in the "SplunkVersionControl Restore" dashboard.

The tags are recorded by outputting the tag list into the lookup definition `splunkversioncontrol_taglist` within the app, this same lookup definition is read by the dashboard to list available tags to restore from.

## How will the restore work?
The restoration is based on a git tag, the relevant tag is checked out on the filesystem after running a git checkout master; git pull command.

Once checked out, the app/user/global directories are checked (depending on which scope was requested) to see if there is a relevant config item to restore, if found the remote object is either updated with the contents of git or created if it does not exist. By default the knowledge object is created with the same username that was in the backup, however there is an option on the SplunkVersionControl Restore dashboard to override the user on restoration, this is only able to be done by a user with an admin role.

## What other lookup files are used by the app?
- `splunkversioncontrol_globalexclusionlist`, this lookup definition records a list of excluded applications
- `splunkversioncontrol_restorelist`, this lookup definition records what must be restored by the restore modular input (this is used by the non-dynamic dashboard)
- `splunkversioncontrol_taglist`, this lookup definition records the tags available in git

## Where are the logs?
On a Linux-based system
- `/opt/splunk/var/log/splunk/splunkversioncontrol_restore.log` -- this log will contain information about the splunk restore modular input
- `/opt/splunk/var/log/splunk/splunkversioncontrol_backup.log` -- this log will contain information about the splunk backup modular input
- `/opt/splunk/var/log/splunk/splunkversioncontrol_postversioncontrolrestore.log` -- this log contains information about the | postversioncontrol command
- `/opt/splunk/var/log/splunk/splunkversioncontrol_rest_restore.log` -- log log contains information about hits to the REST endpoint `/services/splunkversioncontrol_rest_restore`

Or the internal index which also has these log files with the sourcetype splunkversioncontrol

## Installation guide
### Standalone instance
- Install this application on the Splunk standalone instance, if you are going to access a remote instance please ensure you can access the remote instance on port 8089 
- Create a new git repo and initialise the repo (it can have a README or can it be empty, but it must be at a point where the master branch exists)
- The server doing the git backup must have SSH access to the repo without a username/password (in other words you need to have the SSH key setup so a git clone/git checkout/git push) all work without a prompt for credentials as the OS user running Splunk (as the modular input will run as this user)
- If running on a standalone server the modular inputs can be configured either on the current standalone server, or another remote server, the app will work either way
- If errors are seen when creating the modular inputs see the troubleshooting below, or raise a question on SplunkAnswers for assistance
- If you are running the newer `splunkversioncontrol_restore_dynamic` dashboard the macros `splunk_vc_name`, `splunk_vc_url`, `splunk_vc_timeout` may need customisation to match your environment. In particular the `splunk_vc_name` assumes you have called your SplunkVersionControlRestore modular input "Prod". See the macros section of this document for more information
- Ensure the directory where the git repository will be cloned to is empty (i.e. the git clone can create it)
- Ensure the git repository has at least 1 commit (i.e. it is initialized and a git checkout master will work if you clone the git repo)
- When you create the Splunk Version Control Backup (via Settings -> Data Inputs -> Splunk Version Control Backup), click "More settings" and set the backup interval you would like (tags will only be created if config has changed within Splunk)
- When you create the Splunk Version Control Restore (via Settings -> Data Inputs -> Splunk Version Control Restore), if you are using the newer `splunkversioncontrol_restore_dynamic` dashboard then you do not need to set a run interval, if you are using the older method you want to run this on an interval to check if the lookup file has been updated and if a restore is required...

### Search head cluster (on prem)
- Install the SplunkVersionControl application on the SHC via the deployer as normal 
- Either run the modular inputs on a standalone instance using the above instructions, and set the srcURL and destURL to a search head cluster member (or a load balanced REST port of the SHC)
- Or alternatively configure the backup modular input (including the interval), but do not configure the restore modular input to run on an interval (just configure it to allow restores)

### Splunk Cloud
- Install this application as per the standalone instance documentation above onto a non-SplunkCloud instance, install the VersionControl For SplunkCloud on the SplunkCloud instance
- Note that in SplunkCloud the only option is the `splunkversioncontrol_restore` dashboard, the dynamic dashboard cannot be used in SplunkCloud
- Configure the remoteAppName within the Splunk Version Control Backup & Splunk Version Control Restore modular inputs to "SplunkVersionControlCloud"

## How do I initialize a git repository?
github and other websites may offer to initlize the repository for you, if they do not the steps are usually similar to:
- git clone git@<website>:testing.git
- cd testing
- touch README.md
- git add README.md
- git commit -m "add README"
- git push -u origin master

There are also many online resources to help with learning git

## What do the parameters do?
### Splunk Version Control Backup
- srcURL - URL of the remote or local Splunk instance that should be backed up, this needs to point to the REST port of the instance (port 8089)
- srcUsername - the username to use on the instance to login
- srcPassword - the password to use on the instance to login, use `password:<name in passwords.conf>` and the app will attempt to find the password in your passwords.conf file
- gitTempDir - a directory that the git clone will create, and potentially be deleted. For example /tmp/git_backup or e:\temp\git_backup 
- gitRepoURL - an SSH based git repo URL where the backup will be stored of the knowledge objects
- noPrivate - optional, defaults to false, if set to true will not backup private knowledge objects
- noDisabled - optional, defaults to false, if set to true will not backup disabled objects
- includeEntities - optional, mainly for testing, only include knowledge objects with the names listed here, can be a comma separated list or a single name
- excludeEntities - optional, mainly for testing, exclude knowledge objects with the names listed here, can be a comma separated list or a single name
- includeOwner - optional, only include knowledge objects owned by the particular user listed here, can be a comma separated list or a single name
- excludeOwner - optional, exclude knowledge objects owned by the particular user listed here, can be a comma separated list or a single name
- debugMode - optional, defaults to false, if set to true outputs DEBUG level logs to splunkversioncontrol_backup.log
- useLocalAuth - optional, defaults to false, only set this to "true" if you are using the srcURL of https://localhost:8089, this does not require a srcUsername/srcPassword as local authentication is used
- remoteAppName - optional, defaults to "SplunkVersionControl", if you have renamed the application on the srcURL instance, update this to the new application name
- appsList - optional, by default this app will backup knowledge objects from all apps that are not in the `splunkversioncontrol_globalexclusionlist` lookup file, if an application name is specified only the application is backed up, can be a comma separted list
- git_command - optional, the location of the git command, this is mainly used on Windows where the git command may not be in the PATH of the user running Splunk
- ssh_command - optional, the location of the ssh command, this is mainly used on Windows where the git command may not be in the PATH of the user running Splunk
- proxy - optional, if supplied provides a proxy setting to use to access the srcURL (https proxy). Use https://user:password:passwordinpasswordsconf@10.10.1.0:3128 and the application will obtain the password for the entry "passwordinpasswordsconf". If password: is not used the password is used as per a normal proxy setting, for example https://user:password@10.10.1.0:3128

"More settings"
- interval - how often the backup should run, if not set the backup will only run on restart of the Splunk instance or when you save this configuration...

### Splunk Version Control Restore
- destURL - URL of the remote or local Splunk instance that should be queried for restores, this needs to point to the REST port of the instance (port 8089)
- destUsername - the username to use on the instance to login
- destPassword - the password to use on the instance to login, use `password:<name in passwords.conf>` and the app will attempt to find the password in your passwords.conf file
- gitTempDir - a directory that the git clone will create, and potentially be deleted. For example /tmp/git_restore or e:\temp\git_restore
- gitRepoURL - an SSH based git repo URL which will be used to checkout the required tag to restore from 
- auditLogsLookupBackTime - optional, defaults to -1h, this is the earliest time to pass to the savedsearch `"SplunkVersionControl Audit Query"` to confirm the restore request came from the search head, this must be in Splunk format (-10m, -1h or similar)
- debugMode - optional, defaults to false, if set to true outputs DEBUG level logs to splunkversioncontrol_restore.log
- useLocalAuth - optional, defaults to false, only use this to "true" if you are using the srcURL of https://localhost:8089, this does not require a srcUsername/srcPassword as local authentication is used
- remoteAppName - optional, defaults to "SplunkVersionControl", if you have renamed the application on the srcURL instance, update this to the new application name
- timewait - optional, defaults to 600, this only relates to the dynamic restore dashboard. If the kvstore on the instance advises a restore is in progress, how many seconds should pass before it is assumed the restore has failed and to allow another REST restore to run?
- git_command - optional, the location of the git command, this is mainly used on Windows where the git command may not be in the PATH of the user running Splunk
- ssh_command - optional, the location of the ssh command, this is mainly used on Windows where the git command may not be in the PATH of the user running Splunk 
- proxy - optional, if supplied provides a proxy setting to use to access the destURL (https proxy). Use https://user:password:passwordinpasswordsconf@10.10.1.0:3128 and the application will obtain the password for the entry "passwordinpasswordsconf". If password: is not used the password is used as per a normal proxy setting, for example https://user:password@10.10.1.0:3128

"More settings"
- interval - how often should the remote server be checked to see if a restore is required. If you are on-prem and using the dynamic restore dashboard you do not need to set an interval, if this is a cloud based system or using the non-dynamic dashboard this is the interval to check the remote server for if a restore needs to be run (i.e. how long it is between a user requesting a restore and this script checking/polling the remote system to run the restoration job)

### Additional notes
To get passwords into or out of the passwords.conf you may wish to use https://splunkbase.splunk.com/app/4013/

The context of the application name (default of SplunkVersionControl) will be checked first for the password, if that fails a query to all contexts /-/-/ will occur, realms will be ignored, only the name of the password is used for searching so any realm (or lack of realm) will work for storing the password

## Macros
The following macros exist and are relate to the `splunkversioncontrol_restore_dynamic` dashboard
- `splunk_vc_name` - this macro is the name of the `splunkversioncontrol_restore` modular input name on the remote (or local) system where the restore occurs
- `splunk_vc_url` - this macro is the URL endpoint of the remote system, defaults to `https://localhost:8089/services/splunkversioncontrol_rest_restore`, you will need to change this if you have a remote instance performing the backup/restore operations, for example if you are on a search head cluster 
- `splunk_vc_timeout` - this is the time delay between triggering the remote command and waiting for the `_audit` index to catchup with a log entry to advise the command was run, if set too short the restore may fail because the `| postversioncontrolrestore` search has not appeared in the `_audit` index yet

## Troubleshooting
In some Linux OS distributions an error similar to `OPENSSL_1.0.0 not found` may appear, `os.unsetenv('LD_LIBRARY_PATH')` appears to fix this however AppInspect does not allow modification of OS environment variables.

If you have this issue please add this into the python files to workaround the problem as required
Refer to [this issue on github](https://github.com/gjanders/SplunkVersionControl/issues/3) for more details

Note that you can run this from the command line if the logs are not getting populated:

`splunk cmd splunkd print-modinput-config splunkversioncontrol_backup splunkversioncontrol_backup://<your_input_name_goes_here>`

Finally the log files are mentioned under the "Where are the logs?" section of this document

### Problems with the Splunk Version Control Restore or Splunk Version Control Backup modular input
Both inputs follow a similar validation process:
- Run a request against `<srcURL>/servicesNS/nobody/<remoteAppName>/search/jobs/export?search=makeresults` (where remoteAppName is SplunkVersionControl unless specified)
- Run the OS command (as the user running splunk) `git ls-remote <gitRepoURL>`
- If the above fails attempt to run `ssh -n -o \"BatchMode yes\" -o StrictHostKeyChecking=no <gitRepoURL>`
- If the previous step was required re-attempt the git ls-remote step again

In 7.3.0 the Splunk process will kill -9 the modular input if it takes more than 30 seconds, if this occurs you can bypass validation by updating the inputs.conf file manually

## Will this work on a search head cluster?
Yes but do not configure the modular inputs to run on the search head cluster, modular inputs run on each member at the same time which would not work well. What you want to do is configure a standalone server with the modular inputs for backup/restore and set the srcURL/destURL to the remote search head cluster member (or load balanced URL) on the REST port.

This would allow the modular inputs to run backup/restore and any customers to use the dashboard on the search head cluster member to request restoration of a knowledge object

## Can I use this application on Windows?
Yes, but there are some tricks involved as I have not yet integrated python git libraries into the application, I'm using the command line!

The first is that the SSH key is still required to access the remote repository, the VersionControl app assumes you can run git clone without a password
In my testing, the SYSTEM users SSH key directory was:
`C:\Windows\System32\config\systemprofile\.ssh`

Furthermore the `id_rsa` file within that directory had to have permissions changed on it so only the SYSTEM account had access and no one else...

Furthermore, the git/ssh command may not be in the PATH of the sytem user, and this is fine, you can use the `git_command` and `ssh_command` options to point them to your git installation directory, I installed the https://gitforwindows.org/ package into e:\temp\git, I set the two settings to:
`E:\temp\git\cmd\git.exe`
`E:\temp\Git\usr\bin\ssh.exe`

Note there is ssh in Windows 10 but it did not work with the same switches as the Unix SSH so I've used the above in testing
Furthermore I needed to use a system user command line window which I opened via:
psexec –i –s CMD 

And set the git global configuration
`git config --global user.name "John Doe"`
`git config --global user.email johndoe@example.com`


Finally, I found that the git temporary directory often fails to delete on Windows, since this is done under error conditions it should not be an issue in day to day operation, but I'd recommend using a Linux server if at all possible!

## Can I use this on a Splunk Cloud instance?

This application, no. But this application can be used to backup a SplunkCloud instance from a remote Splunk instance, the same remote instance could also be used to restore to the SplunkCloud instance.

To do this you will need to install Version Control For SplunkCloud on your SplunkCloud instance, and setup this application on a remote instance configuring an interval for both the Splunk Version Control Backup and Splunk Version Control Restore modular inputs

## SplunkBase Link
[VersionControl For Splunk](https://splunkbase.splunk.com/app/4355)

[VersionControl For SplunkCloud (stripped down version of this app for SplunkCloud)](https://splunkbase.splunk.com/app/5061)

## Github Links
[SplunkVersionControl github](https://github.com/gjanders/SplunkVersionControl)

[SplunkVersionControlCloud github](https://github.com/gjanders/SplunkVersionControlCloud)

## Release Notes 
### 1.1.6
Allow the backup process to run on search head clusters for those that wish to do this...

### 1.1.5
Minor update so that the gitTempDir refers to the correct directory and not a sub-directory

### 1.1.4
Created inputs.conf to pass app inspect and force python 3 by default

### 1.1.3
password: syntax did not work if using a dynamic/REST based restore, now supported

### 1.1.2
Found a bug that stops this running on Splunk 8 / python 3

### 1.1.1
Corrected useLocalAuth setting so that it works as expected

Corrected imports so that post version control method works as well as the cloud version

### 1.1.0
Now tested on Windows and Splunk Cloud (note this version of the app is not installed on SplunkCloud, the VersionControl for SplunkCloud is the app to install on the SplunkCloud instance, this variation of the app includes only what is required to remotely backup/restore a SplunkCloud instance

This app is still used for SplunkCloud instances, but this app is installed on-prem

Updates include:
- Updated python SDK to 1.6.13
- New options in both backup & restore so that you can specify the location of the git / SSH command
- The ability to only backup particular apps by default rather than to backup all and rely on an exclusion list (appsList)
- Support for passwords.conf instead of plain text passwords
- Proxy support
- Re-wrote the runOSProcess function so that it works on Windows as expected

The README.md has had various updates including more details around setup and how this was tested on Windows

### 1.0.12
Fixed missing sys import from `splunkversioncontrol_rest_restore.py`
Updated README.md instructions 
Updated python SDK to version 1.6.12
Updated inputs.conf.spec and restmap.conf to specify python3 as the default version to pass appinspect

### 1.0.11
Corrected errors in the import of the six library which stopped this from working
Minor updates to README.md

### 1.0.10
Changed import to use local Splunk python SDK to ensure this works on older Splunk versions
Added the (experimental) apps list option to attempt to make this work with Splunk Cloud instances 

### 1.0.9
Version 1.0.8 caused an issue where the checkpoint file stopped getting created, fixed in this version

### 1.0.8
1.0.8 has Splunk 8 / python 3 changes only

### 1.0.7
This version has a few major changes:
- Restoration immediately after clicking the restore button rather than using lookup files
- The previous lookup file method remains supported (in fact the `splunkversioncontrol_restore` modular input must still exist, it is not required to run on a schedule
- Changes to the way the OS processes are executed in python which makes it more reliable during validation of the modular inputs
- Improved logging, in particular relating to the validation procedure

The new dashboard `splunkversioncontrol_restore_dynamic` which is now the default dashboard is an alternative to the `splunkversioncontrol_restore` dashboard which remains lookup based (the latter dashboard assumes the `splunkversioncontrol_restore` modular input is running on a schedule

Note that if you are running this app on a search head cluster, and restoring from a different server you may wish to remove the:
- `web.conf`
- `restmap.conf`

Files from the default directory, this removes the ability to trigger a restore by hitting a REST endpoint without authentication

### 1.0.6
Dashboard backups no longer include version attribute (appears on some dashboards and prevents restoration)
Updated README.md to include an installation and troubleshooting guide

### 1.0.5
Correct lastRunEpoch (as per fix in 1.0.3) for macros

### 1.0.4
Minor changes to the code to wipe the git directory re-clone on failure in both the clone failure & checkout master / git pull scenarios

### 1.0.3
Fix so that the first run does not fail due to the lastRunEpoch been set to None

Minor log improvement for when the saved searches do not work as expected

### 1.0.2
Minor tweak to logging to ensure timezones are handled when logging updated objects

### 1.0.1
Minor changes to log when an object has an updated timestamp newer than the last epoch value (this logs objects that have a newer timestamp since last run)

### 1.0.0
Improvements to logging for git related errors and auto-wipe of the git repo on failure (this handles corruption of git repos on disk)

### 0.0.7
Change of app icons only, no functional changes

### 0.0.6
Added the `sort_keys` option into the python code, this should ensure the output files for git are in a consistent order (previously random). 

The goal is to reduce the git repository size increase over time

Added Troubleshooting section in details/README.md about "OPENSSL not found" issues on Ubuntu
