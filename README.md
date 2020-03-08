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

## What is required for this application to work with a remote git repository?
The following assumptions are made:
- git is accessible on the command line, this has been tested on Linux only
- git is using an SSH-based URL and the remote git repository allows the machine running the SplunkVersionControl application to remotely access the repository without a username/password prompt (i.e. SSH keys are in use)
- git will work from the user running the Splunk process over SSH, note that on Windows this will be the system account by default, on Linux the splunk user

## Do the modular input backup and restore tasks need to be on the same Splunk instance?
No. However, the backup/restore modular input must have access to its own git temporary directory on the OS filesystem.

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
- `splunkversioncontrol_restorelist`, this lookup definition records what must be restored by the restore modular input
- `splunkversioncontrol_taglist`, this lookup definition records the tags available in git

## Where are the logs?
On a Linux-based system
- `/opt/splunk/var/log/splunk/splunkversioncontrol_restore.log` -- this log will contain information about the splunk restore modular input
- `/opt/splunk/var/log/splunk/splunkversioncontrol_backup.log` -- this log will contain information about the splunk backup modular input
- `/opt/splunk/var/log/splunk/splunkversioncontrol_postversioncontrolrestore.log` -- this log contains information about the | postversioncontrol command
- `/opt/splunk/var/log/splunk/splunkversioncontrol_rest_restore.log` -- log log contains information about hits to the REST endpoint `/services/splunkversioncontrol_rest_restore`

Or the internal index which also has these log files

## Installation guide
- If running on a search head cluster or not running the modular inputs on the local instance, install the SplunkVersionControl app on the remote search head or search head cluster first
- Create a new git repo and initialise the repo (it can have a README or can it be empty, but it must be at a point where the master branch exists)
- The server doing the git backup must have SSH access to the repo without a username/password (in other words you need to have the SSH key setup so a git clone/git checkout/git push) all work without a prompt for credentials as the OS user running Splunk (as the modular input will run as this user)
- If running on a standalone server the modular inputs can be configured either on the current standalone server, or another remote server, the app will work either way
- If running on a search head cluster, the modular input must run on a standalone Splunk instance (non-clustered)
- If errors are seen when creating the modular inputs see the troubleshooting below, or raise a question on SplunkAnswers for assistance
- If you are running the newer `splunkversioncontrol_restore_dynamic` dashboard the macros `splunk_vc_name`, `splunk_vc_url`, `splunk_vc_timeout` may need customisation to match your environment 

## Macros
The following macros exist and are relate to the `splunkversioncontrol_restore_dynamic` dashboard
- `splunk_vc_name` - this macro is the name of the `splunkversioncontrol_restore` modular input name on the remote (or local) system where the restore occurs
- `splunk_vc_url` - this macro is the URL endpoint of the remote system, defaults to `https://localhost:8089/services/splunkversioncontrol_rest_restore` 
- `splunk_vc_timeout` - this is the time delay between triggering the remote command and waiting for the `_audit` index to catchup with a log entry to advise the command was run, if set too short the restore may fail because the `| postversioncontrolrestore` search has not appeared in the `_audit` index yet

## Troubleshooting
In some Linux OS distributions an error similar to `OPENSSL_1.0.0 not found` may appear, `os.unsetenv('LD_LIBRARY_PATH')` appears to fix this however AppInspect does not allow modification of OS environment variables.

If you have this issue please add this into the python files to workaround the problem as required
Refer to [this issue on github](https://github.com/gjanders/SplunkVersionControl/issues/3) for more details

### Problems with the Splunk Version Control Restore or Splunk Version Control Backup modular input
Both inputs follow a similar validation process:
- Run a request against `<srcURL>/servicesNS/nobody/<remoteAppName>/search/jobs/export?search=makeresults` (where remoteAppName is SplunkVersionControl unless specified)
- Run the OS command (as the user running splunk) `git ls-remote <gitRepoURL>`
- If the above fails attempt to run `ssh -n -o \"BatchMode yes\" -o StrictHostKeyChecking=no <gitRepoURL>`
- If the previous step was required re-attempt the git ls-remote step again

In 7.3.0 the Splunk process will kill -9 the modular input if it takes more than 30 seconds, if this occurs you can bypass validation by updating the inputs.conf file manually

## Will this work on a search head cluster?
No, modular inputs run on each member at the same time which would not work well...however you can use a standalone server to backup/restore to a search head cluster.
You could also run the input on a single search head cluster member but this is not a recommended solution

## SplunkBase Link
[VersionControl For Splunk](https://splunkbase.splunk.com/app/4355)

## Release Notes 
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
