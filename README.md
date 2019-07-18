# Splunk Version Control

## What does this app do?

This app allows you to back up and use version control to manage your Splunk knowledge objects, such as saved searches and macros.

## Why?
Splunk (as of the time of writing in January 2019) has no native ability to use version control on its knowledge objects. This can lead to issues where an object is accidentally changed or deleted and there is no way to restore them beyond using OS-level backups, which are difficult to use in a search head cluster.

## How does the app function?

The app uses two modular inputs to back up and restore configurations, Splunk Version Control Backup (or splunkversioncontrol_backup) and and Splunk Version Control Restore (or splunkversioncontrol_restore). 

The backup portion of the app provides a Splunk modular input with the ability to serialize various Splunk knowledge objects into JSON format, which is then stored in a remote git repository and tagged based on each change to the backup.

These two inputs do not have to be on the same machine, however, they must be pointing to the same git repository and the gitTempDir must be unique on the filesystem if sharing the same machine.

The restore portion provides a Splunk modular input and a dashboard (SplunkVersionControl Restore) that can be used to request the restoration of a knowledge object.

## How do I restore a knowledge object?

Use the SplunkVersionControl Restore dashboard to request that a knowledge object be restored to a prior version. You must be the author of the knowledge objects you wish to restore, or have the admin role. The application with the knowledge object in it must still exist on the Splunk server.

When a knowledge object restore is requested the dashboard (SplunkVersionControl Restore) outputs the knowledge object information to a lookup with the definition splunkversioncontrol_restorelist. The modular input then triggers the restore based on the contents of this lookup, the modular input either creates or updates the knowledge object with the requested git tag, or logs the failure to find the object in the logs.

## Security Concerns
The ability to restore/create configuration opens up a few obvious issues:
- What if the lookup file storing the list of objects to restore and the user who is performing the restoration is manually edited to add additional rows?
- What if a user attempts to restore the objects of another user?
- What if a user attempts to restore an object but re-own it to a different user?

To address these issues, a report named "SplunkVersionControl Audit Query" runs a query against the audit logs to determine if the lookup was updated by the saved search "SplunkVersionControl AddToLookup". This audit query returns a username and a time (it looks back/forwards one second from when the lookup was created).

The restoration script then validates that the username entered in the lookup file and the time match those found in the audit log. If they do not match then the restoration is rejected.

If a user attempts to restore the objects of another user, or attempts to restore the objects as a different user, this is allowed if the user has the admin role (which is determined by the saved search "SplunkVersionControl CheckAdmin").

## What is required for this application to work with a remote git repository?
The following assumptions are made:
- git is accessible on the command line, this has been tested on Linux only
- git is using an SSH-based URL and the remote git repository allows the machine running the SplunkVersionControl application to remotely access the repository without a username/password prompt (i.e. SSH keys are in use)

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

The tags are recorded by outputting the tag list into the lookup definition splunkversioncontrol_taglist within the app, this same lookup definition is read by the dashboard to list available tags to restore from.

## How will the restore work?
The restoration is based on a git tag, the relevant tag is checked out on the filesystem after running a git checkout master; git pull command.

Once checked out, the app/user/global directories are checked (depending on which scope was requested) to see if there is a relevant config item to restore, if found the remote object is either updated with the contents of git or created if it does not exist. By default the knowledge object is created with the same username that was in the backup, however there is an option on the SplunkVersionControl Restore dashboard to override the user on restoration, this is only able to be done by a user with an admin role.

## What other lookup files are used by the app?
- splunkversioncontrol_lastrunepoch, this lookup definition records the last backup run for this particular Splunk instance
- splunkversioncontrol_globalexclusionlist, this lookup definition records a list of excluded applications
- splunkversioncontrol_restorelist, this lookup definition records what must be restored by the restore modular input
- splunkversioncontrol_taglist, this lookup definition records the tags available in git

## Where are the logs?
On a Linux-based system
/opt/splunk/var/log/splunk/splunkversioncontrol_restore.log
/opt/splunk/var/log/splunk/splunkversioncontrol_backup.log

Or the internal index which also has these log files

## Troubleshooting
In some Linux OS distributions an error similar to `OPENSSL_1.0.0 not found` may appear, `os.unsetenv('LD_LIBRARY_PATH')` appears to fix this however AppInspect does not allow modification of OS environment variables.

If you have this issue please add this into the python files to workaround the problem as required
Refer to [this issue on github](https://github.com/gjanders/SplunkVersionControl/issues/3) for more details

## Will this work on a search head cluster?
No, modular inputs run on each member at the same time which would not work well...however you can use a standalone server to backup/restore to a search head cluster.
You could also run the input on a single search head cluster member but this is not a recommended solution

## SplunkBase Link
[VersionControl For Splunk](https://splunkbase.splunk.com/app/4355)

## Release Notes 
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
Added the sort_keys option into the python code, this should ensure the output files for git are in a consistent order (previously random). 

The goal is to reduce the git repository size increase over time

Added Troubleshooting section in details/README.md about "OPENSSL not found" issues on Ubuntu
