# Splunk Version Control
## Why?
Splunk (as of the time of writing in January 2019) has no ability to version control it's knowledge objects. This can lead to issues where an object is accidentally changed, or deleted and their is no restore mechanism beyond OS level backups which are difficult to utilise in a search head cluster

## What does this app do?
The backup portion of the app provides a Splunk modular input with the ability to serialize various Splunk knowledge objects into JSON format which is then stored in a remote git repository and tag'ed based on each change to the backup

The restore portion provides a Splunk modular input and a user accessible dashboard (SplunkVersionControl Restore) that can be used to request the restoration of a knowledge object, it will then either create or update the knowledge object to the requested git tag or log the failure to find the object in the logs.

## How?
Provide a Splunk modular input to backup configuration into a remote git repository (Splunk Version Control Backup or splunkversioncontrol_backup) and another input that provides restore functionality (Splunk Version Control Restore or splunkversioncontrol_restore)

Note that these two inputs do not have to be on the same machine, however they must be pointing to the same git repository and the gitTempDir must be unique on the filesystem if sharing the same machine

For the customers a dashboard is provided within the SplunkVersionControl app called "SplunkVersionControl Restore", from this dashboard any user can request restoration of a knowledge object (deleted or existing) as long as the application still exists on the server, when run this outputs the entry into the lookup definition splunkversioncontrol_restorelist

## Security Concerns
The ability to restore/create configuration opens up a few obvious issues:
- What if the lookup file storing the list of objects to restore and the user who is performing the restoration is manually edited to add additional rows?
- What if a user attempts to restore the objects of another user?
- What if a user attempts to restore an object but re-own it to a different user?

To address these issues a report named "SplunkVersionControl Audit Query" was created to run a query against the audit logs to determine if the lookup was updated by the saved search "SplunkVersionControl AddToLookup", this search returns a username and a time (it looks back/forwards one second from when the lookup was created).

The restoration script than validates that the username entered in the lookup file and the time match those found in the audit log, if they do not match then the restoration is rejected

If a user attempts to restore the objects of another user, or attempts to restore the objects as a different user, this is allowed if the user has the admin role (which is determined by the saved search "SplunkVersionControl CheckAdmin")

## What is required for this application to work with a remote git repository?
The following assumptions are made:
- git is accessible on the command line, this has been tested on Linux only
- git is using an SSH-based URL and the remote git repository allows the machine running the SplunkVersionControl application to remotely access the repository without a username/password prompt (i.e. SSH keys are in use)

## Do the modular input backup and restore tasks need to be on the same Splunk instance?
This is not a requirement, it is however a requirement that any backup/restore modular input has access to it's own git temporary directory on the OS filesystem

## When will a full application backup occur?
During the first run of the script (at which point the lookup file is empty) all applications and all objects will be backed up.

During each subsequent run of the script, if an application is found in the Splunk system but not on the filesystem then the backup of all objects will occur

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