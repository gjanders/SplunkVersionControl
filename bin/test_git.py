from splunkversioncontrol_utility import runOSProcess, get_password
import argparse
import logging
import os

logger = logging.getLogger()

parser = argparse.ArgumentParser(description='Test GIT connectivity')
parser.add_argument('-ssh_command', help='Override SSH command if not using "ssh" if using a full path or similar', required=False)
parser.add_argument('-git_command', help='Override git command if not using "git" if using a full path or similar', required=False)
parser.add_argument('-gitRepoURL', help='Git repo URL', required=True)

args = parser.parse_args()

if args.ssh_command:
    ssh_command = args.ssh_command
else:
    ssh_command = "ssh"

if args.git_command:
    git_command = args.git_command
else:
    git_command = "git"

gitRepoURL = args.gitRepoURL

# print OS env variables just in case
print ("os environment variables: '%s'" % (os.environ))

# SSH results
(stdout, stderrout, res) = runOSProcess(ssh_command + " -n -o \"BatchMode yes\" -o StrictHostKeyChecking=no " + args.gitRepoURL[:args.gitRepoURL.find(":")], logger)
print("%s -n -o \"Batchmode yes\" -o StrictHostKeyChecking=no results in: stdout: '%s', stderrout: '%s', res: '%s'" % (ssh_command, stdout, stderrout, res))

(stdout, stderr, res) = runOSProcess("%s ls-remote %s" % (git_command, gitRepoURL), logger)
print("%s ls-remote %s results in stdout: '%s', stderrout: '%s', res: '%s'" % (git_command, gitRepoURL, stdout, stderrout, res))
