set -e
sudo microdnf install git
sudo -u splunk  mkdir -p /opt/splunk/vcs/{git_tmp_backup,git_tmp_restore}
if [ ! -d "/opt/splunk/vcs/backup.git" ]; then
sudo -u splunk  mkdir -p /opt/splunk/vcs/backup.git
sudo -u splunk sh -c "cd /opt/splunk/vcs/backup.git && git init --bare --shared"
sudo -u splunk sh -c "cd /opt/splunk/vcs/ && git clone backup.git"
sudo -u splunk sh -c "git config --global user.email 'backup@example.local'"
sudo -u splunk sh -c "git config --global user.name 'BackupUser'"
sudo -u splunk sh -c 'cd /opt/splunk/vcs/backup && touch test && git add test && git commit -a -m "init" && git push'
fi
/usr/sbin/entrypoint.sh start
