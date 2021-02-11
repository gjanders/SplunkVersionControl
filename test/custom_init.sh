set -e
sudo microdnf install git
sudo -u splunk  mkdir -p /opt/splunk/vcs/{git_tmp_backup,git_tmp_restore}
sudo -u splunk  mkdir -p /opt/splunk/vcs/backup.git
echo "dirs"
sudo -u splunk sh -c "cd /opt/splunk/vcs/backup.git && git init --bare --shared"
echo "init"
sudo -u splunk sh -c "cd /opt/splunk/vcs/ && git clone backup.git"
sudo -u splunk sh -c "git config --global user.email 'backup@example.local'"
sudo -u splunk sh -c "git config --global user.name 'BackupUser'"
echo "clone"
sudo -u splunk sh -c 'cd /opt/splunk/vcs/backup && touch test && git add test && git commit -a -m "init" && git push'
echo "file"
 
/usr/sbin/entrypoint.sh start
