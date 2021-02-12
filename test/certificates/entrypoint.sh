#!/bin/sh
set -e
echo "Starting Certificate Creation"
mkdir -p /cert_dir
cd /cert_dir
sh /scripts/createca.sh
while read -r line; do
  # Get the string before = (the var name)
  name="${line%=*}"
  eval value="\$$name"
  if [[ $name = 'CERTIFICATE'* ]]
  then
    echo "name: ${name}, value: ${value}"
    bash /scripts/createcerts.sh  ${value}
  fi
done <<EOF
$(env)
EOF


echo $(env)
