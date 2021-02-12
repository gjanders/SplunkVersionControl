set -e
CA_KEY=ca.key
CA_CRT=ca.crt
SUBJ="/C=CH/ST=Bern/L=Bern/O=Example Company/CN=CA Domain1"

if [ ! -f $CA_KEY ]; then 
    openssl genrsa -out $CA_KEY 4096 
fi

if [ ! -f $CA_CRT ]; then 
    openssl req -new -x509 -key ${CA_KEY} -out ${CA_CRT} -subj "$SUBJ" -days 3000
fi

