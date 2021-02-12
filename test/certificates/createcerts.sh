set -e

if [ $# -ne 3 ]
  then
      cat <<EOF
Usage: $0 DNS_NAME IP (server_cert|usr_cert)

Example:
  $0 searchhead.example.local 192.0.2.2 server_cert
EOF
exit 1
fi

HOSTNAME=$1
IP=$2
CRT_TYPE=$3

KEYOUT=$1.key
CSR=$1.csr
CERT=$1.crt
COMBINED=$1.pem

#  -config <(cat openssl.conf) \
#    <(printf "[SAN]\nsubjectAltName='DNS.1:${HOSTNAME},IP.1:${IP}'")


openssl req \
  -newkey rsa:4096 \
  -nodes \
  -keyout ${KEYOUT} \
  -out ${CSR} \
  -config <(
cat <<-EOF
[req]
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[ dn ]
C=CH
O=Lab
OU=IT
CN=${HOSTNAME}

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1=${HOSTNAME}
IP.1=${IP}
EOF
)

dir=./castuff
mkdir -p $dir/newcerts
mkdir -p $dir/crl
mkdir -p $dir/certs
[ ! -f $dir/serial ] && echo 1000 > $dir/serial
[ ! -f $dir/index.txt ] && touch $dir/index.txt
# SIGN Request
openssl ca \
  -in ${CSR} \
  -out ${CERT} \
  -extensions ${CRT_TYPE} \
  -config <(
cat <<-EOF
[ ca ]
default_ca = CA_default
[ CA_default ]
copy_extensions   = copy
dir               = .
certs             = $dir/certs
crl_dir           = $dir/crl
new_certs_dir     = $dir/newcerts
database          = $dir/index.txt
serial            = $dir/serial
RANDFILE          = $dir/private/.rand

private_key       = ./ca.key
certificate       = ./ca.crt

crlnumber         = $dir/crlnumber
crl               = $dir/crl/ca.crl.pem
crl_extensions    = crl_ext
default_crl_days  = 30

# SHA-1 is deprecated, so use SHA-2 instead.
default_md        = sha256

name_opt          = ca_default
cert_opt          = ca_default
default_days      = 375
preserve          = no
policy            = policy_loose
unique_subject    = no

[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ usr_cert ]
basicConstraints = CA:FALSE
nsCertType = client
nsComment = "Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, emailProtection

[ server_cert ]
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

EOF
)

cat ${CERT} ${KEYOUT} > ${COMBINED}
#rm ${CERT} ${CSR} ${KEYOUT}
