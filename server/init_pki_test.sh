#!/bin/bash

PASS_PHRASE="azerty"
EASY_RSA_BIN="./easyrsa_modified"

# duplicate 

# first init pki and ca
${EASY_RSA_BIN} init-pki 
${EASY_RSA_BIN} build-ca <<EOF
$PASS_PHRASE
$PASS_PHRASE

EOF

# generate server cert
echo 'server' | ${EASY_RSA_BIN} gen-req 'server' nopass 
${EASY_RSA_BIN} sign-req server server <<EOF
yes
$PASS_PHRASE
EOF