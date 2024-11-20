#!/bin/bash

EASY_RSA_BIN="/usr/bin/easyrsa"

# duplicate the binary into the current directory
cp ${EASY_RSA_BIN} ./easyrsa_modified

# change the -passin argument to -passin stdin so that we can pass the passphrase through stdin
sed -i '/# sign request/,/verbose "sign_req: signed cert '\''$file_name_base'\'' OK"/s/${EASYRSA_PASSIN:+ -passin "$EASYRSA_PASSIN"}/-passin stdin/' ./easyrsa_modified

if [ "$(grep -c '\-passin stdin' ./easyrsa_modified)" -eq 1 ]; then
    echo "success"
else
    echo "fail"
fi
