#!/bin/bash

## Generates a complex file containing lots of private (encrypted and unencrypted), public keys,
## text between the keys, and some badly formatted keys, all as a giant test case to ensure that the
## file is parseable and tolerates nonsense outside of the `----BEGIN/END----` armor while also working
## for the most straightforward usecase(s).
##
##  Couple of examples along this line around GitHub:
## - https://github.com/chef/opscode-omnibus/blob/master/files/private-chef-ctl-commands/spec/fixtures/badkey.pub
## - https://github.com/aaossa/Computer-Security-Algorithms/blob/master/09%20-%20Insufficient%20Key%20Size/publickey.params

set -o pipefail

THISDIR=`pwd`
TEMPDIR=`mktemp -d`

## Method to ensure that the temp dir we created gets destroyed at the end of our run
cleanup_tmp_dir(){
    test -d ${TEMPDIR} && rm -rf ${TEMPDIR}
}

# Trap to cleanup the tmp dir
trap cleanup_tmp_dir       EXIT

# Move into the tmpdir
pushd ${TEMPDIR}

# Our test case filename
OUR_FILE=multiple-keys-testcase.pem

## Our totally made up password
PASS=`openssl rand 4 -hex`

# Encryption types to test
ENC_ALGOS="aes128 aes192 aes256"

# Bit sizes to test
BITSIZES="1024 2048 4096"

# Create our file
touch ${OUR_FILE}

## Generates a public/private RSA key pair of the desired encryption type and bitsize
generate_data() {
    ENC=$1
    BITS=$2
    
    TMP_PRIVATE="private.${ENC}.${BITS}.tmp.pem"
    LOCAL_FILE="output.${ENC}.${BITS}.txt"
    
    echo "--> ENC=${ENC} / BITS=${BITS}" > ${LOCAL_FILE}
    echo >> ${LOCAL_FILE}
    
    openssl genrsa -${ENC} -passout pass:${PASS} ${BITS}        >   ${TMP_PRIVATE}
    
    # Throw in the encrypted key
    cat ${TMP_PRIVATE}                                          >>  ${LOCAL_FILE}
    
    # And the unencrypted key with `-text` for more output
    openssl rsa -in ${TMP_PRIVATE} -passin pass:${PASS} -text   >>  ${LOCAL_FILE}

    # And the public key as well
    openssl rsa -in ${TMP_PRIVATE} -passin pass:${PASS} -pubout >>  ${LOCAL_FILE}
    
    echo "Interstitial text junk" >> ${LOCAL_FILE}
    echo >> ${LOCAL_FILE}
    
    cat ${LOCAL_FILE} >> ${OUR_FILE}
}

## Create all the key pairz!
for ENC in ${ENC_ALGOS}; do
    for BITS in ${BITSIZES}; do
        generate_data ${ENC} ${BITS}
    done;
done;

# Lastly, throw some armored junk in here…
cat >> ${OUR_FILE} <<EOF

-----BEGIN PUBLIC KEY-----
Garbage key!!!!
-----END PUBLIC KEY-----

-----BEGIN PRIVATE KEY-----
Garbage key!!!!
-----END PRIVATE KEY-----

-----BEGIN ENCRYPTED PRIVATE KEY-----
Garbage key!!!!
-----END ENCRYPTED PRIVATE KEY-----

EOF

popd

cp -v "${TEMPDIR}/${OUR_FILE}" .
