# ndnph-ndncertclient

Here are some example transactions using CA implementation from NDNts `@ndn/keychain-cli` package.

## "nop" challenge

```bash
export NDNTS_KEYCHAIN=/tmp/ca-keychain
export NDNTS_NFDREG=1
export NDNPH_KEYCHAIN=/tmp/req-keychain
nfd-start
# The CA host must have NFD.
# If the client is on a different host, use NDNPH_UPLINK_UDP environ to connect to the NFD
# on the CA host, or install NFD locally and add routes for /authority and /requester prefixes.

# generate CA key
CACERT=$(ndntssec gen-key /authority)

# make CA profile
ndntssec ndncert03-make-profile --out /tmp/ca.data --prefix /authority/CA --cert $CACERT --valid-days 60

# start CA with "nop" challenge
ndntssec ndncert03-ca --profile /tmp/ca.data --store /tmp/ca-repo --challenge nop

# generate key pair
ndnph-keychain keygen k0 /requester/0 >/dev/null

# request certificate via NDNCERT
ndnph-ndncertclient -P /tmp/ca.data -i k0 >/tmp/k0-cert.data

# import and display the certificate
ndnph-keychain certimport k0 </tmp/k0-cert.data
ndnph-keychain certinfo k0
```

## "possession" challenge

```bash
# first complete all steps in the "nop" challenge

# start CA with "possession" challenge, accepting existing certificates issued by the same CA
ndntssec ndncert03-ca --profile /tmp/ca.data --store /tmp/ca-repo --challenge possession

# generate key pair
ndnph-keychain keygen k1 /requester/1 >/dev/null

# request certificate via NDNCERT
ndnph-ndncertclient -P /tmp/ca.data -i k1 -E k0 >/tmp/k1-cert.data

# import and display the certificate
ndnph-keychain certimport k1 </tmp/k1-cert.data
ndnph-keychain certinfo k1
```
