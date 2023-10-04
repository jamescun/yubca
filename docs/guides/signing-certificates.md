# Signing Certificates using your YubiKey

This guide details how to use your Root Certificate Authority stored on a YubiKey to sign certificates.

You will need:
* yubca [installed](https://github.com/jamescun/yubca/releases)
* a YubiKey 4+
* a root certificate authority initialized by yubca


## Step 1: Create a Private Key and Certificate Signing Request (CSR)

Other than the root certificate authority, yubca will not generate any certificates. They must be generated using something else, such as `openssl`, and only the Certificate Signing Request (CSR) is needed by yubca.

If you already have this, you can move on to the next step.

First, your certificate will need a private key. This should be generated close to where it will be used, and only the CSR should be copied between locations.

To generate an ECDSA P-256 private key with `openssl`, run:

```sh
openssl ecparam -genkey -name prime256v1 -noout -out key.pem
```

This will write the private key to `key.pem`. We can now generate the CSR:

```sh
openssl req -new -sha256 -key key.pem -out csr.pem
```

You'll be asked a number of questions to define the distinguished name of your certificate. The only important one is the Common Name, as this will be used by some clients to validate the hostname of your server.

This will write the CSR to `csr.pem`. This is what is needed by yubca in the next step.


## Step 2: Sign Certificate Signing Request (CSR)

Once you have generated a Certificate Signing Request (CSR), it needs to be passed to yubca.

You will be prompted to enter the PIN for your YubiKey, input this or hit enter to use the default value.

Lastly, you will need to touch your YubiKey to authorize the signing operation.

After this, the PEM-encoded certificate will be written to your console. Either copy/paste this to where you need it, or pass `--output cert.pem` to have it written to a file.

To sign a server certificate, you can run:

```sh
yubca sign --csr csr.pem --server
```

Or if you want to use the certificate for the client, such as for Mutual TLS (mTLS) authentication, use the `--client` flag:

```sh
yubca sign --csr csr.pem --client
```

### Intermediate Certificate Authority

This same process can be used to generate an Intermediate Certificate Authority.

Simply generate the Certificate Signing Request (CSR) as specified above, but pass `--ca` to the sign command:

```sh
yubca sign --csr csr.pem --ca
```

This will generate a certificate authority signed by your root certificate authority.
