# yubca

yubca is a utility to operate a certificate authority from a YubiKey.

## Install

Either [download a pre-compiled binary](https://github.com/jamescun/yubca/releases), or build from source:

```sh
go install github.com/jamescun/yubca@latest
```

## Usage

To get started, you need to create a configuration file that specifies the shape of your Certificate Authority. This includes it's distinguished name and future certificate revocation URLs.

In this example, we'll create `ca.json` with some dummy values. Feel free to update these to your use case.

```json
{
  "slot": "9a",
  "algorithm": "EC256",
  "subject": {
    "C": [ "GB" ],
    "O": [ "ACME Limited" ],
    "CN": "Root EC1"
  },
  "validity": "87600h",
  "crl": [ "http://example.org/ec1.crl" ]
}
```

The above config will initialize a root Certificate Authority on slot 9a (authentication) on your YubiKey, if one doesn't already exist. It will use the P-256 elliptic curve algorithm and the subject `C=GB, O=ACME Limited, CN=Root EC1`. It will be valid for 10 years, and also will optionally include a URL to a Certificate Revocation List (CRL).

To apply this configuration, run:

```sh
yubca init --config ca.json
```
If successful, you will now be able to inspect your Certificate Authority:

```sh
yubca inspect --config ca.json
```

This will output metadata about your Certificate Authority.

To export your Certificate Authority or it's Public Key, run:

```sh
yubca export --config ca.json --ca --public-key
```

This will export the PEM-encoded version of your Certificate Authority and/or it's Public Key.

To sign a Certificate Signing Request (CSR) using your Certificate Authority, run:

```sh
yubca sign --config ca.json --csr csr.pem --server
```

This will return the PEM-encoded certificate in response to the CSR signed by your Certificate Authority.

You may also include `--ca` to sign an intermediate Certificate Authority, or `--server` or `--client` to enable Server or Client certificate usage.
