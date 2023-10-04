# Creating a Root Certificate Authority using a YubiKey

This guide details how to use yubca to initialize a Root Certificate Authority (CA) using your YubiKey like a hardware security module (HSM), where the private key never leaves the YubiKey.

You will need:
* yubca [installed](https://github.com/jamescun/yubca/releases)
* a YubiKey 4+


## Step 1: Create the configuration file

The first step is to configure yubca itself with the parameters it will use to build your certificate authority, this is done with a JSON configuration file.

By default, yubca will look for a configuration file called `ca.json` in the current working directory. This can be changed using the `--config` command line flag.

This file configures things such as the slot on your YubiKey where the certificate/private key will be stored, the algorithm of the private key, the subject of the certificate, it's expiry and optionally it's certificate revocation lists.

Options:
* `slot`: this configures where on the YubiKey to store your certificate authority. generally there will be 4 slots (9a, 9c, 9d and 9e).
* `algorithm`: this configures the private key algorithm of your certificate authority. one of EC256, EC384, ED25519, RSA1024 or RSA2048.
* `subject`: this configures the destinguished name of your certificate authority to identify it to clients (only `CN` is required):
  * `C`: configures one-or-more countries for the certificate.
  * `O`: configures one-or-more organizations for the certificate.
  * `OU`: configures one-or-more organizational units for the certificate.
  * `ST`: configures one-or-more state or province for the certificate.
  * `L`: configures one-or-more locality for the certificate.
  * `CN`: configures the common name for the certificate (required).
* `validity`: this configures when your certificate authority will expire relative to when it is created. can be specified in ns, ms, s, m or h.
* `crl`: this optionally configures one-or-more URLs where clients can download certificate revocation lists.

### Example

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


## Step 2: Initialize your Root Certificate Authority

Once the configuration file exists, yubca can initialize the slot on your YubiKey with the private key and subsequently generate the root certificate authority with it.

```sh
yubca init
```

You will be prompted to enter the management key for your YubiKey, either input this or hit enter to use the default value.

You will also be prompted to enter the PIN for your YubiKey, either input this or hit enter to use the default value.

Lastly, you will need to touch your YubiKey to authorize the signing operation.

If a certificate authority already exists in this slot, either select a different slot or delete the existing one with `yubca delete`.


## Step 3: Export your Root Certificate Authority

Lastly, we need to export our certificate authority's own certificate to deploy elsewhere to verify the certificates it signs.

```sh
yubca export --ca
```

The above command will output the PEM-encoded version of your certificate authority to your console.

You can either copy/paste this to wherever you want to store it, or use something like `tee` to write it to a file:

```sh
yubca export --ca | tee root.pem
```

And you're done! You now have your very own Root Certificate Authority that can be used to build your very own Public Key Infrastructure (PKI)!

Please take a look at the other guides to see how to sign leaf certificates or intermediaries.
