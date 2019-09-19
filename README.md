# Description

When you use a crypto library (e.g. OpenSSL, WolfSSL, MbedTLS, etc...) for a particular crypto operation
(e.g. RSA encryption, RSA signature, etc...) there is no doubt that you parse a crypto object
(e.g. RSA private/public key, DH parameters, etc..) before performing your crypto operation.
Most of the available and the well-known crypto libraries use dynamic memory allocation when
parsing the crypto objects. Not only that but, they depend on the C standard library as well.
In deeply embedded environments, it is not possible to perform dynamic memory allocation and
the C standard library is not available.

That's why I decided to implement a tiny crypto parser which uses only the stack, doesn't depend
on any external library (not even the C standard library!), written in native C and which is
suitable for deeply embedded environments.

# Supported crypto objects

- x509 certificates in DER format
- RSA PKCS1 in DER format
- RSA PKCS8 unencrypted in DER format
- DH parameters in DER format
- DSA parameters in DER format

# Build

Create a folder for the build

```shell
mkdir build
```

Generate the Makefile file with cmake

```shell
cd build
cmake ..
```

Build the library and the samples

```shell
make
```

# Use The Crypto Parser Command Line Tool

```
usage:
crypto_parser -o <x509Cert|rsaPubKey|rsaPrivKey|dhParam|dsaParam> -f <file.der>
-o   specify the crypto object type, it could be one of the following values
     x509Cert|rsaPubKey|rsaPrivKey|dhParam|dsaParam
-f   specify the file to parse in DER format\n
```
