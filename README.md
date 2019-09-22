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

# Supported Crypto Objects

- X.509 certificates in DER format
- RSA PKCS1 in DER format
- RSA PKCS8 unencrypted in DER format
- DH parameters in DER format
- DSA parameters in DER format

# Build

Create a folder for the build

```shell
mkdir build
```

Generate a Makefile file with cmake

```shell
cd build
cmake ..
```

Build the library and the command line tool

```shell
make
```

To cross compile, the cross compiler may be set with the following cmake option:

```shell
cmake -D C_CROSS_COMPILER=<path/to/cross/compiler> ..
```

To disable building the command line tool use the following cmake option:

```shell
cmake -D CMD_LINE_TOOL=NO ..
```

**WARNING** : The command line tool uses the C standard Library. Make sure that you have the C standard library if the command line tool is not disabled. 

**INFO** : If the command line tool is disabled, The C standard library is not needed as the library is idependent of external and third party libraries.

# Use The Crypto Parser Command Line Tool

```
usage:
crypto_parser -o <x509Cert|rsaPubKey|rsaPrivKey|dhParam|dsaParam> -f <file.der>
-o   specify the crypto object type, it could be one of the following values
     x509Cert|rsaPubKey|rsaPrivKey|dhParam|dsaParam
-f   specify the file to parse in DER format
```
