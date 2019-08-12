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

- RSA PKCS1 in DER format
- RSA PKCS8 unencrypted in DER format
- DH parameters in DER format
- DSA parameters in DER format 
