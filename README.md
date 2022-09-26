# JWK Generator

### A C++ library for generating test jwks using OpenSSL

```c++
using namespace jwk_generator;
std::cout << JwkSetGenerator<RS512, ES384>() << std::endl;
```

```json
{"keys":[{"alg":"RS512","e":"AQAB","kid":"0cf728e4-68b3-4c4f-a6ea-01b763ff1c4c","kty":"RSA","n":"662BwB9jjVzDT8mKkV5zQnT9C_31s6Tnnv4r3Sgr4YUNAHPN0mjUQXxiJOofTdUc52RwQTKGRnci2amDV-R0sBlyUmA3L1gOz4ToSNkUiRPLvKaVZuDJcGtCpt4Bv0YUmMDHnhMOgPZRd9tfA7tS93x_iZ-z35vFInK7S7lMyi1OUXPI-gyk90BdAYT-FR4Dd6re090NlnkMfmL8ux44VTiVdjzOjQ3P5obYZIzxTprrvJVjcp5Gm9DyQjbCTnapV2vJ112l-91P9_f4DXRgEUguvmHJS_pS-vWSYn4gUITmueN23tP6XPA5PpL9Qy00GwodHQ_Jyh97w4frbTMVFw"},{"alg":"ES384","crv":"P-384","kid":"ba5efdd9-aa2a-4f43-8841-188916914d6d","kty":"EC","x":"VYY883CYVCC0oj7KYwt2rpRd613fJB0IJfB4vTii03UNJls8RiEHEhoYrFTjeMjf","y":"jJqwWbiHmSq8m6UUNb8S7dMMT0SKilaHm6qzmG09Ykgl4Gwo-Puv-sYbCp8HZP7q"}]}
```

An individual jwk can also be exported as `.pem`
```c++
using namespace jwk_generator;
JwkGenerator<ES512> jwk;
std::cout << jwk.public_to_pem() << std::endl;
std::cout << jwk.private_to_pem() << std::endl;

// or using a set:
JwkGenerator<ES512, E256> jwks;
std::cout << jwks.get<0>().public_to_pem() << std::endl;
std::cout << jwks.get<0>().private_to_pem() << std::endl;
std::cout << jwks.get<1>().public_to_pem() << std::endl;
std::cout << jwks.get<1>().private_to_pem() << std::endl;
```

Helper function to generate a lot of keys (of the same type)
```c++
using namespace jwk_generator;
auto jwks = make_jwks<ES512>(100);
std::cout << jwks << std::endl;
```

Implementations are provided for RSASSA-PKCS1-v1_5 (RSA) or ECDSA (EC) keys, according to the
[JSON Web Algorithm standard rfc7518](https://www.rfc-editor.org/rfc/rfc7518.html)

#### OpenSSL 1.1.1 or 3.0
When compiled with OpenSSL 3.0, the newer APIs will be used to avoid any deprecation warnings

Tested with gcc 11, 12 & clang 13, 14

RSA keys are hardcoded to use `2048` bits ¯\\_(ツ)_/¯

---
DO NOT USE THIS LIBRARY FOR SECURE KEY GENERATION

I wrote it for testing, and there is no guarantee that it generates keys in a secure way
---

## The main classes
* `JwkGenerator<KeySpec>`

    The `JwkGenerator` templates uses a key spec to generate a jwk. It generates the
    key according to the `KeySpec` and a jwk containing the public key info when it is
    constructed.

* `JwkSetGenerator<KeySpec...>`

    The `JwkSetGenerator` templates is very similar except it takes many key specs

* `JwkSetSingleSpecGenerator<KeySpec>`

    The `JwkSetSingleSpecGenerator` templates is very similar except it only takes a single
    type of key

### The key specs:
* `ECKey<shaBits>`, aliased as `ES256`, `ES384`, `ES512`

    The `ECDSA` key spec defines eliptic curve keys. The `shaBits` determines the curve,
    and the hashing algorithm according to [rfc7518](https://www.rfc-editor.org/rfc/rfc7518#section-3.4)

* `RSAKey<shaBits>`, aliased as `RS256`, `RS384`, `RS512`

    The `RSAKey` key spec defines an RSA key. The number bits used to generate the key
    is always 2048, and the exponent is always 65537. The `shaBits` param only changes
    the algorithm key in the generated jwk.
