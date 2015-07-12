SwiftyRSA
=========

Public key RSA encryption in Swift.

Usage
-----

### Encrypt ###

```
// With a PEM public key
let encrypted = SwiftyRSA.encryptString(str, publicKeyPEM: pemString)

// With a DER public key
let encrypted = SwiftyRSA.encryptString(str, publicKeyDER: derData)
```

### Decrypt ###

```
let decrypted = SwiftyRSA.decryptString(str, privateKeyPEM: pemString)
```

### Advanced Usage ###

#### Get a key instance ####

Note that the key reference will only be valid as long as the `SwiftyRSA` instance is alive.

```
let rsa = SwiftyRSA()

// Public key (PEM)
let pubPath   = bundle.pathForResource("public", ofType: "pem")!
let pubString = NSString(contentsOfFile: pubPath, encoding: NSUTF8StringEncoding, error: nil)! as String
let pubKey    = rsa.publicKeyFromPEMString(pubString)!

// Public key (DER)
let pubPath = bundle.pathForResource("public", ofType: "der")!
let pubData = NSData(contentsOfFile: pubPath)!
let pubKey  = rsa.publicKeyFromDERData(pubData)!

// Private key (PEM)
let privPath   = bundle.pathForResource("private", ofType: "pem")!
let privString = NSString(contentsOfFile: privPath, encoding: NSUTF8StringEncoding, error: nil)! as String
let privKey    = rsa.privateKeyFromPEMString(privString)!
```

#### Use a key instance to encrypt/decrypt ####

```
// Encrypt
let encryptedString = rsa.encryptString(str, publicKey: pubKey)!

// Decrypt
let decryptedString = rsa.decryptString(encrypted, privateKey: privKey)!
```

Under the hood
--------------

When encrypting using a public key:

 - If the key is in PEM format, get rid of meta data and convert to NSData
 - Strip the ASN.1 data from the public key header (otherwise the keychain won't accept it)
 - Add the public key to the app keychain, with a random tag
 - Get a reference on the key using the key tag
 - Convert clear text to NSData using UTF8
 - Encrypt data with `SecKeyEncrypt` using the key reference
 - Convert the resulting data to base64 and return it
 - Delete public key from keychain using tag

When decrypting using a private key:

 - Get rid of PEM meta data and convert to NSData
 - Add the private key to the app keychain, with a random tag
 - Get a reference on the key using the key tag
 - Convert encrypted text to NSData from base64 string
 - Decrypt data with `SecKeyDecrypt` using the key reference
 - Convert the resulting data to String using UTF8
 - Delete private key from keychain using tag

Inspired from
-------------

 - <http://blog.flirble.org/2011/01/05/rsa-public-key-openssl-ios/>
 - <https://github.com/lancy/RSADemo>

License
-------

This project is copyrighted under the MIT license. Complete license can be found here: <https://github.com/TakeScoop/SwiftyRSA/blob/master/LICENSE>
