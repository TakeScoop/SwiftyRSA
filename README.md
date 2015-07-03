SwiftyRSA
=========

Public key RSA encryption in Swift.

Usage
-----

### Add keys ###

First of all, create an instance of `SwiftyRSA`:

```
let rsa = SwiftyRSA()
```

#### Public key (PEM) ####

```
let pubPath   = bundle.pathForResource("public", ofType: "pem")!
let pubString = NSString(contentsOfFile: pubPath, encoding: NSUTF8StringEncoding, error: nil)! as String
let pubKey    = rsa.publicKeyFromPEMString(pubString)!
```

#### Public key (DER) ####

```
let rsa     = SwiftyRSA()
let pubPath = bundle.pathForResource("public", ofType: "der")!
let pubData = NSData(contentsOfFile: pubPath)!
let pubKey  = rsa.publicKeyFromDERData(pubData)!
```

#### Private key (PEM) ####

```
let privPath   = bundle.pathForResource("private", ofType: "pem")!
let privString = NSString(contentsOfFile: privPath, encoding: NSUTF8StringEncoding, error: nil)! as String
let privKey    = rsa.privateKeyFromPEMString(privString)!
```

### Encrypt ###

```
let encryptedData = rsa.encryptString(str, publicKey: pubKey)!
let encryptedString = NSString(data: encrypted, encoding: NSUTF8StringEncoding)!
```

### Decrypt ###

```
let decrypted = rsa.decryptData(encrypted, privateKey: privKey)!
let encryptedString = NSString(data: encrypted, encoding: NSUTF8StringEncoding)!
```

Inspired from
-------------

 - <http://blog.flirble.org/2011/01/05/rsa-public-key-openssl-ios/>
 - <https://github.com/lancy/RSADemo>