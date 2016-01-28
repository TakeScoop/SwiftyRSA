SwiftyRSA
=========

**Public key RSA encryption in Swift.**

SwiftyRSA is used in the [Scoop](https://www.takescoop.com/) [iOS app](https://itunes.apple.com/us/app/scoop-easy-custom-carpooling/id997978145?mt=8) to encrypt driver license numbers before submitting them to Checkr through our API.

Installation
------------

```
pod 'SwiftyRSA'
```

Usage
-----

### Encrypt

```
// With a PEM public key
let encrypted = try! SwiftyRSA.encryptString(str, publicKeyPEM: pemString)

// With a DER public key
let encrypted = try! SwiftyRSA.encryptString(str, publicKeyDER: derData)
```

### Decrypt

```
let decrypted = try! SwiftyRSA.decryptString(str, privateKeyPEM: pemString)
```

Advanced Usage
--------------

### Create public and private RSA keys

Use `ssh-keygen` to generate a PEM public key and a PEM private key. SwiftyRSA also supports DER public keys.

```
$ ssh-keygen -t rsa -f ~/mykey -N ''
$ cat ~/mykey > ~/private.pem
$ ssh-keygen -f ~/mykey.pub -e -m pem > ~/public.pem
```

Your keys are now in `~/public.pem` and `~/private.pem`. Don't move `~/mykey` and `~/mykey.pub` in a secure place.

### Get a key instance

Note that the key reference will only be valid as long as the `SwiftyRSA` instance is alive.

```
import SwiftyRSA

let rsa = SwiftyRSA()

// Public key (PEM)
let pubPath   = bundle.pathForResource("public", ofType: "pem")!
let pubString = NSString(contentsOfFile: pubPath, encoding: NSUTF8StringEncoding, error: nil)! as String
let pubKey    = try! rsa.publicKeyFromPEMString(pubString)

// Public key (DER)
let pubPath = bundle.pathForResource("public", ofType: "der")!
let pubData = NSData(contentsOfFile: pubPath)!
let pubKey  = try! rsa.publicKeyFromDERData(pubData)

// Private key (PEM)
let privPath   = bundle.pathForResource("private", ofType: "pem")!
let privString = NSString(contentsOfFile: privPath, encoding: NSUTF8StringEncoding, error: nil)! as String
let privKey    = try! rsa.privateKeyFromPEMString(privString)
```

### Use a key instance to encrypt/decrypt

```
// Encrypt
let encryptedString = try! rsa.encryptString(str, publicKey: pubKey)

// Decrypt
let decryptedString = try! rsa.decryptString(encrypted, privateKey: privKey)
```

### Use with Objective-C

```
@import SwiftyRSA;

NSString* str = @"ClearText";

NSBundle* bundle = [NSBundle bundleForClass:self.class];

NSString* pubPath = [bundle pathForResource:@"swiftyrsa-public" ofType:@"pem"];
NSString* pubString = [NSString stringWithContentsOfFile:pubPath encoding:NSUTF8StringEncoding error:nil];

NSString* privPath = [bundle pathForResource:@"swiftyrsa-private" ofType:@"pem"];
NSString* privString = [NSString stringWithContentsOfFile:privPath encoding:NSUTF8StringEncoding error:nil];

NSString* encrypted = [SwiftyRSA encryptString:str publicKeyPEM:pubString padding:kSecPaddingPKCS1 error:nil];
NSString* decrypted = [SwiftyRSA decryptString:encrypted privateKeyPEM:privString padding:kSecPaddingPKCS1 error:nil];
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
