SwiftyRSA
=========

![](https://img.shields.io/cocoapods/v/SwiftyRSA.svg)
![](https://img.shields.io/badge/carthage-compatible-brightgreen.svg)
![](https://img.shields.io/cocoapods/p/SwiftyRSA.svg)
![](https://img.shields.io/badge/language-swift_2\+-brightgreen.svg)
![](https://img.shields.io/travis/TakeScoop/SwiftyRSA/master.svg)

**Public key RSA encryption in Swift.**

SwiftyRSA is used in the [Scoop](https://www.takescoop.com/) [iOS app](https://itunes.apple.com/us/app/scoop-easy-custom-carpooling/id997978145?mt=8) to encrypt driver license numbers before submitting them to Checkr through our API.

Installation
------------

With Cocoapods:

```
pod 'SwiftyRSA'
```

With Carthage:

```
github "TakeScoop/SwiftyRSA"
```

Usage
-----

### Encrypt

```
// String
let encryptedString = try! SwiftyRSA.encryptString(str, publicKeyPEM: pemString)

// Data
let encryptedData = try! SwiftyRSA.encryptData(data, publicKeyPEM: pemString)

// With a DER key
let encryptedString = try! SwiftyRSA.encryptString(str, publicKeyDER: derData)
let encryptedData = try! SwiftyRSA.encryptData(data, publicKeyDER: pemString)
```

### Decrypt

```
// String
let decryptedString = try! SwiftyRSA.decryptString(str, privateKeyPEM: pemString)

// Data
let decryptedData = try! SwiftyRSA.decryptData(data, privateKeyPEM: pemString)
```

### Sign

SwiftyRSA can sign data with a private key.  SwiftyRSA will calculate an SHA1 digest
of the supplied `String`/`NSData` and use this to generate the digital signature.

```
// String
let signatureString = try! SwiftyRSA.signString(str, privateKeyPEM: pemString)

// Data
let signatureData = try! SwiftyRSA.signData(data, privateKeyPEM: pemString)
```

## Verify

SwiftyRSA can verify digital signatures with a public key.  SwiftyRSA will calculate 
a digest (default is SHA1) of the supplied `String`/`NSData` and use this to verify the digital 
signature.

```
// String
let verificationResult = try! SwiftyRSA.verifySignatureString(str, signature: sigString, publicKeyPEM: pemString)
if (verificationResult) {
    // verification was successful
}

// Data
let verificationResult = try! SwiftyRSA.verifySignatureData(data, signature: sigData, publicKeyPEM: String)
if (verificationResult) {
    // verification was successful
}

```

## Alternate digest algorithms

SHA1 is the default digest algorithm. Alternate algorithms can be specified by supplying a value for the `digestMethod` 
parameter:

```
let digestSignature = try! rsa.signData(data, privateKey: privKey, digestMethod: .SHA256)
let result = try! rsa.verifySignatureData(data, signatureData: digestSignature, publicKey: pubKey, digestMethod: .SHA256)
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

Your keys are now in `~/public.pem` and `~/private.pem`. Don't forget to move `~/mykey` and `~/mykey.pub` to a secure place.

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
let encryptedData = try! rsa.encryptData(data, publicKey: pubKey)

// Decrypt
let decryptedString = try! rsa.decryptString(str, privateKey: privKey)
let decryptedData = try! rsa.decryptData(data, privateKey: privKey)
```

### Sign or verify an existing digest

```
let rsa = SwiftyRSA()
let digestSignature = try! rsa.signDigest(digest, privateKey: privKey, digestMethod: .SHA1)

let verificationResult = try! rsa.verifySignatureData(digest, signature: digestSignature, publicKey: pubKey, digestMethod: .SHA1)
if (verificationResult) {
    // verification was successful
}
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

NSString* signature = [SwiftyRSA signString:str privateKeyPEM:privString digestMethod:DigestTypeSHA256 error:&error];
VerificationResult* result = [SwiftyRSA verifySignatureString:str signature:signature publicKeyDER:pubData digestMethod:DigestTypeSHA256 error:&error];
if (result.boolValue) {
    // verification was successful
} 

NSData* digestSignature = [rsa signData:data privateKey:privKey digestMethod:DigestTypeSHA256 error:&error];
VerificationResult* result = [rsa verifySignatureData:data signatureData:digestSignature publicKey:pubKey digestMethod:DigestTypeSHA256 error:&error];
if (result.boolValue) {
    // verification was successful
}   

NSData* digest = [data SHA256];
NSData* digestSignature = [rsa signDigest:digest privateKey:privKey digestMethod:DigestTypeSHA256 error:&error];
VerificationResult* result = [rsa verifySignatureData:digest signature:digestSignature publicKey:pubKey digestMethod:DigestTypeSHA256 error:&error];
if (result.boolValue) {
    // verification was successful
}
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
 - <https://github.com/btnguyen2k/swift-rsautils>

License
-------

This project is copyrighted under the MIT license. Complete license can be found here: <https://github.com/TakeScoop/SwiftyRSA/blob/master/LICENSE>
