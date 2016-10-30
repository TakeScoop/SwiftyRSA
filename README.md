SwiftyRSA
=========

[![](https://img.shields.io/cocoapods/v/SwiftyRSA.svg)](https://cocoapods.org/pods/SwiftyRSA)
![](https://img.shields.io/badge/carthage-compatible-brightgreen.svg)
![](https://img.shields.io/cocoapods/p/SwiftyRSA.svg)
![](https://img.shields.io/badge/language-swift_3.0-brightgreen.svg)
[![](https://circleci.com/gh/TakeScoop/SwiftyRSA.png?style=shield&circle-token=03e95e0cd05dab2e159cf65d6e62de1d1d84148e)](https://circleci.com/gh/TakeScoop/SwiftyRSA)

**Public key RSA encryption in Swift.**

SwiftyRSA is used in the [Scoop](https://www.takescoop.com/) [iOS app](https://itunes.apple.com/us/app/scoop-easy-custom-carpooling/id997978145?mt=8) to encrypt driver license numbers before submitting them to Checkr through our API.

Installation
------------

### Swift 3+

With Cocoapods:

```
pod 'SwiftyRSA'
```

With Carthage:

```
github "TakeScoop/SwiftyRSA"
```

### Swift 2.3

The `swift-2.3` branch is built out of SwiftRSA 0.4.0 and is not actively maintained. If you'd like to use the latest features of SwiftyRSA, please use swift 3.0.

```
pod 'SwiftyRSA', :git => 'git@github.com:TakeScoop/SwiftyRSA.git', :branch => 'swift-2.3'
```

Quick Start
-----------

### Encrypt with a public key

```swift
let publicKey = try PublicKey(pemNamed: "public")
let clear = try ClearMessage(string: "Clear Text", using: .utf8)
let encrypted = try clear.encrypted(with: publicKey, padding: .PKCS1)

// Then you can use:
let data = encrypted.data
let base64String = encrypted.base64String
```

### Decrypt with a private key

```swift
let privateKey = try PrivateKey(pemNamed: "private")
let encrypted = try EncryptedMessage(base64Encoded: "AAA===")
let clear = try encrypted.decrypted(with: privateKey, padding: .PKCS1)

// Then you can use:
let data = clear.data
let base64String = clear.base64String
let string = clear.string(using: .utf8)
```


Advanced Usage
--------------

### Get a public/private key reference

#### With a DER file

```swift
let publicKey = try PublicKey(derNamed: "public")
let privateKey = try PublicKey(derNamed: "private")
```

#### With a PEM file

```swift
let publicKey = try PublicKey(pemNamed: "public")
let privateKey = try PublicKey(pemNamed: "private")
```

#### With a PEM string

```swift
let publicKey = try PublicKey(pemEncoded: str)
let privateKey = try PrivateKey(pemEncoded: str)
```

#### With a Base64 string

```swift
let publicKey = try PublicKey(base64Encoded: base64String)
```

#### With data

```swift
let publicKey = try PublicKey(data: data)
```

### Encrypt with a public key

```swift
let str = "Clear Text"
let clear = try ClearMessage(string: str, using: .utf8)    
let encrypted = try clear.encrypted(with: publicKey, padding: .PKCS1)

let data = encrypted.data
let base64String = encrypted.base64Encoded
```

### Decrypt with a private key

```swift
let encrypted = try EncryptedMessage(base64Encoded: base64String)
let clear = try encrypted.decrypted(with: privateKey, padding: .PKCS1)

let data = clear.data
let base64String = clear.base64Encoded
let string = try clear.string(using: .utf8)
```

### Sign with a private key

SwiftyRSA can sign data with a private key. SwiftyRSA will calculate a SHA digest of the supplied `String`/`Data` and use this to generate the digital signature.

```swift
let clear = try ClearMessage(string: "Clear Text", using: .utf8)
let signature = clear.signed(with: privateKey, digestType: .sha1)

let data = signature.data
let base64String = signature.base64String
```

### Verify with a public key

SwiftyRSA can verify digital signatures with a public key. SwiftyRSA will calculate a digest of the supplied `String`/`Data` and use this to verify the digital signature.

```swift
let signature = try Signature(base64Encoded: "AAA===")
let isSuccessful = try clear.verify(with: publicKey, signature: signature, digestType: .sha1)
```

Create public and private RSA keys
----------------------------------

Use `ssh-keygen` to generate a PEM public key and a PEM private key. SwiftyRSA also supports DER public keys.

```
$ ssh-keygen -t rsa -f ~/mykey -N ''
$ cat ~/mykey > ~/private.pem
$ ssh-keygen -f ~/mykey.pub -e -m pem > ~/public.pem
```

Your keys are now in `~/public.pem` and `~/private.pem`. Don't forget to move `~/mykey` and `~/mykey.pub` to a secure place.

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
