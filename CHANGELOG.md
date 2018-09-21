SwiftyRSA Changelog
===================

# [master]

# [1.5.0]

 - Made compatible with Swift 4.2 and Xcode 10
 - Fixed a potential crash when building dictionaries with `CFString` values
   [#107](https://github.com/TakeScoop/SwiftyRSA/issues/107)
- Fixed getting `SwiftyRSA.SwiftyRSAError.keyAddFailed(-50)` error when the device is locked on iOS 8 / 9.

# [1.4.0]

 - Fixed compilation warnings for Xcode 9.1 / 9.2.
 - Added support for Swift 4.1 and Xcode 9.3.
 - Added ability to generate a RSA key pair by using `SwiftyRSA.generateRSAKeyPair`.
   [#106](https://github.com/TakeScoop/SwiftyRSA/issues/106)

# [1.3.0]

 - Added Swift 3.2 and 4.0 support.
 - SwiftyRSAError is now exposed as an enum so that it can be introspected.
   [#68](https://github.com/TakeScoop/SwiftyRSA/issues/68)

# [1.2.0]

 - **Breaking**: SwiftyRSA ObjC was refactored under the hood to offer a better experience with both Swift and ObjC runtimes. To use SwiftyRSA with Objective-C use the following pod:

   ```
   pod 'SwiftyRSA/ObjC'
   ```

    - Other methods of integration – like Carthage – are unaffected.
    - In Swift, `ClearMessage.verify` now returns a boolean instead of a `VerificationResult`.
 
 - Fixed an issue that prevented private keys from loading if they contained an ASN1 header.
   [#71](https://github.com/TakeScoop/SwiftyRSA/issues/71)
 - Fixed an issue that prevented public/private keys from loading if their integers were represented with an Octet String ASN1 node.
   [#70](https://github.com/TakeScoop/SwiftyRSA/issues/70)

# [1.1.1]

 - Fixed Carthage integration by running SwiftLint only if it exists in a Pods directory.
   [#66](https://github.com/TakeScoop/SwiftyRSA/issues/66)
   [#65](https://github.com/TakeScoop/SwiftyRSA/issues/65)
   
# [1.1.0]

 - `PublicKey` and `PrivateKey` now expose their keychain reference and the data they were created with, in the `reference` and `originalData` fields.
   [#60](https://github.com/TakeScoop/SwiftyRSA/issues/60)
 - `PublicKey` and `PrivateKey` now have a method `data()` which returns the key data as exported by the keychain.
	[#60](https://github.com/TakeScoop/SwiftyRSA/issues/60)
 - `PublicKey` and `PrivateKey` now can be exported to PEM via the `pemString()` method, or base64 via the `base64String()` method.
   [#60](https://github.com/TakeScoop/SwiftyRSA/issues/60)
 - `PublicKey` and `PrivateKey` now can be created from a `SecKey` reference.
   [#48](https://github.com/TakeScoop/SwiftyRSA/issues/48)
 - Fixed a bug that would pass a wrong bit size to `SecKeyCreateWithData` on iOS 10+.
   [https://github.com/TakeScoop/SwiftyRSA/issues/58](#58)

# [1.0.0]

### Breaking changes

For its 1.0 version, SwiftyRSA is getting an architecture overhaul to ensure separation of concerns and code clarity. We're introducing the following classes:

 - `PublicKey/PrivateKey` allow to extract a key from a PEM/DER/base64 string and now includes helpers like `PublicKey(pemNamed: "public")`.
 - `ClearMessage/EncryptedMessage` represents a clear or encrypted message to process through the RSA algorithm.
 - `Signature` represents a message's signature that can be verified with a public key.

We recommend to check out the new [usage instructions](./README.md) to migrate code from `0.x` versions of SwiftyRSA.

# [0.5.0]

 - Migrated source code to Swift 3.0
 - Don't reduce maxmim blocksize when padding is `None` [#29](https://github.com/TakeScoop/SwiftyRSA/issues/29)

# [0.4.0]

 - Add support for SHA2 (224,256,384 & 512 bits) digest algorithms
 - `verifySHA1SignatureData` & `signSHA1Digest` are now deprecated; use `verifySignature()`
   and `signDigest()`
 - Objective-C sign & verification functions now require a `digestMethod:` parameter
 - Added support to read multiple keys from an input file using `publicKeysFromString()`.
	[#22](https://github.com/TakeScoop/SwiftyRSA/pull/22)
 - Added WatchOS and tvOS support.
   [#23](https://github.com/TakeScoop/SwiftyRSA/pull/23)

# [0.3.0]

 - Added digital signature creation & verification support.
 [#7](https://github.com/TakeScoop/SwiftyRSA/pull/7)

# [0.2.1]

 - Fixed compiler warnings for Carthage.
	[#8](https://github.com/TakeScoop/SwiftyRSA/issues/8)
 - Added Carthage support.
   [#3](https://github.com/TakeScoop/SwiftyRSA/issues/3)

# [0.2.0]

 - Added NSData encryption/decryption.
 - Fixed a bug where SwiftyRSA couldn't encrypt/decrypt data which length was bigger than the RSA key block size.
   [#6](https://github.com/TakeScoop/SwiftyRSA/issues/6)
 - Added support for headerless RSA public keys, improved public key header parsing function.
   [#2](https://github.com/TakeScoop/SwiftyRSA/issues/2)
 - Added Objective-C support.
 - Added instructions to create public/private keys using `ssh-keygen`.
 - Fixed swift 3 compiler warnings.
   [#4](https://github.com/TakeScoop/SwiftyRSA/issues/4)
 - SwiftyRSA is now unit tested on each commit with Travis CI.
 - Unit tests now run against the SwiftyRSA framework, and not the actual sources, which makes sure all required methods are public.

# [0.1.0]

Initial release.

[master]: https://github.com/TakeScoop/SwiftyRSA/tree/master
[1.5.0]: https://github.com/TakeScoop/SwiftyRSA/releases/tag/1.5.0
[1.4.0]: https://github.com/TakeScoop/SwiftyRSA/releases/tag/1.4.0
[1.3.0]: https://github.com/TakeScoop/SwiftyRSA/releases/tag/1.3.0
[1.2.0]: https://github.com/TakeScoop/SwiftyRSA/releases/tag/1.2.0
[1.1.1]: https://github.com/TakeScoop/SwiftyRSA/releases/tag/1.1.1
[1.1.0]: https://github.com/TakeScoop/SwiftyRSA/releases/tag/1.1.0
[1.0.0]: https://github.com/TakeScoop/SwiftyRSA/releases/tag/1.0.0
[0.5.0]: https://github.com/TakeScoop/SwiftyRSA/releases/tag/0.5.0
[0.4.0]: https://github.com/TakeScoop/SwiftyRSA/releases/tag/0.4.0
[0.3.0]: https://github.com/TakeScoop/SwiftyRSA/releases/tag/0.3.0
[0.2.1]: https://github.com/TakeScoop/SwiftyRSA/releases/tag/0.2.1
[0.2.0]: https://github.com/TakeScoop/SwiftyRSA/releases/tag/0.2.0
[0.1.0]: https://github.com/TakeScoop/SwiftyRSA/releases/tag/0.1.0
