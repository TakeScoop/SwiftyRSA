SwiftyRSA Changelog
===================

# [master]

 - Added Carthage support.

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

[master]: https://github.com/TakeScoop/SwiftyRSA/compare/0.2.0...master
[0.2.0]: https://github.com/TakeScoop/SwiftyRSA/releases/tag/0.2.0
[0.1.0]: https://github.com/TakeScoop/SwiftyRSA/releases/tag/0.1.0