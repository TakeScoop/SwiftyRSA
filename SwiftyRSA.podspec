Pod::Spec.new do |s|

  s.name         = "SwiftyRSA"
  s.version      = "0.0.3"
  s.summary      = "Public key RSA encryption in Swift."

  s.description  = <<-DESC
                   Encrypt with a RSA public key, decrypt with a RSA private key.
                   DESC

  s.homepage     = "https://github.com/TakeScoop/SwiftyRSA"
  s.license      = "MIT"
  s.author       = { "Scoop" => "ops@takescoop.com" }

  s.source       = { :git => "https://github.com/TakeScoop/SwiftyRSA.git", :tag => "0.1.0" }
  s.source_files = "SwiftyRSA/SwiftyRSA.swift"
  s.framework    = "Security"

  s.requires_arc = true
  s.osx.deployment_target = "10.9"
  s.ios.deployment_target = "8.0"

end
