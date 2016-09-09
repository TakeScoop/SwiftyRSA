Pod::Spec.new do |s|

  s.name         = "SwiftyRSA"
  s.version      = "0.4.0"
  s.summary      = "Public key RSA encryption in Swift."

  s.description  = <<-DESC
                   Encrypt with a RSA public key, decrypt with a RSA private key.
                   DESC

  s.homepage     = "https://github.com/TakeScoop/SwiftyRSA"
  s.license      = "MIT"
  s.author       = { "Scoop" => "ops@takescoop.com" }

  s.source       = { :git => "https://github.com/TakeScoop/SwiftyRSA.git", :tag => s.version }
  s.source_files = "SwiftyRSA/*.{swift,m,h}"
  s.framework    = "Security"

  s.requires_arc = true
  
  s.ios.deployment_target = '8.3'
  s.tvos.deployment_target = '9.2'
  s.watchos.deployment_target = '2.2'
end
