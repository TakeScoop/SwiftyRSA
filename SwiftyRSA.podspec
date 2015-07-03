Pod::Spec.new do |s|

  s.name         = "SwiftyRSA"
  s.version      = "0.0.1"
  s.summary      = "Public key RSA encryption in Swift."

  s.description  = <<-DESC
                   Encrypt with a RSA public key, decrypt with a RSA private key.
                   DESC

  s.homepage     = "https://github.com/TakeScoop/SwiftyRSA"
  s.license      = "MIT"
  s.author       = { "Loïs Di Qual" => "lois@takescoop.com" }

  s.source       = { :git => "git@github.com:TakeScoop/SwiftyRSA.git" }
  s.source_files = "SwiftyRSA/SwiftyRSA.swift"
  s.framework    = "Security"

  s.platform     = :ios, "8.0"

end
