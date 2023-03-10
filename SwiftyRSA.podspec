Pod::Spec.new do |s|

  s.name = "SwiftyRSA"
  s.version = "1.8.0"
  s.summary = "Public key RSA encryption in Swift."

  s.description = <<-DESC
    Encrypt with a RSA public key, decrypt with a RSA private key.
  DESC

  s.homepage = "https://github.com/TakeScoop/SwiftyRSA"
  s.license = "MIT"
  s.author = { "Scoop" => "ops@takescoop.com" }

  s.source = { :git => "https://github.com/TakeScoop/SwiftyRSA.git", :tag => s.version }
  s.source_files = "Source/*.{swift,m,h}"
  s.exclude_files = "Source/SwiftyRSA+ObjC.swift"
  s.framework = "Security"
  s.requires_arc = true

  s.swift_version = "5.0"
  s.ios.deployment_target = "10.0"
  s.tvos.deployment_target = "11.0"
  s.watchos.deployment_target = "4.3"

  s.subspec "ObjC" do |sp|
    sp.source_files = "Source/*.{swift,m,h}"
  end
end
