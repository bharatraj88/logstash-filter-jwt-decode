Gem::Specification.new do |s|
  s.name          = 'logstash-filter-jwt-decode'
  s.version       = '0.1.0'
  s.licenses      = ['Apache-2.0']
  s.summary       = 'Logstash filter plugin for decoding JSON Web Token (JWT)'
  s.description   = 'TODO: Write a longer description or delete this line.'
  s.homepage      = 'https://github.com/bharatraj88/logstash-filter-jwt-decode'
  s.authors       = ['Bharat Raj Arutla']
  s.email         = 'bharatraj.arutla@gmail.com'
  s.require_paths = ['lib']

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT']
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "filter" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core-plugin-api", "~> 2.0"
  s.add_development_dependency 'logstash-devutils'
  s.add_development_dependency 'jwt',"1.5.6"
end
