# Gemfile
#
# frozen_string_literal: true

# Derived from onetimesecret/onetimesecret Gemfile (2026-09-04): same
# framework line (Roda 3, Rodauth 2, rodauth-tools 0.4, Sequel 5, Ruby 3.4)
# so idioms and eventually code transfer, minus everything that belongs to
# the tenant app (Familia/Redis, Otto, RabbitMQ, Stripe, OmniAuth, Vue).
#
# Rodauth Admin is a server-rendered Roda app over the production authdb.
# The gem set is deliberately small: this is the tool that holds the keys,
# and every dependency here is one more thing to audit.

ruby file: '.ruby-version'

source 'https://rubygems.org/'

# ====================================
# Core Application Framework
# ====================================

gem 'roda', '~> 3.0'
gem 'rodauth', '~> 2.0'
# table_guard (schema validation at boot), hmac_secret_guard, external_identity
# (the accounts.external_id join column), and the Sequel migration templates
# the local dev authdb is generated from.
gem 'rodauth-tools', '~> 0.4.0'

# Web server and middleware
gem 'puma', '>= 6.0', '< 8.0'
gem 'rack', '>= 3.2.6', '< 4.0'
gem 'rack-protection', '~> 4.1'

# Templates (Roda render plugin; Rodauth ships .str templates via tilt)
gem 'erubi', '~> 1.13'
gem 'tilt', '~> 2.4'

# ====================================
# Database
# ====================================

# Both drivers: SQLite for local development and tests, PostgreSQL in
# production (the authdb is PostgreSQL; the admin's own tables may be either).
gem 'pg', '~> 1.6'
gem 'sequel', '~> 5.0'
gem 'sqlite3', '~> 2.0'

# ====================================
# Security & Encryption
# ====================================

# Must match the tenant app: production password hashes are argon2id with a
# pepper (ARGON2_SECRET); bcrypt covers legacy hashes.
gem 'argon2', '~> 2.3'
gem 'bcrypt', '~> 3.1'
# TOTP for the operator MFA requirement; rqrcode renders the setup QR.
gem 'rotp', '~> 6.2'
gem 'rqrcode', '~> 3.1'

# ====================================
# Logging
# ====================================

gem 'semantic_logger', '~> 4.17'

# ====================================
# Ruby Standard Library Compatibility
# ====================================

gem 'base64'
gem 'logger'

# ====================================
# Development & Testing Dependencies
# ====================================

group :development do
  gem 'debug', require: false
  gem 'rackup'
  gem 'rerun', '~> 0.14'
  gem 'rubocop', '~> 1.89.0', require: false
  gem 'rubocop-performance', require: false
  gem 'rubocop-rspec', require: false
  gem 'rubocop-sequel', require: false
  gem 'rubocop-thread_safety', require: false
end

group :test do
  gem 'rack-test', require: false
  gem 'rspec', '4.0.0.beta1'
  gem 'timecop', '~> 0.9'
  gem 'tryouts', '~> 4.0.0.pre1', require: false

  # RSpec components, pinned to match the rspec 4.0.0.beta1 release on rubygems.
  %w[rspec-core rspec-expectations rspec-mocks rspec-support].each do |lib|
    gem lib, '4.0.0.beta1'
  end
end
