# try/spec_mode_try.rb
#
# frozen_string_literal: true

# Which database mode the spec suite picks, decided from the inherited
# environment alone. No database, no RSpec.

require_relative '../spec/support/spec_mode'

@url = 'postgresql://rodauth_admin_app:pw@host/onetime_authdb_ci'

## CI's provisioned lane: the caller set both
SpecMode.provisioned_database?({ 'RACK_ENV' => 'test', 'ADMIN_DATABASE_URL' => @url })
#=> true

## A direnv dev shell: RACK_ENV=development, so the inherited URL is ignored
SpecMode.provisioned_database?({ 'RACK_ENV' => 'development', 'ADMIN_DATABASE_URL' => @url })
#=> false

## No RACK_ENV at all is not provisioned either
SpecMode.provisioned_database?({ 'ADMIN_DATABASE_URL' => @url })
#=> false

## RACK_ENV=test without a URL is the default scratch-SQLite mode
SpecMode.provisioned_database?({ 'RACK_ENV' => 'test' })
#=> false

## A blank URL under RACK_ENV=test is not a URL
SpecMode.provisioned_database?({ 'RACK_ENV' => 'test', 'ADMIN_DATABASE_URL' => '   ' })
#=> false

## RACK_ENV=production never provisions, however the URL is named
SpecMode.provisioned_database?({ 'RACK_ENV' => 'production', 'ADMIN_DATABASE_URL' => @url })
#=> false
