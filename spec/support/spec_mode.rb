# spec/support/spec_mode.rb
#
# frozen_string_literal: true

# Which database the suite runs against is decided from the *inherited*
# environment, before spec_helper touches it.
#
# The problem this solves: direnv exports ADMIN_DATABASE_URL (the developer's
# real local authdb) into every shell in the checkout, so "ADMIN_DATABASE_URL
# is set" cannot mean "someone provisioned a database for this run" — under
# that reading `rake test` in a dev shell walks into the scratch guard's
# refusal, which is correct but useless.
#
# The rule: a pre-provisioned run is one where the *caller* said RACK_ENV=test
# as well. The CI lanes do (both the SQLite and the PostgreSQL job); direnv
# sets RACK_ENV=development. Anything else — no RACK_ENV, development,
# production — means the inherited URLs are incidental and are ignored: the
# suite builds its own scratch SQLite as in the default mode.
#
# Pure over a Hash so try/spec_mode_try.rb can exercise it with no database.
module SpecMode
  module_function

  # @param env [Hash] the environment as inherited, before spec_helper mutates it
  def provisioned_database?(env)
    env['RACK_ENV'].to_s.strip == 'test' && !env['ADMIN_DATABASE_URL'].to_s.strip.empty?
  end
end
