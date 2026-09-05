# lib/rodauth_admin.rb
#
# frozen_string_literal: true

require 'semantic_logger'

require_relative 'rodauth_admin/env'
require_relative 'rodauth_admin/database'

# Rodauth Admin: a standalone admin application over the Onetime Secret
# authdb (Rodauth full-mode). See docs/CHARTER.md.
module RodauthAdmin
  class Error < StandardError; end
  class ConfigurationError < Error; end

  LOGGER = SemanticLogger['RodauthAdmin']

  class << self
    def logger = LOGGER

    # Boot order matters: the admin tables must exist before the Roda app
    # loads, because RodauthAdmin::Auth's table_guard connects at
    # class-definition time and the allowlist check on the first request
    # reads admin_operators. Migrations are never run here (offline only).
    def boot!
      SemanticLogger.default_level = Env.log_level
      if SemanticLogger.appenders.empty?
        SemanticLogger.add_appender(io: $stdout,
                                    formatter: Env.production? ? :json : :color)
      end

      Env.validate!
      Database.check_admin_schema!

      require_relative 'rodauth_admin/app'
      logger.info 'Rodauth Admin booted', env: Env.rack_env
      self
    end
  end
end
