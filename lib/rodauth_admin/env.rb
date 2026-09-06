# lib/rodauth_admin/env.rb
#
# frozen_string_literal: true

require 'securerandom'

module RodauthAdmin
  # All ENV access lives here. Unset RACK_ENV is production (fail closed),
  # and every production-required value raises at boot rather than at the
  # first request that needs it.
  #
  # Database credentials follow the tenant app's Rodauth pattern of a
  # runtime user and a migration user (docs/design/database-credentials.md):
  #
  #   ADMIN_DATABASE_URL             runtime "app" user: the Rodauth login
  #                                  path plus the admin's own tables
  #   ADMIN_DATABASE_URL_RO          read-only user: every admin query
  #   ADMIN_DATABASE_URL_MIGRATIONS  the tenant app's existing migrator,
  #                                  used only by `rake db:migrate` offline
  module Env
    DEV_DATABASE_URL = 'sqlite://data/authdb.sqlite3'
    SESSION_SECRET_MIN_BYTES = 64

    module_function

    def rack_env
      ENV.fetch('RACK_ENV', 'production')
    end

    def production? = rack_env == 'production'
    def test?       = rack_env == 'test'
    def development? = rack_env == 'development'

    def log_level
      ENV.fetch('LOG_LEVEL', production? ? 'info' : 'debug').to_sym
    end

    # Runtime user: DML on Rodauth's login-path tables and the admin tables.
    def database_url
      presence(ENV.fetch('ADMIN_DATABASE_URL', nil)) || dev_default('ADMIN_DATABASE_URL', DEV_DATABASE_URL)
    end

    # Read-only user: every admin query.
    def database_url_ro
      presence(ENV.fetch('ADMIN_DATABASE_URL_RO', nil)) || dev_default('ADMIN_DATABASE_URL_RO', DEV_DATABASE_URL)
    end

    # Mutation user: the Phase 4 verbs (CHARTER §4/§6 item 4) and nothing
    # else. A separate credential rather than a widened read-only role, so a
    # role named _ro can never DELETE and every read screen keeps running
    # without mutation privilege (docs/design/database-credentials.md).
    def database_url_verbs
      presence(ENV.fetch('ADMIN_DATABASE_URL_VERBS', nil)) || dev_default('ADMIN_DATABASE_URL_VERBS', DEV_DATABASE_URL)
    end

    # The existing migrator (the tenant app's AUTH_DATABASE_URL_MIGRATIONS
    # user). Never read by the running app; only rake db:migrate and
    # authdb:dev use it, and both run offline.
    def database_url_migrations
      presence(ENV.fetch('ADMIN_DATABASE_URL_MIGRATIONS', nil)) ||
        dev_default('ADMIN_DATABASE_URL_MIGRATIONS', DEV_DATABASE_URL)
    end

    def session_secret
      secret = presence(ENV.fetch('RODAUTH_ADMIN_SESSION_SECRET', nil))
      if secret.nil?
        raise ConfigurationError, 'RODAUTH_ADMIN_SESSION_SECRET is required in production' if production?

        return @session_secret ||= SecureRandom.hex(SESSION_SECRET_MIN_BYTES)
      end
      if secret.bytesize < SESSION_SECRET_MIN_BYTES
        raise ConfigurationError, "RODAUTH_ADMIN_SESSION_SECRET must be >= #{SESSION_SECRET_MIN_BYTES} bytes"
      end

      secret
    end

    def otp_issuer
      ENV.fetch('OTP_ISSUER', 'OTS')
    end

    # The tenant app's HMAC secret: production OTP keys are stored HMAC'd
    # with it, so the admin door cannot verify a code without the same
    # value. Read once, removed from ENV, required in production.
    def auth_secret
      @auth_secret ||= begin
        secret = presence(ENV.delete('AUTH_SECRET'))
        if secret.nil?
          raise ConfigurationError, 'AUTH_SECRET (the tenant app HMAC secret) is required in production' if production?

          SecureRandom.hex(32)
        else
          secret
        end
      end
    end

    def auth_old_secret
      @auth_old_secret ||= presence(ENV.delete('AUTH_OLD_SECRET'))
    end

    # Host the admin is served on; Rodauth's +domain+ (no email links are
    # ever generated here, but Rodauth requires it to be set deliberately).
    def public_host
      presence(ENV.fetch('RODAUTH_ADMIN_HOST', nil)) || dev_default('RODAUTH_ADMIN_HOST', 'localhost')
    end

    # Base URL of the tenant app's colonel console. CHARTER §4 integration
    # seam 1, and the whole of it: an account row that has an external_id
    # renders an outbound link to
    # "#{colonel_console_url}/colonel/customers/<external_id>". Nothing is
    # ever requested from it — no credential, no cross-service call — so it
    # is optional everywhere including production. Unset means the external
    # id renders as plain text.
    def colonel_console_url
      url = presence(ENV.fetch('COLONEL_CONSOLE_URL', nil))
      url&.sub(%r{/+\z}, '')
    end

    # Fail fast at boot. The migrations URL is deliberately not validated
    # here: the running app must work without it.
    def validate!
      database_url
      database_url_ro
      database_url_verbs
      session_secret
      auth_secret
      public_host
      nil
    end

    def presence(value)
      value = value.to_s.strip
      value.empty? ? nil : value
    end

    def dev_default(key, default)
      raise ConfigurationError, "#{key} is required in production" if production?

      default
    end
  end
end
