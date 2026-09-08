# config.ru
#
# frozen_string_literal: true

require_relative 'lib/rodauth_admin'

# A configuration failure is never worth a retry: a bad secret or authdb
# schema drift will fail identically on every attempt. Exiting 78 (EX_CONFIG,
# sysexits(3)) pairs with `RestartPreventExitStatus=78` in the systemd unit,
# so the service stops at the first failure instead of looping. `boot!` itself
# keeps raising — the specs depend on that — and this rescue is the process
# boundary only. Sysexits, not anything Debian-specific: the app stays portable.
begin
  RodauthAdmin.boot!
rescue RodauthAdmin::ConfigurationError => e
  # boot! adds the log appender, so validation that fails before it lands
  # would otherwise log into the void. Fall back to stderr in that case.
  if SemanticLogger.appenders.empty?
    warn "FATAL: #{e.class}: #{e.message}"
  else
    RodauthAdmin.logger.fatal('Configuration error; refusing to start',
                              error_class: e.class.name, message: e.message)
    SemanticLogger.flush
  end
  exit 78
end

run RodauthAdmin::App.freeze.app
