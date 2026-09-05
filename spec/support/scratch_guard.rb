# spec/support/scratch_guard.rb
#
# frozen_string_literal: true

require 'uri'

# The proof that the suite's destructive fixtures are pointed at a database
# nobody minds losing.
#
# The suite's `before` hook DELETEs every account table, `AuthdbSchema.build!`
# runs DDL, and `create_account` writes rows — and those go through whichever
# credential is the schema owner, i.e. *not necessarily* ADMIN_DATABASE_URL.
# So every URL the suite can write through is checked, not just the app one,
# and the resolved connections are checked again afterwards (a URL is a
# string; `opts[:database]` is what Sequel actually opened).
#
# Deliberately dependency-free and pure over strings: try/scratch_guard_try.rb
# exercises it with no database and no RSpec.
module ScratchGuard
  SCRATCH_DATABASE_NAME = /(^|_)(test|ci|scratch)($|_)/
  DESTRUCTIVE_OVERRIDE = 'RODAUTH_ADMIN_ALLOW_DESTRUCTIVE_SPECS'

  # Every URL the suite can open a writable connection on. FIXTURE_DB is the
  # migrator whenever it differs from the app URL, which is exactly the
  # provisioned mode this guard exists for; _RO is here because a
  # misconfigured "read-only" credential is only read-only by convention.
  CHECKED_URL_VARS = %w[
    ADMIN_DATABASE_URL
    ADMIN_DATABASE_URL_RO
    ADMIN_DATABASE_URL_MIGRATIONS
  ].freeze

  module_function

  # The last path segment of a URL, or the string itself when it is already a
  # bare database name (Sequel's `opts[:database]`). An unparseable URL (a
  # password with unescaped punctuation, say) is not a licence to proceed:
  # no name means no proof, so it yields '' and the refusal stands.
  def database_name(url)
    URI.parse(url.to_s).path.to_s.split('/').last.to_s
  rescue URI::InvalidURIError
    ''
  end

  # A SQLite file the suite created itself under its own per-process tmpdir
  # needs no name: its provenance is the proof. Nothing else gets this.
  def own_scratch_file?(url, scratch_dir)
    return false if scratch_dir.to_s.empty?

    url.to_s.delete_prefix('sqlite://').start_with?("#{scratch_dir}/")
  end

  # @return [String, nil] nil when the target is acceptable, else the
  #   offending database name (possibly '') for the refusal message.
  def violation(url, scratch_dir: nil)
    return nil if ENV[DESTRUCTIVE_OVERRIDE] == '1'
    return nil if own_scratch_file?(url, scratch_dir)

    name = database_name(url)
    name.match?(SCRATCH_DATABASE_NAME) ? nil : name
  end

  # @param env [Hash] ENV or a stand-in
  # @return [Array<Array(String, String)>] [variable, offending name] pairs,
  #   in CHECKED_URL_VARS order, for every set URL that fails the rule.
  def offenders(env, scratch_dir: nil)
    CHECKED_URL_VARS.filter_map do |var|
      url = env[var].to_s
      next if url.strip.empty?

      name = violation(url, scratch_dir: scratch_dir)
      [var, name] if name
    end
  end

  def refusal(source, name)
    <<~REFUSAL
      Refusing to run the specs: #{source} names database #{name.inspect}.

      This suite truncates every account table (accounts and every account_*
      child) plus admin_operators before each example, and runs DDL and
      fixture writes through the migrator credential. It is only ever safe
      against a scratch database, so EVERY configured URL has to be one —
      the app URL passing is not enough when the destructive statements go
      through ADMIN_DATABASE_URL_MIGRATIONS.

      Name the database so it says so (matching #{SCRATCH_DATABASE_NAME.source},
      e.g. onetime_authdb_ci), or set #{DESTRUCTIVE_OVERRIDE}=1 if you have
      genuinely decided this database is disposable.
    REFUSAL
  end
end
