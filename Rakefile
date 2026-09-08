# Rakefile
#
# frozen_string_literal: true

require_relative 'lib/rodauth_admin'

def cli_actor
  "cli:#{ENV.fetch('USER', 'unknown')}"
end

# Same normalization as RodauthAdmin::Auth#normalize_login.
def normalize_email(raw)
  raw.unicode_normalize(:nfc).strip.downcase
end

def require_reason!
  reason = RodauthAdmin::Env.presence(ENV.fetch('REASON', nil))
  abort 'REASON="why" is required (it is written to admin_actions)' unless reason
  reason
end

namespace :db do
  desc 'Run pending admin migrations with the migrator credential (ADMIN_DATABASE_URL_MIGRATIONS); offline only'
  task :migrate do
    db = RodauthAdmin::Database.migrate_admin!
    version = db[RodauthAdmin::Database::ADMIN_SCHEMA_TABLE].get(:version)
    puts "admin migrations at version #{version}: #{RodauthAdmin::Database::ADMIN_TABLES.join(', ')}"
  end
end

namespace :authdb do
  desc 'Build a local development authdb from the rodauth-tools templates (never point this at production)'
  task :dev do
    require_relative 'lib/rodauth_admin/authdb_schema'
    abort 'authdb:dev refuses to run with RACK_ENV=production' if RodauthAdmin::Env.production?

    db = RodauthAdmin::Database.migrator
    RodauthAdmin::AuthdbSchema.build!(db)
    puts "authdb built (#{db.tables.size} tables): #{db.tables.sort.join(', ')}"
  end

  desc 'Show which authdb tables the admin sign-in requires and whether they exist'
  task :status do
    require_relative 'lib/rodauth_admin/auth'
    rodauth = RodauthAdmin::Auth.allocate
    rodauth.table_status.each do |row|
      puts "#{row[:exists] ? '✓' : '✗'} #{row[:table].to_s.ljust(36)} #{row[:feature]}"
    end
  end
end

namespace :operators do
  desc 'List allowlisted operators'
  task :list do
    require_relative 'lib/rodauth_admin/allowlist'
    rows = RodauthAdmin::Allowlist.list
    puts 'no operators' if rows.empty?
    rows.each do |r|
      puts "#{r[:account_id].to_s.rjust(8)}  #{r[:email].ljust(40)} added #{r[:created_at]} by #{r[:added_by]}"
    end
  end

  desc 'Allowlist a production account by email: rake operators:add[EMAIL] REASON="..."'
  task :add, [:email] do |_t, args|
    require_relative 'lib/rodauth_admin/allowlist'
    email = RodauthAdmin::Env.presence(args[:email]) or abort 'usage: rake operators:add[EMAIL] REASON="..."'
    reason = require_reason!
    email = normalize_email(email)
    account = RodauthAdmin::Database.readonly[:accounts].where(email: email).select(:id, :email, :status_id).first
    abort "no authdb account for #{email}" unless account
    unless account[:status_id] == 2
      abort "#{email} is not Verified (status_id=#{account[:status_id]}); verify it in the tenant app first"
    end

    RodauthAdmin::Allowlist.add!(account_id: account[:id], email: account[:email], actor: cli_actor, reason: reason)
    puts "added #{account[:email]} (account #{account[:id]})"
  end

  desc 'Remove an operator by email: rake operators:remove[EMAIL] REASON="..."'
  task :remove, [:email] do |_t, args|
    require_relative 'lib/rodauth_admin/allowlist'
    email = RodauthAdmin::Env.presence(args[:email]) or abort 'usage: rake operators:remove[EMAIL] REASON="..."'
    reason = require_reason!
    email = normalize_email(email)
    # The authdb is authoritative: an operator may have changed their email
    # in the tenant app since being allowlisted, so resolve the current
    # address to an account id there and remove by id. The display copy in
    # admin_operators is only the fallback for an account that no longer
    # exists in the authdb at all.
    begin
      account_id = RodauthAdmin::Allowlist.account_id_for_email(email, authdb: RodauthAdmin::Database.readonly)
    rescue RodauthAdmin::Allowlist::AmbiguousEmail => e
      abort "#{e.message}; remove by the account id you mean with rake operators:remove_id[ID]"
    end
    abort "#{email} is not an operator" unless account_id

    row = RodauthAdmin::Allowlist.remove!(account_id: account_id, actor: cli_actor, reason: reason)
    abort "#{email} (account #{account_id}) is not an operator" unless row

    puts "removed #{row[:email]} (account #{row[:account_id]})"
  end

  desc 'Remove an operator by authdb account id: rake operators:remove_id[ID] REASON="..."'
  task :remove_id, [:id] do |_t, args|
    require_relative 'lib/rodauth_admin/allowlist'
    id = Integer(args[:id].to_s, exception: false) or abort 'usage: rake operators:remove_id[ID] REASON="..."'
    reason = require_reason!
    row = RodauthAdmin::Allowlist.remove!(account_id: id, actor: cli_actor, reason: reason)
    abort "account #{id} is not an operator" unless row

    puts "removed #{row[:email]} (account #{row[:account_id]})"
  end
end

namespace :audit do
  desc 'Show the most recent admin_actions rows'
  task :recent do
    require_relative 'lib/rodauth_admin/audit'
    RodauthAdmin::Audit.recent(limit: (ENV['LIMIT'] || 50).to_i).each do |r|
      target = r[:target] ? " -> #{r[:target]}" : ''
      puts "#{r[:at]}  #{r[:action].ljust(16)} #{r[:actor]}#{target}  (#{r[:reason]})"
    end
  end
end

# One definition of "the tests", shared with the git hooks and GitHub
# Actions. Stage list and behaviour live in bin/ci.
desc 'Run the checks: bin/ci (lint, tryouts, RSpec)'
task :test do
  sh File.expand_path('bin/ci', __dir__)
end

task default: :test
