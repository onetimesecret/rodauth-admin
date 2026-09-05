# spec/grants_spec.rb
#
# frozen_string_literal: true

require_relative 'spec_helper'

# db/grants/postgres/rodauth_admin_roles.sql is the privilege boundary, and a
# grant file that is never executed proves nothing. This is the check that it
# says what it means: run against a PostgreSQL authdb with the grant file
# applied and three genuinely distinct roles (the `test-postgres` CI job), it
# asserts the read-only role can read every Phase 2 table and cannot write,
# and that admin_actions is append-only for the runtime role too.
#
# On SQLite — the default local and CI path — there are no roles and the file
# is inert, so the whole group skips. That is the honest outcome: the
# behaviour specs prove behaviour, this file proves privilege, and only
# PostgreSQL can prove privilege (docs/design/database-credentials.md).
RSpec.describe 'PostgreSQL grants' do # rubocop:disable RSpec/DescribeClass
  # CHARTER §3 / the Phase 2 block in the grant file.
  let(:phase_2_tables) do
    %i[
      accounts
      account_statuses
      account_otp_keys
      account_webauthn_keys
      account_lockouts
      account_login_failures
      account_active_session_keys
      account_recovery_codes
    ]
  end

  let(:ro) { RodauthAdmin::Database.readonly }
  let(:app_db) { RodauthAdmin::Database.app }
  let(:migrator) { RodauthAdmin::Database.migrator }

  before do
    skip 'grants exist only on PostgreSQL' unless RodauthAdmin::Database.migrator.database_type == :postgres

    distinct = [RodauthAdmin::Env.database_url,
                RodauthAdmin::Env.database_url_ro,
                RodauthAdmin::Env.database_url_migrations].uniq.size == 3
    skip 'all three URLs are the same credential; nothing to prove' unless distinct
  end

  describe 'rodauth_admin_ro' do
    it 'can SELECT every table Phase 2 reads' do
      phase_2_tables.each do |table|
        expect { ro[table].limit(1).all }.not_to raise_error,
                                                 "rodauth_admin_ro cannot SELECT #{table}"
      end
    end

    it 'sees the password-reuse count but never the hashes' do
      expect { ro[:account_previous_password_hashes].select(:id, :account_id).limit(1).all }.not_to raise_error
      expect { ro[:account_previous_password_hashes].select(:password_hash).limit(1).all }
        .to raise_error(Sequel::DatabaseError, /permission denied/)
    end

    it 'cannot read the tables outside the capability surface' do
      %i[account_password_hashes account_remember_keys account_session_keys account_sms_codes].each do |table|
        expect { ro[table].limit(1).all }.to raise_error(Sequel::DatabaseError, /permission denied/),
                                             "rodauth_admin_ro can read #{table}"
      end
    end

    it 'cannot call the password functions' do
      expect { ro.get(Sequel.function(:rodauth_valid_password_hash, 1, 'x')) }
        .to raise_error(Sequel::DatabaseError, /permission denied/)
    end

    # Scoped to one fixture row on purpose. An unqualified UPDATE/DELETE
    # would pass this example even if the statement were merely rejected
    # for some other reason, and would rewrite the whole table the day the
    # grant regressed. WHERE id = <fixture> both narrows the blast radius
    # and proves the refusal is about privilege on a row that exists.
    it 'cannot write accounts' do
      fixture_id = migrator[:accounts].insert(email: 'ro-target@example.com', status_id: 2)

      expect { ro[:accounts].insert(email: 'nope@example.com', status_id: 2) }
        .to raise_error(Sequel::DatabaseError, /permission denied/)
      expect { ro[:accounts].where(id: fixture_id).update(status_id: 3) }
        .to raise_error(Sequel::DatabaseError, /permission denied/)
      expect { ro[:accounts].where(id: fixture_id).delete }
        .to raise_error(Sequel::DatabaseError, /permission denied/)
      expect(migrator[:accounts].where(id: fixture_id).get(:status_id)).to eq(2)
    end

    it 'cannot write admin_actions' do
      expect { ro[:admin_actions].insert(action: 'x', actor: 'x', reason: 'x') }
        .to raise_error(Sequel::DatabaseError, /permission denied/)
      expect { ro[:admin_actions].where(action: 'grants_spec_ro').update(reason: 'rewritten') }
        .to raise_error(Sequel::DatabaseError, /permission denied/)
      expect { ro[:admin_actions].where(action: 'grants_spec_ro').delete }
        .to raise_error(Sequel::DatabaseError, /permission denied/)
    end
  end

  describe 'rodauth_admin_app' do
    it 'cannot UPDATE or DELETE admin_actions' do
      app_db[:admin_actions].insert(action: 'grants_spec', actor: 'spec', reason: 'privilege check')

      expect { app_db[:admin_actions].where(action: 'grants_spec').update(reason: 'rewritten') }
        .to raise_error(Sequel::DatabaseError, /permission denied/)
      expect { app_db[:admin_actions].where(action: 'grants_spec').delete }
        .to raise_error(Sequel::DatabaseError, /permission denied/)
    end

    it 'cannot write accounts, and cannot read the hash table directly' do
      expect { app_db[:accounts].insert(email: 'nope2@example.com', status_id: 2) }
        .to raise_error(Sequel::DatabaseError, /permission denied/)
      expect { app_db[:account_password_hashes].limit(1).all }
        .to raise_error(Sequel::DatabaseError, /permission denied/)
    end
  end

  # The grant is one of the two locks on the audit trail; the trigger is the
  # other, and it is the one that also binds the table's owner.
  describe 'the append-only trigger' do
    it 'rejects UPDATE and DELETE even for the migrator that owns the table' do
      migrator[:admin_actions].insert(action: 'grants_spec_owner', actor: 'spec', reason: 'trigger check')

      expect { migrator[:admin_actions].where(action: 'grants_spec_owner').update(reason: 'rewritten') }
        .to raise_error(Sequel::DatabaseError, /append-only/)
      expect { migrator[:admin_actions].where(action: 'grants_spec_owner').delete }
        .to raise_error(Sequel::DatabaseError, /append-only/)
    end
  end
end
