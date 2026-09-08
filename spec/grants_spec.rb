# spec/grants_spec.rb
#
# frozen_string_literal: true

require_relative 'spec_helper'

# db/grants/postgres/rodauth_admin_roles.sql is the privilege boundary, and a
# grant file that is never executed proves nothing. This is the check that it
# says what it means: run against a PostgreSQL authdb with the grant file
# applied and genuinely distinct roles (the `test-postgres` CI job), it
# asserts the read-only role can read every Phase 2 and Phase 3 table and
# cannot write, that the Phase 4 verbs role can delete exactly the tables the
# verbs touch and nothing else, and that admin_actions is append-only for the
# runtime role too.
#
# On SQLite — the default local and CI path — there are no roles and the file
# is inert, so the whole group skips. That is the honest outcome: the
# behaviour specs prove behaviour, this file proves privilege, and only
# PostgreSQL can prove privilege (docs/design/database-credentials.md).
# rubocop:disable RSpec/MultipleMemoizedHelpers -- four table lists and four
# connections; naming them is what makes the failures readable.
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

  # CHARTER §3 / the Phase 3 (account detail) block in the grant file. The
  # Phase 1 grant file already covered these; the split keeps a regression
  # naming the phase whose screens just went dark.
  let(:phase_3_tables) do
    %i[
      account_otp_unlocks
      account_jwt_refresh_keys
      account_password_reset_keys
      account_verification_keys
      account_login_change_keys
      account_email_auth_keys
      account_identities
      account_password_change_times
      account_authentication_audit_logs
    ]
  end

  # CHARTER §6 item 4 / the Phase 4 block in the grant file: every table a
  # verb deletes from. Kept in one list because the failure that matters is
  # "a verb lost its grant", not "which verb".
  let(:verb_tables) do
    %i[
      account_lockouts
      account_login_failures
      account_password_reset_keys
      account_verification_keys
      account_login_change_keys
      account_email_auth_keys
      account_otp_keys
      account_otp_unlocks
      account_recovery_codes
      account_webauthn_keys
      account_webauthn_user_ids
      account_active_session_keys
      account_jwt_refresh_keys
      account_identities
      account_remember_keys
    ]
  end

  let(:ro) { RodauthAdmin::Database.readonly }
  let(:verbs) { RodauthAdmin::Database.verbs }
  let(:app_db) { RodauthAdmin::Database.app }
  let(:migrator) { RodauthAdmin::Database.migrator }

  before do
    skip 'grants exist only on PostgreSQL' unless RodauthAdmin::Database.migrator.database_type == :postgres

    distinct = [RodauthAdmin::Env.database_url,
                RodauthAdmin::Env.database_url_ro,
                RodauthAdmin::Env.database_url_verbs,
                RodauthAdmin::Env.database_url_migrations].uniq.size == 4
    skip 'the URLs are not four distinct credentials; nothing to prove' unless distinct
  end

  describe 'rodauth_admin_ro' do
    it 'can SELECT every table Phase 2 reads' do
      phase_2_tables.each do |table|
        expect { ro[table].limit(1).all }.not_to raise_error,
                                                 "rodauth_admin_ro cannot SELECT #{table}"
      end
    end

    it 'can SELECT every table Phase 3 reads' do
      phase_3_tables.each do |table|
        expect { ro[table].limit(1).all }.not_to raise_error,
                                                 "rodauth_admin_ro cannot SELECT #{table}"
      end
    end

    it 'sees the password-reuse count but never the hashes' do
      expect { ro[:account_previous_password_hashes].select(:id, :account_id).limit(1).all }.not_to raise_error
      expect { ro[:account_previous_password_hashes].select(:password_hash).limit(1).all }
        .to raise_error(Sequel::DatabaseError, /permission denied/)
    end

    # The column-scoped grant has to survive the exact shape the detail page
    # issues: a COUNT over the column-scoped grant, never password_hash.
    it 'counts the password-reuse history the way the detail page does' do
      expect do
        ro[:account_previous_password_hashes].where(account_id: 0).select(:id, :account_id).count
      end.not_to raise_error
    end

    # The count above is one query of many. This runs the whole per-account
    # page through the read-only role, which is the only way to catch a
    # section whose grant is missing: every query in AccountDetail is
    # swallowed into available: false, so a privilege regression would
    # otherwise render as a degraded panel rather than a failing example.
    it 'renders the account detail through the read-only role' do
      fixture_id = migrator[:accounts].insert(email: 'ro-detail@example.com', status_id: 2)

      detail = RodauthAdmin::AccountDetail.find(id: fixture_id, db: ro)
      expect(detail.available).to be(true), "degraded: #{detail.reason}"
      expect(detail.found).to be(true)

      timeline = RodauthAdmin::AccountDetail.timeline(id: fixture_id, db: ro)
      expect(timeline.available).to be(true), "degraded: #{timeline.reason}"
    end

    # The count is a capability (the revoke-sessions confirm page states how
    # many remember-me cookies it is about to invalidate); the token is not.
    it 'counts remember-me tokens but never reads one' do
      expect { ro[:account_remember_keys].select(:id, :deadline).limit(1).all }.not_to raise_error
      expect { ro[:account_remember_keys].select(:key).limit(1).all }
        .to raise_error(Sequel::DatabaseError, /permission denied/)
    end

    it 'cannot read the tables outside the capability surface' do
      %i[account_password_hashes account_session_keys account_sms_codes].each do |table|
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

    # The Phase 4 line the charter did NOT take: rodauth_admin_ro stays
    # SELECT-only, and the verbs run as rodauth_admin_verbs instead
    # (db/grants/postgres/rodauth_admin_roles.sql, Phase 4 revision).
    it 'still cannot DELETE the tables the Phase 4 verbs mutate' do
      verb_tables.each do |table|
        expect { ro[table].where(false).delete }
          .to raise_error(Sequel::DatabaseError, /permission denied/),
              "rodauth_admin_ro can DELETE #{table}"
      end
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

  describe 'rodauth_admin_verbs' do
    # WHERE false still plans against the relation, so PostgreSQL checks the
    # DELETE privilege — the statement proves the grant without depending on
    # a fixture row existing, which keeps the lane re-runnable.
    it 'can DELETE every table a verb mutates' do
      verb_tables.each do |table|
        expect { verbs[table].where(false).delete }
          .not_to raise_error, "rodauth_admin_verbs cannot DELETE #{table}"
      end
    end

    it 'can SELECT the rows it is about to delete' do
      # account_remember_keys is column-scoped and so is asserted separately
      # below; admin_operators is what the operator-target refusal reads.
      selectable = verb_tables - %i[account_remember_keys]
      (selectable + %i[accounts account_password_change_times admin_operators]).each do |table|
        expect { verbs[table].limit(1).all }
          .not_to raise_error, "rodauth_admin_verbs cannot SELECT #{table}"
      end
    end

    # revoke_sessions deletes remember-me rows WHERE id = ?, which PostgreSQL
    # will not plan without SELECT on the columns the clause names. The token
    # itself stays unreadable to the role that deletes it.
    it 'reads a remember-me row by id and deadline, never its key' do
      expect { verbs[:account_remember_keys].select(:id, :deadline).limit(1).all }.not_to raise_error
      expect { verbs[:account_remember_keys].select(:key).limit(1).all }
        .to raise_error(Sequel::DatabaseError, /permission denied/)
    end

    # Everything a mutation credential must NOT be able to do. Each of these
    # is a way a support tool would quietly become an authentication bypass:
    # re-keying a second factor, forging or editing evidence, or granting
    # itself an operator.
    it 'cannot UPDATE the second-factor tables' do
      expect { verbs[:account_otp_keys].where(false).update(num_failures: 0) }
        .to raise_error(Sequel::DatabaseError, /permission denied/)
      expect { verbs[:account_webauthn_keys].where(false).update(sign_count: 0) }
        .to raise_error(Sequel::DatabaseError, /permission denied/)
    end

    it "cannot write Rodauth's own auth log" do
      expect { verbs[:account_authentication_audit_logs].insert(account_id: 0, message: 'forged') }
        .to raise_error(Sequel::DatabaseError, /permission denied/)
    end

    it 'can read admin_operators but cannot change who is one' do
      expect { verbs[:admin_operators].limit(1).all }.not_to raise_error
      expect { verbs[:admin_operators].insert(account_id: 0, email: 'x@example.com', added_by: 'spec') }
        .to raise_error(Sequel::DatabaseError, /permission denied/)
      expect { verbs[:admin_operators].where(false).update(email: 'x@example.com') }
        .to raise_error(Sequel::DatabaseError, /permission denied/)
      expect { verbs[:admin_operators].where(false).delete }
        .to raise_error(Sequel::DatabaseError, /permission denied/)
    end

    it 'cannot read the tables outside its mutation surface' do
      %i[account_previous_password_hashes account_session_keys account_sms_codes].each do |table|
        expect { verbs[table].limit(1).all }
          .to raise_error(Sequel::DatabaseError, /permission denied/),
              "rodauth_admin_verbs can read #{table}"
      end
    end

    # force_password_reset upserts changed_at; regenerate_recovery_codes
    # inserts fresh codes. Both are rolled back so the lane is repeatable.
    it 'can UPSERT account_password_change_times and INSERT recovery codes' do
      fixture_id = migrator[:accounts].insert(email: 'verbs-target@example.com', status_id: 2)

      expect do
        verbs.transaction(rollback: :always) do
          verbs[:account_password_change_times].insert(id: fixture_id, changed_at: Time.utc(1970, 1, 1))
          verbs[:account_password_change_times].where(id: fixture_id).update(changed_at: Time.utc(1970, 1, 1))
          verbs[:account_recovery_codes].insert(id: fixture_id, code: 'grants-spec-code')
        end
      end.not_to raise_error
    end

    # The audit row commits with the mutation, on this connection.
    it 'can INSERT admin_actions but cannot UPDATE or DELETE them' do
      verbs[:admin_actions].insert(action: 'grants_spec_verbs', actor: 'spec', reason: 'privilege check')

      expect { verbs[:admin_actions].where(action: 'grants_spec_verbs').update(reason: 'rewritten') }
        .to raise_error(Sequel::DatabaseError, /permission denied|append-only/)
      expect { verbs[:admin_actions].where(action: 'grants_spec_verbs').delete }
        .to raise_error(Sequel::DatabaseError, /permission denied|append-only/)
    end

    it 'cannot touch the password hashes at all' do
      expect { verbs[:account_password_hashes].limit(1).all }
        .to raise_error(Sequel::DatabaseError, /permission denied/)
      expect { verbs[:account_password_hashes].insert(id: 0, password_hash: 'x') }
        .to raise_error(Sequel::DatabaseError, /permission denied/)
      expect { verbs[:account_password_hashes].where(false).update(password_hash: 'x') }
        .to raise_error(Sequel::DatabaseError, /permission denied/)
      expect { verbs[:account_password_hashes].where(false).delete }
        .to raise_error(Sequel::DatabaseError, /permission denied/)
    end

    it 'cannot write accounts, and cannot run DDL' do
      expect { verbs[:accounts].where(false).delete }
        .to raise_error(Sequel::DatabaseError, /permission denied/)
      expect { verbs.run('CREATE TABLE grants_spec_verbs_ddl (id int)') }
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

    # Lockout is not enabled on the admin instance (CHARTER §4, revision 5),
    # so the sign-in role has no business with either table. The grant file
    # REVOKEs what Phase 1 granted; this is the proof that the re-run took
    # it back.
    it 'cannot touch the lockout tables' do
      fixture_id = migrator[:accounts].insert(email: 'app-lockout@example.com', status_id: 2)
      migrator[:account_login_failures].insert(id: fixture_id, number: 1)

      expect { app_db[:account_login_failures].where(id: fixture_id).all }
        .to raise_error(Sequel::DatabaseError, /permission denied/)
      expect { app_db[:account_login_failures].where(id: fixture_id).delete }
        .to raise_error(Sequel::DatabaseError, /permission denied/)
      expect { app_db[:account_lockouts].insert(id: fixture_id, key: 'k', deadline: Time.now + 3600) }
        .to raise_error(Sequel::DatabaseError, /permission denied/)
      expect(migrator[:account_login_failures].where(id: fixture_id).get(:number)).to eq(1)
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
# rubocop:enable RSpec/MultipleMemoizedHelpers
