# db/migrate/002_admin_actions.rb
#
# frozen_string_literal: true

# The admin's own audit trail: append-only, reason required, from day one.
#
# Append-only is enforced in the database, not just by convention:
#   - PostgreSQL: a trigger function rejects UPDATE and DELETE, and the
#     runtime role gets INSERT/SELECT only (db/grants/postgres/rodauth_admin_roles.sql)
#   - SQLite: BEFORE UPDATE / BEFORE DELETE triggers RAISE(ABORT)
#
# Requires PostgreSQL >= 11 (EXECUTE FUNCTION in CREATE TRIGGER).
Sequel.migration do
  up do
    json_type = database_type == :postgres ? :jsonb : String

    create_table(:admin_actions) do
      primary_key :id, type: :Bignum
      DateTime :at, null: false, default: Sequel::CURRENT_TIMESTAMP
      # text: true makes the type explicit: nothing here has a natural
      # 255-byte bound, and a long User-Agent or reason must never abort the
      # insert that records the request. (Sequel already emits text for a
      # bare String on PostgreSQL; SQLite gets varchar(255), unenforced.)
      String :action, null: false, text: true
      String :actor, null: false, text: true   # operator email or 'cli:<user>'
      Bignum :actor_account_id                 # authdb accounts.id; nil for CLI
      Bignum :target_account_id                # authdb accounts.id acted on
      String :target, text: true               # display handle (email / external_id)
      String :reason, null: false, text: true
      String :ip, text: true
      String :user_agent, text: true           # capped at 512 by Audit.record
      column :metadata, json_type
      index :at, name: :admin_actions_at_idx
      index %i[actor_account_id at], name: :admin_actions_actor_at_idx
      index %i[target_account_id at], name: :admin_actions_target_at_idx
    end

    case database_type
    when :postgres
      run <<~SQL
        CREATE OR REPLACE FUNCTION admin_actions_append_only() RETURNS trigger AS $$
        BEGIN
          RAISE EXCEPTION 'admin_actions is append-only';
        END;
        $$ LANGUAGE plpgsql;

        CREATE TRIGGER admin_actions_no_update
          BEFORE UPDATE OR DELETE ON admin_actions
          FOR EACH ROW EXECUTE FUNCTION admin_actions_append_only();
      SQL
    when :sqlite
      run <<~SQL
        CREATE TRIGGER admin_actions_no_update BEFORE UPDATE ON admin_actions
        BEGIN SELECT RAISE(ABORT, 'admin_actions is append-only'); END;
      SQL
      run <<~SQL
        CREATE TRIGGER admin_actions_no_delete BEFORE DELETE ON admin_actions
        BEGIN SELECT RAISE(ABORT, 'admin_actions is append-only'); END;
      SQL
    end
  end

  down do
    case database_type
    when :postgres
      run 'DROP TRIGGER IF EXISTS admin_actions_no_update ON admin_actions'
      run 'DROP FUNCTION IF EXISTS admin_actions_append_only()'
    when :sqlite
      run 'DROP TRIGGER IF EXISTS admin_actions_no_update'
      run 'DROP TRIGGER IF EXISTS admin_actions_no_delete'
    end
    drop_table(:admin_actions)
  end
end
