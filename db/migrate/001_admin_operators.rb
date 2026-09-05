# db/migrate/001_admin_operators.rb
#
# frozen_string_literal: true

# The operator allowlist. account_id is accounts.id in the production
# authdb (a different database — no FK is possible, and none is wanted:
# the admin database must not depend on authdb DDL).
Sequel.migration do
  change do
    create_table(:admin_operators) do
      primary_key :id
      Bignum :account_id, null: false, unique: true
      # text: true makes the type explicit. Sequel already emits text for a
      # bare String on PostgreSQL; SQLite gets varchar(255), unenforced.
      String :email, null: false, text: true    # display copy; the authdb is authoritative
      String :added_by, null: false, text: true # operator email or 'cli:<user>'
      String :note, text: true
      DateTime :created_at, null: false, default: Sequel::CURRENT_TIMESTAMP
    end
  end
end
