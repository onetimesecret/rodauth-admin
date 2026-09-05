# try/scratch_guard_try.rb
#
# frozen_string_literal: true

# The spec suite's scratch-database guard. No database and no RSpec: the
# check is a pure function of URL strings, which is the whole point — it has
# to be able to refuse *before* anything connects.

require_relative '../spec/support/scratch_guard'

@app_ci = 'postgresql://rodauth_admin_app:pw@host/onetime_authdb_ci'
@migrator_prod = 'postgresql://ots_migrator:pw@host/onetime_authdb'
@scratch_dir = '/tmp/rodauth-admin-spec-1234'

## A scratch-named database passes
ScratchGuard.violation(@app_ci)
#=> nil

## A production-named database is refused, and names itself
ScratchGuard.violation(@migrator_prod)
#=> "onetime_authdb"

## The review's failure scenario: app URL passes, migrator URL is production
env = { 'ADMIN_DATABASE_URL' => @app_ci, 'ADMIN_DATABASE_URL_MIGRATIONS' => @migrator_prod }
ScratchGuard.offenders(env)
#=> [['ADMIN_DATABASE_URL_MIGRATIONS', 'onetime_authdb']]

## A refused read-only URL is caught too
env = { 'ADMIN_DATABASE_URL' => @app_ci, 'ADMIN_DATABASE_URL_RO' => @migrator_prod,
        'ADMIN_DATABASE_URL_MIGRATIONS' => @app_ci }
ScratchGuard.offenders(env).map(&:first)
#=> ['ADMIN_DATABASE_URL_RO']

## All three scratch: nothing to refuse
ScratchGuard.offenders({ 'ADMIN_DATABASE_URL' => @app_ci, 'ADMIN_DATABASE_URL_RO' => @app_ci,
                         'ADMIN_DATABASE_URL_MIGRATIONS' => @app_ci })
#=> []

## Unset URLs are not offences
ScratchGuard.offenders({ 'ADMIN_DATABASE_URL' => @app_ci, 'ADMIN_DATABASE_URL_RO' => '' })
#=> []

## An unparseable URL is refused rather than waved through
ScratchGuard.violation('postgresql://user:p@ss word@host/whatever')
#=> ""

## The default SQLite path is accepted by provenance, not by name
ScratchGuard.violation("sqlite://#{@scratch_dir}/authdb.sqlite3", scratch_dir: @scratch_dir)
#=> nil

## ... and the same file name outside that directory is not
ScratchGuard.violation('sqlite:///var/lib/authdb.sqlite3', scratch_dir: @scratch_dir)
#=> "authdb.sqlite3"

## Sequel's resolved opts[:database] (a bare name) is checkable the same way
[ScratchGuard.violation('onetime_authdb_ci'), ScratchGuard.violation('onetime_authdb')]
#=> [nil, 'onetime_authdb']

## A resolved SQLite path under the suite's own tmpdir passes
ScratchGuard.violation("#{@scratch_dir}/authdb.sqlite3", scratch_dir: @scratch_dir)
#=> nil

## The override is the documented escape hatch, and it is read from the
## env hash passed in — never from the real ENV
ScratchGuard.violation(@migrator_prod, env: { ScratchGuard::DESTRUCTIVE_OVERRIDE => '1' })
#=> nil

## Without it in that hash the same URL is refused, whatever the real ENV says
ScratchGuard.violation(@migrator_prod, env: {})
#=> "onetime_authdb"

## Only the exact value '1' counts
ScratchGuard.violation(@migrator_prod, env: { ScratchGuard::DESTRUCTIVE_OVERRIDE => 'true' })
#=> "onetime_authdb"

## An override in the real ENV does not reach the default-arg-free path used
## by offenders: offenders reads the override from the hash it was given
ENV[ScratchGuard::DESTRUCTIVE_OVERRIDE] = '1'
refused = ScratchGuard.offenders({ 'ADMIN_DATABASE_URL' => @migrator_prod })
ENV.delete(ScratchGuard::DESTRUCTIVE_OVERRIDE)
refused
#=> [['ADMIN_DATABASE_URL', 'onetime_authdb']]

## ... and an override in the hash offenders was given clears the whole set
ScratchGuard.offenders({ 'ADMIN_DATABASE_URL' => @migrator_prod,
                         ScratchGuard::DESTRUCTIVE_OVERRIDE => '1' })
#=> []

## override? is the predicate both use
[ScratchGuard.override?({ ScratchGuard::DESTRUCTIVE_OVERRIDE => '1' }), ScratchGuard.override?({})]
#=> [true, false]

## The refusal message names the variable that failed
ScratchGuard.refusal('ADMIN_DATABASE_URL_MIGRATIONS', 'onetime_authdb').lines.first.strip
#=> 'Refusing to run the specs: ADMIN_DATABASE_URL_MIGRATIONS names database "onetime_authdb".'
