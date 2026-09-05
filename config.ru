# config.ru
#
# frozen_string_literal: true

require_relative 'lib/rodauth_admin'

RodauthAdmin.boot!

run RodauthAdmin::App.freeze.app
