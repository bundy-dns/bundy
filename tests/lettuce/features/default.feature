Feature: default bundy config
    Tests for the default configuration of bundy.

    Scenario: Check that only the default components are running
    Given I have bundy running with configuration default.config
    And wait for bundy stderr message BUNDY_STARTED_CC
    And wait for bundy stderr message CMDCTL_STARTED
    And wait for bundy stderr message STATS_STARTING

    # These should be running
    bundy module Init should be running
    And bundy module Logging should be running
    And bundy module Stats should be running

    # These should not be running
    bundy module Resolver should not be running
    And bundy module Xfrout should not be running
    And bundy module Zonemgr should not be running
    And bundy module Xfrin should not be running
    And bundy module Auth should not be running
    And bundy module StatsHttpd should not be running
