Feature: Basic Authoritative DNS server
    This feature set is for testing the execution of the bundy-auth
    component using its default datasource configurations. This
    will start it and perform queries against it.

    Scenario: Query builtin bind zone
        Given I have bundy running with configuration auth/auth_basic.config
        And wait for bundy stderr message BUNDY_STARTED_CC
        And wait for bundy stderr message CMDCTL_STARTED
        And wait for bundy stderr message AUTH_SERVER_STARTED

        bundy module Auth should be running
        And bundy module Resolver should not be running

        A query for example.com should have rcode REFUSED
        A query for version.bind type TXT class CH should have rcode NOERROR
        A query for authors.bind type TXT class CH should have rcode NOERROR

        # TODO: to be compatible with BIND 9
        # A query for nonexistent.bind type TXT class CH should have rcode REFUSED
