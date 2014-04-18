Feature: Multiple instances
    This feature tests whether multiple instances can be run, and whether
    removing them does not affect the running of other instances

    Scenario: Multiple instances of Auth
        # Standard check to test (non-)existence of a file
        # This file is actually automatically
        The file data/test_nonexistent_db.sqlite3 should not exist

        # This config should have two running instances
        Given I have bundy running with configuration multi_instance/multi_auth.config
        And wait for bundy stderr message BUNDY_STARTED_CC
        And wait for bundy stderr message CMDCTL_STARTED

        # This is a hack. We should actually check if bundy-auth and
        # bundy-auth-2 are started by name. But there's currently no way
        # for a component to find out its name and log it.
        And wait 2 times for bundy stderr message AUTH_SERVER_STARTED

        bundy module Auth should be running
        And bundy module Resolver should not be running
        And bundy module Xfrout should not be running
        And bundy module Zonemgr should not be running
        And bundy module Xfrin should not be running
        And bundy module Stats should not be running
        And bundy module StatsHttpd should not be running

        # Now we use the first step again to see if the file has been created
        The file data/test_nonexistent_db.sqlite3 should exist

        A query for example.com should have rcode REFUSED

        # this also checks whether the process is running
        If I remember the pid of process bundy-auth
        And remember the pid of process bundy-auth-2

        When I remove bundy configuration Init/components value bundy-auth-2
        And wait for new bundy stderr message BUNDY_PROCESS_ENDED

        Then the pid of process bundy-auth should not have changed
        And a query for example.com should have rcode REFUSED

        When I send bundy the following commands
        """
        config add Init/components bundy-auth-2
        config set Init/components/bundy-auth-2/special auth
        config set Init/components/bundy-auth-2/kind needed
        config commit
        """
        And wait for new bundy stderr message AUTH_SERVER_STARTED
        And remember the pid of process bundy-auth-2

        Then the pid of process bundy-auth should not have changed
        A query for example.com should have rcode REFUSED

        When I remove bundy configuration Init/components value bundy-auth
        And wait for new bundy stderr message BUNDY_PROCESS_ENDED
        Then the pid of process bundy-auth-2 should not have changed
        A query for example.com should have rcode REFUSED
