Feature: Message queue tests
    Tests for the message queue daemon.

    Scenario: logging
        # We check the message queue logs.
        Given I have bundy running with configuration default.config
        And wait for bundy stderr message BUNDY_STARTED_CC
        And wait for bundy stderr message MSGQ_START
        And wait for bundy stderr message MSGQ_LISTENER_STARTED
        And wait for bundy stderr message MSGQ_CFGMGR_SUBSCRIBED
        And wait for bundy stderr message CMDCTL_STARTED

        # Check it handles configuration. The configuration is invalid,
        # but it should get there anyway and we abuse it.
        # TODO: Once it has any kind of real command or configuration
        # value, use that instead.
        Then set bundy configuration Msgq to {"nonsense": 1}
        And wait for bundy stderr message MSGQ_CONFIG_DATA
