Feature: Master loader feature
    This feature is a collection of tests for the zone file loader in
    BUNDY.

    Scenario: $GENERATE support
        Given I have bundy running with configuration generate.config
        And wait for bundy stderr message BUNDY_STARTED_CC
        And wait for bundy stderr message CMDCTL_STARTED
        And wait for bundy stderr message AUTH_SERVER_STARTED

        bundy module Auth should be running
        And bundy module Resolver should not be running
        And bundy module Xfrout should not be running
        And bundy module Zonemgr should not be running
        And bundy module Xfrin should not be running
        And bundy module Stats should not be running
        And bundy module StatsHttpd should not be running

        A query for www.example.org should have rcode NXDOMAIN
        The SOA serial for example.org should be 12341

        A query for host0.example.org should have rcode NXDOMAIN
        A query for host1.example.org should have rcode NOERROR
        The answer section of the last query response should be
        """
        host1.example.org.        3600    IN      A       192.0.2.1
        """
        A query for host2.example.org should have rcode NOERROR
        The answer section of the last query response should be
        """
        host2.example.org.        3600    IN      A       192.0.2.2
        """
        A query for host3.example.org should have rcode NOERROR
        The answer section of the last query response should be
        """
        host3.example.org.        3600    IN      A       192.0.2.3
        """
        A query for host4.example.org should have rcode NOERROR
        The answer section of the last query response should be
        """
        host4.example.org.        3600    IN      A       192.0.2.4
        """
        A query for host5.example.org should have rcode NXDOMAIN

        A query for example.org type NS should have rcode NOERROR
        The answer section of the last query response should be
        """
        example.org.              3600    IN      NS      ns1.example.org.
        example.org.              3600    IN      NS      ns2.example.org.
        """
