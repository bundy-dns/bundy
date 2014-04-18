Feature: bundy-stats-httpd module
    Tests the stats httpd module

    Scenario: Check that the module logs and responds to requests
    Given I have bundy running with configuration bundyctl_commands.config
    And wait for bundy stderr message STATSHTTPD_STARTED

    When I request the URL http://127.0.0.1:47811/
    # Should result in redirect, so two query logs
    And wait for new bundy stderr message "GET / HTTP/1.0" 302 -
    And wait for new bundy stderr message "GET /bundy/statistics/xml/ HTTP/1.0" 200 -
    The last http response status code should be 200

    When I request the URL http://127.0.0.1:47811/no_such_url
    And wait for new bundy stderr message "GET /no_such_url HTTP/1.0" 404 -
    The last http response status code should be 404
