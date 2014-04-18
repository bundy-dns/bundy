Feature: control with bundyctl
    Assorted tests using bundyctl for the administration of BUNDY.


    Scenario: Removing modules
        # This test runs the original example configuration, which has
        # a number of modules. It then removes all non-essential modules,
        # and checks whether they do disappear from the list of running
        # modules (note that it 'misuses' the help command for this,
        # there is a Init command 'show_processes' but it's output is
        # currently less standardized than 'help')
        Given I have bundy running with configuration bundyctl_commands.config
        And wait for bundy stderr message BUNDY_STARTED_CC
        And wait for bundy stderr message CMDCTL_STARTED
        And wait for bundy stderr message ZONEMGR_STARTED
        And wait for bundy stderr message AUTH_SERVER_STARTED
        And wait for bundy stderr message XFRIN_STARTED
        And wait for bundy stderr message XFROUT_STARTED
        And wait for bundy stderr message STATS_STARTING
        And wait for bundy stderr message STATSHTTPD_STARTED

        Then remove bundy configuration Init/components/NOSUCHMODULE
        last bundyctl output should contain Error

        bundy module Xfrout should be running
        bundy module Stats should be running
        bundy module Zonemgr should be running
        bundy module Xfrin should be running
        bundy module Auth should be running
        bundy module StatsHttpd should be running
        bundy module Resolver should not be running

        Then remove bundy configuration Init/components value bundy-xfrout
        And wait for new bundy stderr message BUNDY_PROCESS_ENDED
        last bundyctl output should not contain Error

        # assuming it won't error for further modules (if it does, the final
        # 'should not be running' tests would fail anyway)
        Then remove bundy configuration Init/components value bundy-stats-httpd
        And wait for new bundy stderr message BUNDY_PROCESS_ENDED
        last bundyctl output should not contain Error

        Then remove bundy configuration Init/components value bundy-stats
        And wait for new bundy stderr message BUNDY_PROCESS_ENDED
        last bundyctl output should not contain Error

        Then remove bundy configuration Init/components value bundy-zonemgr
        And wait for new bundy stderr message BUNDY_PROCESS_ENDED
        last bundyctl output should not contain Error

        Then remove bundy configuration Init/components value bundy-xfrin
        And wait for new bundy stderr message BUNDY_PROCESS_ENDED
        last bundyctl output should not contain Error

        Then remove bundy configuration Init/components value bundy-auth
        And wait for new bundy stderr message BUNDY_PROCESS_ENDED
        last bundyctl output should not contain Error

        # After these ^^^ have been stopped...
        bundy module Xfrout should not be running
        bundy module Zonemgr should not be running
        bundy module Xfrin should not be running
        bundy module Auth should not be running
        bundy module StatsHttpd should not be running
        bundy module Stats should not be running
        bundy module Resolver should not be running

    Scenario: Executing scripts from files
        # This test tests the 'execute' command, which reads and executes
        # bundyctl commands from a file
        Given I have bundy running with configuration bundyctl/bundyctl.config
        And wait for bundy stderr message BUNDY_STARTED_CC
        And wait for bundy stderr message CMDCTL_STARTED

        # first a few bad commands
        When I send bundy the command execute
        last bundyctl output should contain Error
        When I send bundy the command execute file
        last bundyctl output should contain Error
        When I send bundy the command execute file data/commands/nosuchfile
        last bundyctl output should contain Error

        # empty list should be no-op
        When I send bundy the command execute file data/commands/empty
        last bundyctl output should not contain Error

        # some tests of directives like !echo and !verbose
        When I send bundy the command execute file data/commands/directives
        last bundyctl output should not contain Error
        last bundyctl output should not contain commentexample1
        last bundyctl output should contain echoexample2
        last bundyctl output should contain verbosecommentexample3
        last bundyctl output should not contain commentexample4
        last bundyctl output should contain echoexample5
        last bundyctl output should contain echoexample6
        last bundyctl output should contain verbosecommentexample7
        last bundyctl output should not contain commentexample8

        # bad_command contains a bad command, at which point execution should stop
        When I send bundy the command execute file data/commands/bad_command
        last bundyctl output should contain shouldshow
        last bundyctl output should contain Error
        last bundyctl output should not contain shouldnotshow
        # This would fail if the entire list was passed, or the configuration
        # was committed
        send bundy the command config show Init/components
        last bundyctl output should not contain bundy-auth

        # nested_command contains another execute script
        When I send bundy the command execute file data/commands/nested
        last bundyctl output should contain shouldshow
        last bundyctl output should not contain Error

        # show commands from a file
        When I send bundy the command execute file data/commands/bad_command show
        last bundyctl output should not contain Error
        last bundyctl output should contain shouldshow
        last bundyctl output should contain shouldnotshow

    Scenario: Executing builting script init_authoritative_server
        Given I have bundy running with configuration bundyctl/bundyctl.config
        And wait for bundy stderr message BUNDY_STARTED_CC
        And wait for bundy stderr message CMDCTL_STARTED

        When I send bundy the command execute init_authoritative_server show
        # just test some parts of the output
        last bundyctl output should contain /Init/components/bundy-auth/special
        last bundyctl output should contain /Init/components/bundy-zonemgr/kind
        last bundyctl output should contain Please

        # nothing should have been changed
        When I send bundy the command config diff
        last bundyctl output should contain {}

        # ok now make sure modules aren't running, execute it, and make
        # sure modules are running
        bundy module Auth should not be running
        bundy module Xfrout should not be running
        bundy module Xfrin should not be running
        bundy module Zonemgr should not be running

        When I send bundy the following commands:
        """
        execute init_authoritative_server
        config commit
        """
        And wait for bundy stderr message AUTH_SERVER_STARTED
        And wait for bundy stderr message ZONEMGR_STARTED
        And wait for bundy stderr message XFRIN_STARTED
        And wait for bundy stderr message XFROUT_STARTED

        last bundyctl output should not contain Error
        bundy module Auth should be running
        bundy module Xfrout should be running
        bundy module Xfrin should be running
        bundy module Zonemgr should be running

    Scenario: Shutting down a certain module
        # We could test with several modules, but for now we are particularly
        # interested in shutting down cmdctl.  It previously caused hangup,
        # so this scenario confirms it's certainly fixed.  Note: since cmdctl
        # is a "needed" component, shutting it down will result in system
        # shutdown.  So "send bundy command" will fail (it cannot complete
        # "quit").
        Given I have bundy running with configuration bundyctl/bundyctl.config
        And wait for bundy stderr message BUNDY_STARTED_CC
        And wait for bundy stderr message CMDCTL_STARTED

        When I send bundy ignoring failure the command Cmdctl shutdown
        And wait for bundy stderr message CMDCTL_EXITING
        And wait for bundy stderr message BUNDY_SHUTDOWN_COMPLETE
