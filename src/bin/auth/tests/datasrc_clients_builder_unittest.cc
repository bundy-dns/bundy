// Copyright (C) 2012  Internet Systems Consortium, Inc. ("ISC")
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
// REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
// AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
// INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
// LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
// OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
// PERFORMANCE OF THIS SOFTWARE.

#include <cc/data.h>

#include <auth/datasrc_clients_mgr.h>
#include "test_datasrc_clients_mgr.h"

#include <gtest/gtest.h>

#include <boost/function.hpp>

using isc::data::ConstElementPtr;
using namespace isc::datasrc;
using namespace isc::auth::datasrc_clientmgr_internal;

namespace {
class DataSrcClientsBuilderTest : public ::testing::Test {
protected:
    DataSrcClientsBuilderTest() :
        builder(&command_queue, &cond, &queue_mutex, &clients_map, &map_mutex),
        cond(command_queue, delayed_command_queue),
        shutdown_cmd(SHUTDOWN, ConstElementPtr()),
        noop_cmd(NOOP, ConstElementPtr())
    {}

    TestDataSrcClientsBuilder builder;
    std::list<Command> command_queue; // test command queue
    std::list<Command> delayed_command_queue; // commands available after wait
    ClientListMapPtr clients_map; // configured clients
    TestCondVar cond;
    TestMutex queue_mutex;
    TestMutex map_mutex;
    const Command shutdown_cmd;
    const Command noop_cmd;
};

TEST_F(DataSrcClientsBuilderTest, runSingleCommand) {
    // A simplest case, just to check the basic behavior.
    command_queue.push_back(shutdown_cmd);
    builder.run();
    EXPECT_TRUE(command_queue.empty());
    EXPECT_EQ(0, cond.wait_count); // no wait because command queue is not empty
    EXPECT_EQ(1, queue_mutex.lock_count);
    EXPECT_EQ(1, queue_mutex.unlock_count);
}

TEST_F(DataSrcClientsBuilderTest, runMultiCommands) {
    // Two NOOP commands followed by SHUTDOWN.  We should see two doNoop()
    // calls.
    command_queue.push_back(noop_cmd);
    command_queue.push_back(noop_cmd);
    command_queue.push_back(shutdown_cmd);
    builder.run();
    EXPECT_TRUE(command_queue.empty());
    EXPECT_EQ(1, queue_mutex.lock_count);
    EXPECT_EQ(1, queue_mutex.unlock_count);
    EXPECT_EQ(2, queue_mutex.noop_count);
}

TEST_F(DataSrcClientsBuilderTest, exception) {
    // Let the noop command handler throw exceptions and see if we can see
    // them.  Right now, we simply abort to prevent the system from running
    // with half-broken state.  Eventually we should introduce a better
    // error handling.
    command_queue.push_back(noop_cmd);
    queue_mutex.throw_from_noop = TestMutex::EXCLASS;
    EXPECT_DEATH_IF_SUPPORTED({builder.run();}, "");

    command_queue.push_back(noop_cmd);
    queue_mutex.throw_from_noop = TestMutex::INTEGER;
    EXPECT_DEATH_IF_SUPPORTED({builder.run();}, "");
}

TEST_F(DataSrcClientsBuilderTest, condWait) {
    // command_queue is originally empty, so it will require waiting on
    // condvar.  specialized wait() will make the delayed command available.
    delayed_command_queue.push_back(shutdown_cmd);
    builder.run();

    // There should be one call to wait()
    EXPECT_EQ(1, cond.wait_count);
    // wait() effectively involves one more set of lock/unlock, so we have
    // two in total
    EXPECT_EQ(2, queue_mutex.lock_count);
    EXPECT_EQ(2, queue_mutex.unlock_count);
}

TEST_F(DataSrcClientsBuilderTest, reconfigure) {
    // Full testing of different configurations is not here, but we
    // do check a few cases of correct and erroneous input, to verify
    // the error handling

    // A command structure we'll modify to send different commands
    Command reconfig_cmd(RECONFIGURE, ConstElementPtr());

    // Initially, no clients should be there
    EXPECT_EQ(ClientListMapPtr(), clients_map);

    // A config that doesn't do much except be accepted
    ConstElementPtr good_config = isc::data::Element::fromJSON(
        "{"
        "\"IN\": [{"
        "   \"type\": \"MasterFiles\","
        "   \"params\": {},"
        "   \"cache-enable\": true"
        "}]"
        "}"
    );

    // A configuration that is 'correct' in the top-level, but contains
    // bad data for the type it specifies
    ConstElementPtr bad_config = isc::data::Element::fromJSON(
        "{"
        "\"IN\": [{"
        "   \"type\": \"MasterFiles\","
        "   \"params\": { \"foo\": [ 1, 2, 3, 4  ]},"
        "   \"cache-enable\": true"
        "}]"
        "}"
    );

    reconfig_cmd.second = good_config;
    EXPECT_TRUE(builder.handleCommand(reconfig_cmd));
    EXPECT_EQ(1, clients_map->size());
    EXPECT_EQ(1, map_mutex.lock_count);

    // Store the nonempty clients map we now have
    ClientListMapPtr working_config_clients(clients_map);

    // If a 'bad' command argument got here, the config validation should
    // have failed already, but still, the handler should return true,
    // and the clients_map should not be updated.
    reconfig_cmd.second = isc::data::Element::create("{ \"foo\": \"bar\" }");
    EXPECT_TRUE(builder.handleCommand(reconfig_cmd));
    EXPECT_EQ(working_config_clients, clients_map);
    // Building failed, so map mutex should not have been locked again
    EXPECT_EQ(1, map_mutex.lock_count);

    // The same for a configuration that has bad data for the type it
    // specifies
    reconfig_cmd.second = bad_config;
    builder.handleCommand(reconfig_cmd);
    EXPECT_TRUE(builder.handleCommand(reconfig_cmd));
    EXPECT_EQ(working_config_clients, clients_map);
    // Building failed, so map mutex should not have been locked again
    EXPECT_EQ(1, map_mutex.lock_count);

    // The same goes for an empty parameter (it should at least be
    // an empty map)
    reconfig_cmd.second = ConstElementPtr();
    EXPECT_TRUE(builder.handleCommand(reconfig_cmd));
    EXPECT_EQ(working_config_clients, clients_map);
    EXPECT_EQ(1, map_mutex.lock_count);

    // Reconfigure again with the same good clients, the result should
    // be a different map than the original, but not an empty one.
    reconfig_cmd.second = good_config;
    EXPECT_TRUE(builder.handleCommand(reconfig_cmd));
    EXPECT_NE(working_config_clients, clients_map);
    EXPECT_EQ(1, clients_map->size());
    EXPECT_EQ(2, map_mutex.lock_count);

    // And finally, try an empty config to disable all datasource clients
    reconfig_cmd.second = isc::data::Element::createMap();
    EXPECT_TRUE(builder.handleCommand(reconfig_cmd));
    EXPECT_EQ(0, clients_map->size());
    EXPECT_EQ(3, map_mutex.lock_count);

    // Also check if it has been cleanly unlocked every time
    EXPECT_EQ(3, map_mutex.unlock_count);
}

TEST_F(DataSrcClientsBuilderTest, shutdown) {
    EXPECT_FALSE(builder.handleCommand(shutdown_cmd));
}

TEST_F(DataSrcClientsBuilderTest, badCommand) {
    // out-of-range command ID
    EXPECT_THROW(builder.handleCommand(Command(NUM_COMMANDS,
                                               ConstElementPtr())),
                 isc::Unexpected);
}

} // unnamed namespace