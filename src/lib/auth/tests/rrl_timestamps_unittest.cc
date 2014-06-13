// Copyright (C) 2013  Internet Systems Consortium, Inc. ("ISC")
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

#include <auth/rrl_timestamps.h>

#include <gtest/gtest.h>

#include <boost/bind.hpp>

#include <stdexcept>
#include <ctime>
#include <utility>

using namespace bundy::auth::detail;

namespace {

class RRLTimestampsTest : public ::testing::Test {
protected:
    RRLTimestampsTest() :
        callback_param_(65536), // set to some large dummy value
        ts_bases_(100, boost::bind(&RRLTimestampsTest::callback, this, _1))
    {}

    size_t callback_param_;     // remember parameter of the latest callback

    typedef RRLTimeStampBases<4, 4096> TestBases; 
    TestBases ts_bases_;

    void callback(size_t gen) { callback_param_ = gen; }

};

TEST_F(RRLTimestampsTest, deltaTime) {
    // Normal case: now > recorded timestamp
    EXPECT_EQ(10, TestBases::deltaTime(10, 20));
    // Same if now == timestamp
    EXPECT_EQ(0, TestBases::deltaTime(10, 10));

    // timestamp is "near future".  diff is considered 0.
    EXPECT_EQ(0, TestBases::deltaTime(11, 10));

    // timestamp in "distant future" is considered clock changes.
    EXPECT_EQ(4096, TestBases::deltaTime(16, 10));
}

TEST_F(RRLTimestampsTest, getCurrentBase) {
    std::pair<std::time_t, size_t> result;
    std::time_t now = 100;

    // Initially the current base is stored in the 0-th entry of the ringer
    // buffer.  If it's sufficiently recent, that pair will be returned.
    result = ts_bases_.getCurrentBase(now + 5);
    EXPECT_EQ(100, result.first);
    EXPECT_EQ(0, result.second);
    EXPECT_EQ(65536, callback_param_); // callback shouldn't be called

    // If the current base is in "future", the given 'now' is basically
    // re-interpreted as if it's that future value.
    result = ts_bases_.getCurrentBase(now - 1);
    EXPECT_EQ(100, result.first);
    EXPECT_EQ(0, result.second);
    EXPECT_EQ(65536, callback_param_);

    // If the current base is too old, the buffer is updated.
    now += 4095;
    result = ts_bases_.getCurrentBase(now);
    EXPECT_EQ(now, result.first);
    EXPECT_EQ(1, result.second);
    EXPECT_EQ(1, callback_param_); // callback should be called for 1st gen

    // If the current base is in "far future", it's assumed to result from
    // clock change and the base is updated, too.
    now -= 6;
    result = ts_bases_.getCurrentBase(now);
    EXPECT_EQ(now, result.first);
    EXPECT_EQ(2, result.second);
    EXPECT_EQ(2, callback_param_);

    // With two more updates, it overrides the 0th generation again.
    EXPECT_EQ(3, ts_bases_.getCurrentBase(now + 4095).second);
    EXPECT_EQ(0, ts_bases_.getCurrentBase(now + 4095 + 4095).second);

    // Check behavior of getBaseByGen() after some updates
    EXPECT_EQ(now + 4095 + 4095, ts_bases_.getBaseByGen(0));
    EXPECT_EQ(4195, ts_bases_.getBaseByGen(1));
    EXPECT_EQ(4195 - 6, ts_bases_.getBaseByGen(2));
    EXPECT_EQ(4195 - 6 + 4095, ts_bases_.getBaseByGen(3));
    // out-of-range generation will result in an exception
    EXPECT_THROW(ts_bases_.getBaseByGen(4), std::out_of_range);
}
}
