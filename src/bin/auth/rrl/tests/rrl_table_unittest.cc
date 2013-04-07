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

#include <auth/rrl/rrl_table.h>

#include <exceptions/exceptions.h>

#include <gtest/gtest.h>

using namespace isc::auth::rrl::detail;

namespace {

class RRLTableTest : public ::testing::Test {
protected:
    RRLTableTest() : table_(500) {}

    RRLTable table_;
};

TEST_F(RRLTableTest, expandEntries) {
    EXPECT_EQ(0, table_.getEntryCount());

    // expanding with 0 is invalid
    EXPECT_THROW(table_.expandEntries(0), isc::InvalidParameter);

    // We can expand entries any times until it reaches the max.
    table_.expandEntries(10);
    EXPECT_EQ(10, table_.getEntryCount());

    table_.expandEntries(100);
    EXPECT_EQ(110, table_.getEntryCount());

    // If it would exceed the max, expansion will stop there.
    table_.expandEntries(400);  // try to add 400 more, but can only add 390
    EXPECT_EQ(500, table_.getEntryCount());

    // Once reached the max, adding more is no-op.
    table_.expandEntries(1);
    EXPECT_EQ(500, table_.getEntryCount());

    // expanding with 0 is still invalid
    EXPECT_THROW(table_.expandEntries(0), isc::InvalidParameter);

    // If max number is set to 0 on construction, there's no internal
    // limitation on expansion.
    RRLTable large_table(0);
    large_table.expandEntries(100);
    EXPECT_EQ(100, large_table.getEntryCount());
    large_table.expandEntries(1000);
    EXPECT_EQ(1100, large_table.getEntryCount());
}

TEST_F(RRLTableTest, expand) {
    std::time_t now = 42;       // arbitrary chosen
    // Before adding entries expand() is no-op
    table_.expand(now);
    EXPECT_EQ(0, table_.getBinSize());
    EXPECT_EQ(-1, table_.getGeneration());

    // Add some entries, and expand the table.  bin size should == # entries.
    table_.expandEntries(100);
    table_.expand(now);
    EXPECT_EQ(100, table_.getBinSize());
    EXPECT_EQ(1, table_.getGeneration());

    // Expand the table further.  If # added entries is small, the new bin size
    // is 1.125 times the old size.
    table_.expandEntries(10);   // total 110 entries
    table_.expand(now);
    EXPECT_EQ(212, table_.getBinSize()); // prev bins (100) + new bins (112)
    EXPECT_EQ(0, table_.getGeneration());

    // If a large number of entries are added, the new bin size will be set
    // to that value.
    table_.expandEntries(200);  // total 310 entries
    table_.expand(now);
    EXPECT_EQ(422, table_.getBinSize()); // prev bins (112) + new bins (310)
    EXPECT_EQ(1, table_.getGeneration());
}
}
