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
#include <auth/rrl/rrl_entry.h>
#include <auth/rrl/rrl_key.h>
#include <auth/rrl/rrl_rate.h>

#include <exceptions/exceptions.h>

#include <dns/name.h>
#include <dns/labelsequence.h>
#include <dns/rrtype.h>
#include <dns/rrclass.h>

#include <asiolink/io_endpoint.h>
#include <asiolink/io_address.h>

#include <gtest/gtest.h>

using namespace isc::auth::rrl::detail;
using namespace isc::dns;
using isc::asiolink::IOEndpoint;
using isc::asiolink::IOAddress;

namespace {

const uint32_t MASK4 = htonl(0xffffff00);
const uint32_t MASK6[4] = { 0xffffffff, htonl(0xfffffff0), 0, 0 };

// For constructing TimestampBases; we don't need it in this test.
void noopCallback(size_t) {}

class RRLTableTest : public ::testing::Test {
protected:
    RRLTableTest() :
        ep_(IOEndpoint::create(IPPROTO_UDP, IOAddress("192.0.2.1"), 53210)),
        qname_("example.com"), qlabels_(qname_),
        key_(*ep_, RRType::A(), &qlabels_, RRClass::IN(), RESPONSE_QUERY, MASK4,
             MASK6, 1),
        rates_(5, 1, 0),
        ts_bases_(10, noopCallback),
        table_(500)
    {}

protected:
    boost::scoped_ptr<const IOEndpoint> ep_;
    const Name qname_;
    const LabelSequence qlabels_;
    const RRLKey key_;
    RRLRate rates_;
    RRLEntry::TimestampBases ts_bases_;
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
    EXPECT_EQ(212, table_.getBinSize()); // old bins (100) + new bins (112)
    EXPECT_EQ(0, table_.getGeneration());

    // If a large number of entries are added, the new bin size will be set
    // to that value.
    table_.expandEntries(200);  // total 310 entries
    table_.expand(now);
    EXPECT_EQ(422, table_.getBinSize()); // old bins (112) + new bins (310)
    EXPECT_EQ(1, table_.getGeneration());
}

TEST_F(RRLTableTest, getEntry) {
    table_.expandEntries(100);
    table_.expand(10);

    // First search.  It will come from the free (LRU) list and has invalid
    // timestamp.
    const RRLEntry* entry = table_.getEntry(key_, ts_bases_, rates_, 10, 15);
    EXPECT_TRUE(entry);
    EXPECT_EQ(RRLEntry::TIMESTAMP_FOREVER, entry->getAge(ts_bases_, 15));
    EXPECT_TRUE(entry->hash_hook_.is_linked());
    EXPECT_EQ(1, entry->getHashGen());

    // We can find it again.
    EXPECT_EQ(entry, table_.getEntry(key_, ts_bases_, rates_, 10, 15));

    // Manually expand the table to move the current hash table to "old", then
    // search again.  Should still succeed.
    table_.expand(10);
    EXPECT_EQ(212, table_.getBinSize()); // 2 hash tables, 2 sets of bins
    EXPECT_EQ(entry, table_.getEntry(key_, ts_bases_, rates_, 10, 15));
    EXPECT_EQ(0, entry->getHashGen()); // gen ID should have been updated

    // Similar to the previous case, but this is a new entry and can't be
    // found in either hash tables.  bin size will shrink.
    table_.expand(10);
    const RRLEntry* entry2 = table_.getEntry(
        RRLKey(*ep_, RRType::NS(), &qlabels_, RRClass::IN(), RESPONSE_QUERY,
               MASK4, MASK6, 1), ts_bases_, rates_, 30, 15);
    EXPECT_TRUE(entry2);
    EXPECT_EQ(126, table_.getBinSize()); // 126 = 112 * 1.125
    EXPECT_EQ(100, table_.getEntryCount());
}

TEST_F(RRLTableTest, lru) {
    // Create a table with a very small capacity
    table_.expandEntries(2);
    table_.expand(10);
    EXPECT_EQ(2, table_.getEntryCount());
    EXPECT_EQ(2, table_.getBinSize());

    // fill in the table with allowable number of entries.
    // LRU list will become: entry2->entry
    RRLEntry* entry = table_.getEntry(key_, ts_bases_, rates_, 10, 15);
    EXPECT_TRUE(entry);
    RRLEntry* entry2 = table_.getEntry(
        RRLKey(*ep_, RRType::NS(), &qlabels_, RRClass::IN(), RESPONSE_QUERY,
               MASK4, MASK6, 1), ts_bases_, rates_, 20, 15);
    EXPECT_TRUE(entry2);
    EXPECT_NE(entry, entry2);

    // another search will replace the "oldest" one (= entry).
    // LRU list will become: entry3->entry2
    RRLEntry* entry3 = table_.getEntry(
        RRLKey(*ep_, RRType::MX(), &qlabels_, RRClass::IN(), RESPONSE_QUERY,
               MASK4, MASK6, 1), ts_bases_, rates_, 20, 15);
    EXPECT_EQ(entry, entry3);

    // look for entry2 again.  LRU list will become: entry2->entry3
    EXPECT_EQ(entry2, table_.getEntry(
                  RRLKey(*ep_, RRType::NS(), &qlabels_, RRClass::IN(),
                         RESPONSE_QUERY, MASK4, MASK6, 1), ts_bases_, rates_,
                  20, 15));
    // So another new search will purge entry3 (LRU will be: entry4->entry2)
    RRLEntry* entry4 = table_.getEntry(
        RRLKey(*ep_, RRType::AAAA(), &qlabels_, RRClass::IN(), RESPONSE_QUERY,
               MASK4, MASK6, 1), ts_bases_, rates_, 20, 15);
    EXPECT_EQ(entry3, entry4);

    // expand the table, and do the same thing.
    table_.expand(10);
    EXPECT_EQ(2, table_.getEntryCount());
    EXPECT_EQ(4, table_.getBinSize());
    // After this LRU will be: entry2 (in new table)->entry4 (in old table)
    EXPECT_EQ(entry2, table_.getEntry(
                  RRLKey(*ep_, RRType::NS(), &qlabels_, RRClass::IN(),
                         RESPONSE_QUERY, MASK4, MASK6, 1), ts_bases_,
                  rates_, 20, 15));
    // Another new search will purge entry4 (LRU will be: entry5->entry2)
    RRLEntry* entry5 = table_.getEntry(
        RRLKey(*ep_, RRType::A(), &qlabels_, RRClass::IN(),
               RESPONSE_QUERY, MASK4, MASK6, 1), ts_bases_, rates_, 20, 15);
    EXPECT_EQ(entry4, entry5);
    EXPECT_EQ(4, table_.getBinSize()); // old table is still there

    // make entry2 penalized, so it'll still be penalized in 2 sec.
    // the first query is given a credit of 5 units and consumes one of
    // them. subsequent 4 queries within the same second consume all of them,
    // making the balance zero.  With further 10 queries make sure queries
    // won't be granted within 2 seconds.
    // The resulting LRU will be: entry6->entry2
    for (int i = 0; i < 15; ++i) {
        entry2->updateBalance(ts_bases_, rates_, 0, 20, 15);
    }
    EXPECT_EQ(0, entry2->getResponseBalance(rates_, 2));
    RRLEntry* entry6 = table_.getEntry(
        RRLKey(*ep_, RRType::TXT(), &qlabels_, RRClass::IN(),
               RESPONSE_QUERY, MASK4, MASK6, 1), ts_bases_, rates_, 22, 15);
    EXPECT_EQ(entry5, entry6);

    // make entry6 penalized too.  No more viable entries to replace, so
    // new entry(ies) will be created.
    // The resulting LRU: entry7->entry6->entry2
    for (int i = 0; i < 15; ++i) {
        entry6->updateBalance(ts_bases_, rates_, 0, 20, 15);
    }
    EXPECT_EQ(0, entry6->getResponseBalance(rates_, 2));
    RRLEntry* entry7 = table_.getEntry(
        RRLKey(*ep_, RRType::DS(), &qlabels_, RRClass::IN(),
               RESPONSE_QUERY, MASK4, MASK6, 1), ts_bases_, rates_, 22, 15);
    EXPECT_TRUE(entry7);
    EXPECT_EQ(3, table_.getEntryCount()); // count is increased

    // If the least recently used entry was still used quite recently,
    // (less than 2 sec), it will also trigger more entry creation.
    RRLEntry* entry8 = table_.getEntry(
        RRLKey(*ep_, RRType::DLV(), &qlabels_, RRClass::IN(),
               RESPONSE_QUERY, MASK4, MASK6, 1), ts_bases_, rates_, 21, 15);
    EXPECT_TRUE(entry8);
    EXPECT_EQ(5, table_.getEntryCount()); // new # entries = 3 + (3 + 1)/2
}

TEST_F(RRLTableTest, lruInSmallTable) {
    // Similar to the previous test, but with a table that has a very small
    // capacity.
    RRLTable small_table(1);
    small_table.expandEntries(1);
    small_table.expand(10);

    // Look for and create a new entry, and get it penalized.
    RRLEntry* entry = small_table.getEntry(key_, ts_bases_, rates_, 10, 15);
    for (int i = 0; i < 15; ++i) {
        entry->updateBalance(ts_bases_, rates_, 0, 20, 15);
    }

    // Another search would normally result in creating new entries, but due
    // to the limited capacity the existing penalized entry will be replaced.
    RRLEntry* entry2 = small_table.getEntry(
        RRLKey(*ep_, RRType::NS(), &qlabels_, RRClass::IN(),
               RESPONSE_QUERY, MASK4, MASK6, 1), ts_bases_, rates_, 22, 15);
    EXPECT_EQ(entry, entry2);
}

TEST_F(RRLTableTest, autoExpand) {
    // begin with a minimum number of entry.
    table_.expandEntries(1);
    table_.expand(10);
    EXPECT_EQ(1, table_.getBinSize());

    // Until 100 (hardcoded limit) lookups, there's no expansion
    for (int i = 0; i < 100; ++i) {
        RRLEntry* entry = table_.getEntry(
            RRLKey(*ep_, RRType(i), &qlabels_, RRClass::IN(),
                   RESPONSE_QUERY, MASK4, MASK6, 1), ts_bases_,
            rates_, 20, 15);
        entry->updateBalance(ts_bases_, rates_, 0, 20, 15);
    }
    EXPECT_EQ(1, table_.getBinSize());
    // Next lookup will trigger expansion.
    EXPECT_TRUE(table_.getEntry(
                    RRLKey(*ep_, RRType(101), &qlabels_, RRClass::IN(),
                           RESPONSE_QUERY, MASK4, MASK6, 1), ts_bases_, rates_,
                    25, 15));
    const size_t expected_new_bins = table_.getEntryCount() + 1;
    EXPECT_EQ(expected_new_bins, table_.getBinSize());

    // Internal counters should have been reset, so there won't be another
    // expansion for a while.
    EXPECT_TRUE(table_.getEntry(
                    RRLKey(*ep_, RRType(102), &qlabels_, RRClass::IN(),
                           RESPONSE_QUERY, MASK4, MASK6, 1), ts_bases_, rates_,
                    30, 15));
    EXPECT_EQ(expected_new_bins, table_.getBinSize());
}
}
