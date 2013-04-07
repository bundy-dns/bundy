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

#include <auth/rrl/rrl_entry.h>
#include <auth/rrl/rrl_result.h>
#include <auth/rrl/rrl_rate.h>
#include <auth/rrl/rrl_key.h>

#include <asiolink/io_endpoint.h>
#include <asiolink/io_address.h>

#include <dns/name.h>
#include <dns/labelsequence.h>
#include <dns/rrtype.h>
#include <dns/rrclass.h>

#include <gtest/gtest.h>

#include <boost/scoped_ptr.hpp>

#include <vector>

using namespace isc::auth::rrl::detail;
using namespace isc::auth::rrl;
using namespace isc::dns;
using isc::asiolink::IOEndpoint;
using isc::asiolink::IOAddress;
using std::vector;

namespace {

const uint32_t MASK4 = htonl(0xffffff00);
const uint32_t MASK6[4] = { 0xffffffff, htonl(0xfffffff0), 0, 0 };

// For constructing TimestampBases; we don't need it in this test.
void noopCallback(size_t) {}

class RRLEntryTest : public ::testing::Test {
protected:
    RRLEntryTest() :
        ep_(IOEndpoint::create(IPPROTO_UDP, IOAddress("192.0.2.1"), 53210)),
        qname_("example.com"), qlabels_(qname_),
        rates_(0, 1, 0),        // disable RRL for normal responses and errors
        ts_bases_(10, noopCallback), entries_(42)
    {
        const RRType qtype = RRType::A();
        const RRClass qclass = RRClass::IN();

        entries_[0].reset(RRLKey(*ep_, qtype, &qlabels_, qclass, RESPONSE_QUERY,
                                 MASK4, MASK6, 4200), 0);
        entries_[1].reset(RRLKey(*ep_, qtype, &qlabels_, qclass,
                                 RESPONSE_NXDOMAIN, MASK4, MASK6, 4200), 0);
    }

private:
    boost::scoped_ptr<const IOEndpoint> ep_;
    const Name qname_;
    const LabelSequence qlabels_;
protected:
    RRLRate rates_;
    RRLEntry::TimestampBases ts_bases_;
    vector<RRLEntry> entries_;
};

TEST_F(RRLEntryTest, construct) {
    RRLEntry entry;
    EXPECT_FALSE(entry.hash_hook_.is_linked());
    EXPECT_FALSE(entry.lru_hook_.is_linked());
}

TEST_F(RRLEntryTest, age) {
    // On initialization entry is unusable and getAge() should return "forever"
    RRLEntry& entry = entries_[0];
    EXPECT_EQ(RRLEntry::TIMESTAMP_FOREVER, entry.getAge(ts_bases_, 5));

    // set age, and get it again
    entry.setAge(ts_bases_, 20);
    EXPECT_EQ(5, entry.getAge(ts_bases_, 25));

    // try to set past time than the current base.
    entry.setAge(ts_bases_, 9); // will be reset to base time, 10.
    EXPECT_EQ(5, entry.getAge(ts_bases_, 15));

    // try to set "distant" past time causes base update
    entry.setAge(ts_bases_, 4); // base will be updated to 4
    EXPECT_EQ(11, entry.getAge(ts_bases_, 15));

    // try to set "distant" future time causes base update
    entry.setAge(ts_bases_, 4099); // 4 (current) + 4095
    EXPECT_EQ(1, entry.getAge(ts_bases_, 4100));
}

TEST_F(RRLEntryTest, updateBalance) {
    time_t now = 12;

    // RRL is disabled for normal responses, so the result should be "OK"
    EXPECT_EQ(RRL_OK, entries_[0].updateBalance(ts_bases_, rates_, 0, now, 15));
    // getResponseBalance is always 0 despite the value of age
    EXPECT_EQ(0, entries_[0].getResponseBalance(rates_, 0));
    EXPECT_EQ(0, entries_[0].getResponseBalance(rates_, 1));
    EXPECT_EQ(0, entries_[0].getResponseBalance(rates_, 100));

    // For NXDOMAIN, credit/sec is 1, so the first response is okay, but the
    // second (in the same sec window) will be dropped
    EXPECT_EQ(RRL_OK, entries_[1].updateBalance(ts_bases_, rates_, 0, now, 15));
    EXPECT_EQ(0, entries_[1].getResponseBalance(rates_, 0));
    EXPECT_EQ(RRL_DROP, entries_[1].updateBalance(ts_bases_, rates_, 0, now,
                                                  15));
    EXPECT_EQ(-1, entries_[1].getResponseBalance(rates_, 0));
    // 2 sec later, the balance will be positive again.
    EXPECT_EQ(1, entries_[1].getResponseBalance(rates_, 2));
    EXPECT_EQ(RRL_OK, entries_[1].updateBalance(ts_bases_, rates_, 0, now + 2,
                                                15));
    EXPECT_EQ(0, entries_[1].getResponseBalance(rates_, 2));
    // next one will be dropped again, and after 3 seconds, the balance
    // could become 2, but it can't be larger than rate, so should actually
    // be 1.
    EXPECT_EQ(RRL_DROP, entries_[1].updateBalance(ts_bases_, rates_, 0, now + 2,
                                                  15));
    EXPECT_EQ(1, entries_[1].getResponseBalance(rates_, 3));
    EXPECT_EQ(RRL_OK, entries_[1].updateBalance(ts_bases_, rates_, 0, now + 5,
                                                15));
    EXPECT_EQ(RRL_DROP, entries_[1].updateBalance(ts_bases_, rates_, 0, now + 5,
                                                  15));
    for (int balance = -1; balance >= -15; --balance) {
        EXPECT_EQ(balance, entries_[1].getResponseBalance(rates_, 0));
        EXPECT_EQ(RRL_DROP, entries_[1].updateBalance(ts_bases_, rates_, 0,
                                                      now + 5, 15));
    }
    EXPECT_EQ(-15, entries_[1].getResponseBalance(rates_, 0));
}
}
