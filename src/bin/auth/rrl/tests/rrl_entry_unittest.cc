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
#include <auth/rrl/rrl_name_pool.h>
#include <auth/rrl/logger.h>

#include <asiolink/io_endpoint.h>
#include <asiolink/io_address.h>

#include <dns/name.h>
#include <dns/labelsequence.h>
#include <dns/rcode.h>
#include <dns/rrtype.h>
#include <dns/rrclass.h>

#include <gtest/gtest.h>

#include <boost/scoped_ptr.hpp>

#include <vector>
#include <string>

#include <arpa/inet.h>

using namespace isc::auth::rrl::detail;
using namespace isc::auth::rrl;
using namespace isc::dns;
using isc::asiolink::IOEndpoint;
using isc::asiolink::IOAddress;
using std::vector;

namespace {

uint32_t
htonlWrapper(uint32_t val) {
    return (htonl(val));
}

const uint32_t MASK4 = htonlWrapper(0xffffff00);
const uint32_t MASK6[4] = { 0xffffffff, htonlWrapper(0xfffffff0), 0, 0 };

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

protected:
    boost::scoped_ptr<const IOEndpoint> ep_;
    const Name qname_;
    const LabelSequence qlabels_;
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
    EXPECT_EQ(RRL_OK, entries_[0].updateBalance(ts_bases_, rates_, 0, 0, now,
                                                15));
    // getResponseBalance is always 0 despite the value of age
    EXPECT_EQ(0, entries_[0].getResponseBalance(rates_, 0));
    EXPECT_EQ(0, entries_[0].getResponseBalance(rates_, 1));
    EXPECT_EQ(0, entries_[0].getResponseBalance(rates_, 100));

    // For NXDOMAIN, credit/sec is 1, so the first response is okay, but the
    // second (in the same sec window) will be dropped
    EXPECT_EQ(RRL_OK, entries_[1].updateBalance(ts_bases_, rates_, 0, 0, now,
                                                15));
    EXPECT_EQ(0, entries_[1].getResponseBalance(rates_, 0));
    EXPECT_EQ(RRL_DROP, entries_[1].updateBalance(ts_bases_, rates_, 0, 0, now,
                                                  15));
    EXPECT_EQ(-1, entries_[1].getResponseBalance(rates_, 0));
    // 2 sec later, the balance will be positive again.
    EXPECT_EQ(1, entries_[1].getResponseBalance(rates_, 2));
    EXPECT_EQ(RRL_OK, entries_[1].updateBalance(ts_bases_, rates_, 0, 0,
                                                now + 2, 15));
    EXPECT_EQ(0, entries_[1].getResponseBalance(rates_, 0));
    // next one will be dropped again, and after 3 seconds, the balance
    // could become 2, but it can't be larger than rate, so should actually
    // be 1.
    EXPECT_EQ(RRL_DROP, entries_[1].updateBalance(ts_bases_, rates_, 0, 0,
                                                  now + 2, 15));
    EXPECT_EQ(1, entries_[1].getResponseBalance(rates_, 3));
    EXPECT_EQ(RRL_OK, entries_[1].updateBalance(ts_bases_, rates_, 0, 0,
                                                now + 5, 15));
    EXPECT_EQ(RRL_DROP, entries_[1].updateBalance(ts_bases_, rates_, 0, 0,
                                                  now + 5, 15));
    for (int balance = -1; balance >= -15; --balance) {
        EXPECT_EQ(balance, entries_[1].getResponseBalance(rates_, 0));
        EXPECT_EQ(RRL_DROP, entries_[1].updateBalance(ts_bases_, rates_, 0, 0,
                                                      now + 5, 15));
    }
    EXPECT_EQ(-15, entries_[1].getResponseBalance(rates_, 0));
}

TEST_F(RRLEntryTest, updateBalanceSlip) {
    time_t now = 12;

    // Same setup as the NXDOMAIN case of updateBalance test, but slip is set
    // to 0.  The first response is okay in any case.
    EXPECT_EQ(RRL_OK, entries_[1].updateBalance(ts_bases_, rates_, 2, 0, now,
                                                15));
    // The second in the same sec window would be dropped, but since slip > 0
    // and this is the first one that would be dropped, so the result should be
    // SLIP.
    EXPECT_EQ(RRL_SLIP, entries_[1].updateBalance(ts_bases_, rates_, 2, 0, now,
                                                  15));
    // The next one should be drop.
    EXPECT_EQ(RRL_DROP, entries_[1].updateBalance(ts_bases_, rates_, 2, 0, now,
                                                  15));
    // And the next one is slip again, and so on.
    EXPECT_EQ(RRL_SLIP, entries_[1].updateBalance(ts_bases_, rates_, 2, 0, now,
                                                  15));

    // 4 seconds later, the balance will be positive again.
    EXPECT_EQ(1, entries_[1].getResponseBalance(rates_, 4));
    EXPECT_EQ(RRL_OK, entries_[1].updateBalance(ts_bases_, rates_, 2, 0,
                                                now + 4, 15));
    // In this case, the previous slip count is remembered, so the next
    // result will be drop, and the next one is slip.
    EXPECT_EQ(RRL_DROP, entries_[1].updateBalance(ts_bases_, rates_, 2, 0,
                                                  now + 4, 15));
    EXPECT_EQ(RRL_SLIP, entries_[1].updateBalance(ts_bases_, rates_, 2, 0,
                                                  now + 4, 15));

    // Another 4 sec later, the balance will still be 1 because it cannot be
    // larger than the rate, but slip count should be reset to 0, so the
    // first query after OK will be SLIP.
    EXPECT_EQ(1, entries_[1].getResponseBalance(rates_, 4));
    EXPECT_EQ(RRL_OK, entries_[1].updateBalance(ts_bases_, rates_, 2, 0,
                                                now + 8, 15));
    EXPECT_EQ(RRL_SLIP, entries_[1].updateBalance(ts_bases_, rates_, 2, 0,
                                                  now + 8, 15));

    // Likewise, after a window-size sec the slip count will be reset.
    EXPECT_EQ(RRL_OK, entries_[1].updateBalance(ts_bases_, rates_, 2, 0,
                                                now + 24, 15)); // 24 > 8 + 15
    EXPECT_EQ(RRL_SLIP, entries_[1].updateBalance(ts_bases_, rates_, 2, 0,
                                                  now + 24, 15));

    // The next one will result in drop, and slip count will be reset.
    EXPECT_EQ(RRL_DROP, entries_[1].updateBalance(ts_bases_, rates_, 2, 0,
                                                  now + 24, 15));
    // If configured slip count is 1, all penalized queries will result in
    // slip.
    EXPECT_EQ(RRL_SLIP, entries_[1].updateBalance(ts_bases_, rates_, 1, 0,
                                                  now + 24, 15));
    EXPECT_EQ(RRL_SLIP, entries_[1].updateBalance(ts_bases_, rates_, 1, 0,
                                                  now + 24, 15));
}

TEST_F(RRLEntryTest, makeLogMessage) {
    boost::scoped_ptr<NamePool> names(RRLEntry::createNamePool());

    // A normal case
    EXPECT_EQ("would limit response to 192.0.2.0/24 for example.com IN A",
              entries_[0].makeLogMessage("would ", "limit ", RRL_OK,
                                         Rcode::NOERROR(), *names,
                                         &qname_, true, 24, 56));

    // omitting leading text
    EXPECT_EQ("limit response to 192.0.2.0/24 for example.com IN A",
              entries_[0].makeLogMessage(NULL, "limit ", RRL_OK,
                                         Rcode::NOERROR(), *names,
                                         &qname_, true, 24, 56));
    EXPECT_EQ("consider limiting response to 192.0.2.0/24 for example.com IN A",
              entries_[0].makeLogMessage("consider limiting ", NULL, RRL_OK,
                                         Rcode::NOERROR(), *names,
                                         &qname_, true, 24, 56));

    // Other result codes than OK
    EXPECT_EQ("would drop response to 192.0.2.0/24 for example.com IN A",
              entries_[0].makeLogMessage("would ", NULL, RRL_DROP,
                                         Rcode::NOERROR(), *names,
                                         &qname_, true, 24, 56));
    EXPECT_EQ("would slip response to 192.0.2.0/24 for example.com IN A",
              entries_[0].makeLogMessage("would ", NULL, RRL_SLIP,
                                         Rcode::NOERROR(), *names,
                                         &qname_, true, 24, 56));

    // Other response types than query
    EXPECT_EQ("limit NXDOMAIN response to 192.0.2.0/24 for example.com",
              entries_[1].makeLogMessage(NULL, "limit ", RRL_OK,
                                         Rcode::NOERROR(), *names,
                                         &qname_, true, 24, 56));
    RRLEntry entry;
    entry.reset(RRLKey(*ep_, RRType::A(), &qlabels_, RRClass::IN(),
                       RESPONSE_ERROR, MASK4, MASK6, 4200), 0);
    EXPECT_EQ("limit error response to 192.0.2.0/24",
              entry.makeLogMessage(NULL, "limit ", RRL_OK, Rcode::NOERROR(),
                                   *names, &qname_, true, 24, 56));
    EXPECT_EQ("limit REFUSED error response to 192.0.2.0/24",
              entry.makeLogMessage(NULL, "limit ", RRL_OK, Rcode::REFUSED(),
                                   *names, &qname_, true, 24, 56));

    // qname is not given to makeLogMessage but already remembered in the pool
    EXPECT_EQ("would limit response to 192.0.2.0/24 for example.com IN A",
              entries_[0].makeLogMessage("would ", "limit ", RRL_OK,
                                         Rcode::NOERROR(), *names,
                                         NULL, true, 24, 56));
    // qname is totally unknown
    entry.reset(RRLKey(*ep_, RRType::A(), &qlabels_, RRClass::IN(),
                       RESPONSE_QUERY, MASK4, MASK6, 4200), 0);
    EXPECT_EQ("limit response to 192.0.2.0/24 for (?) IN A",
              entry.makeLogMessage(NULL, "limit ", RRL_OK, Rcode::NOERROR(),
                                   *names, NULL, true, 24, 56));
    // type-independent result
    entry.reset(RRLKey(*ep_, RRType(0), &qlabels_, RRClass::IN(),
                       RESPONSE_QUERY, MASK4, MASK6, 4200), 0);
    EXPECT_EQ("limit response to 192.0.2.0/24 for example.com IN",
              entry.makeLogMessage(NULL, "limit ", RRL_OK, Rcode::NOERROR(),
                                   *names, &qname_, true, 24, 56));
}

TEST_F(RRLEntryTest, dumpLimitLog) {
    // this test doesn't work as expected if log level is set to INFO or lower
    // (it's the case by default, so this condition shouldn't be too
    // restrictive)
    if (!logger.isInfoEnabled()) {
        return;
    }

    boost::scoped_ptr<NamePool> names(RRLEntry::createNamePool());
    std::string log_msg;

    // Initialize: set the internal timestamp = 0
    entries_[0].setAge(ts_bases_, 10);
    entries_[1].setAge(ts_bases_, 10);

    // First limit log.
    EXPECT_TRUE(entries_[0].dumpLimitLog(&qname_, *names, Rcode::NOERROR(),
                                         false, 24, 56, log_msg));
    EXPECT_EQ("limit response to 192.0.2.0/24 for example.com IN A", log_msg);

    // Once logged it'll be suppressed
    log_msg.clear();
    EXPECT_FALSE(entries_[0].dumpLimitLog(&qname_, *names, Rcode::NOERROR(),
                                          false, 24, 56, log_msg));
    EXPECT_EQ("", log_msg);

    // log_only case
    EXPECT_TRUE(entries_[1].dumpLimitLog(&qname_, *names, Rcode::NXDOMAIN(),
                                         true, 24, 56, log_msg));
    EXPECT_EQ("would limit NXDOMAIN response to 192.0.2.0/24 for example.com",
              log_msg);
    // it'll be suppressed for 1800 seconds.  it's counted only in
    // updateBalance().  at time 1809, the elapsed time since the first log
    // is 1799 sec.
    log_msg.clear();
    entries_[1].updateBalance(ts_bases_, rates_, 1, 0, 1809, 15);
    EXPECT_FALSE(entries_[1].dumpLimitLog(&qname_, *names, Rcode::NOERROR(),
                                          true, 24, 56, log_msg));
    EXPECT_EQ("", log_msg);
    // At time 1810 logging is continued.  But since this is not the first
    // log, dumpLimitLog returns false.
    entries_[1].updateBalance(ts_bases_, rates_, 1, 0, 1810, 15);
    EXPECT_FALSE(entries_[1].dumpLimitLog(&qname_, *names, Rcode::NOERROR(),
                                          true, 24, 56, log_msg));
    EXPECT_EQ("would continue limiting NXDOMAIN response to 192.0.2.0/24 for "
              "example.com", log_msg);
    // it's suppressed again.
    log_msg.clear();
    EXPECT_FALSE(entries_[1].dumpLimitLog(&qname_, *names, Rcode::NOERROR(),
                                          true, 24, 56, log_msg));
    EXPECT_EQ("", log_msg);
    // Overflow situation shouldn't confuse the suppression detection logic.
    entries_[1].updateBalance(ts_bases_, rates_, 1, 0, 1810 + (1 << 11), 15);
    EXPECT_FALSE(entries_[1].dumpLimitLog(&qname_, *names, Rcode::NOERROR(),
                                          true, 24, 56, log_msg));
    EXPECT_EQ("would continue limiting NXDOMAIN response to 192.0.2.0/24 for "
              "example.com", log_msg);
}
}
