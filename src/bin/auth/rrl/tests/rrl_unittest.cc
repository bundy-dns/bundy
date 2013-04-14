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

#include <auth/rrl/rrl.h>
#include <auth/rrl/rrl_result.h>

#include <dns/name.h>
#include <dns/labelsequence.h>
#include <dns/rcode.h>
#include <dns/rrtype.h>
#include <dns/rrclass.h>

#include <exceptions/exceptions.h>

#include <asiolink/io_endpoint.h>
#include <asiolink/io_address.h>

#include <gtest/gtest.h>

#include <boost/scoped_ptr.hpp>

#include <cstring>
#include <vector>

using namespace isc::auth::rrl;
using namespace isc::dns;
using isc::asiolink::IOEndpoint;
using isc::asiolink::IOAddress;

namespace {

const uint32_t MASK4 = htonl(0xffffff00);
const uint32_t MASK6[4] = { 0xffffffff, htonl(0xffffff00), 0, 0 };

class ResponseLimiterTest : public ::testing::Test {
protected:
    ResponseLimiterTest() :
        rrl_(100, 50, 1, 4, 5, 15, 2, 24, 56, false, 10),
        ep4_(IOEndpoint::create(IPPROTO_UDP, IOAddress("192.0.2.1"), 53210)),
        ep6_(IOEndpoint::create(IPPROTO_UDP, IOAddress("2001:db8::1"), 53210)),
        qclass_(RRClass::IN()), qtype_(RRType::AAAA()),
        qname_("example.com"), qlabels_(qname_)
    {}

    ResponseLimiter rrl_;
    boost::scoped_ptr<const IOEndpoint> ep4_;
    boost::scoped_ptr<const IOEndpoint> ep6_;
    const RRClass qclass_;
    const RRType qtype_;
    const Name qname_;
    const LabelSequence qlabels_;
};

TEST_F(ResponseLimiterTest, params) {
    EXPECT_EQ(1, rrl_.getResponseRate());
    EXPECT_EQ(4, rrl_.getNXDOMAINRate());
    EXPECT_EQ(5, rrl_.getErrorRate());
    EXPECT_EQ(15, rrl_.getWindow());
    EXPECT_EQ(2, rrl_.getSlip());
    EXPECT_EQ(10, rrl_.getCurrentTimestampBase(15));
    EXPECT_FALSE(rrl_.isLogOnly());
    EXPECT_EQ(MASK4, rrl_.getIPv4Mask());
    EXPECT_EQ(0, std::memcmp(MASK6, rrl_.getIPv6Mask(), sizeof(MASK6)));

    // min entries must be positive
    EXPECT_THROW(ResponseLimiter(100, 0, 3, 4, 5, 15, 2, 24, 56, false, 10),
                 isc::InvalidParameter);
    // must be max >= min
    EXPECT_THROW(ResponseLimiter(10, 100, 3, 4, 5, 15, 2, 24, 56, false, 10),
                 isc::InvalidParameter);
}

TEST_F(ResponseLimiterTest, prefixes) {
    // Unusual and invalid prefixes

    // negative IPv4 prefix
    EXPECT_THROW(ResponseLimiter(100, 50, 3, 4, 5, 15, 2, -1, 56, false, 10),
                 isc::InvalidParameter);
    // too large IPv4 prefix
    EXPECT_THROW(ResponseLimiter(100, 50, 3, 4, 5, 15, 2, 33, 56, false, 10),
                 isc::InvalidParameter);
    // negative IPv6 prefix
    EXPECT_THROW(ResponseLimiter(100, 50, 3, 4, 5, 15, 2, 24, -1, false, 10),
                 isc::InvalidParameter);
    // too large IPv6 prefix
    EXPECT_THROW(ResponseLimiter(100, 50, 3, 4, 5, 15, 2, 24, 129, false, 10),
                 isc::InvalidParameter);

    // all 0
    EXPECT_EQ(0, ResponseLimiter(100, 50, 3, 4, 5, 15, 2, 0, 56, false, 10).
              getIPv4Mask());
    std::vector<uint8_t> mask6(16);
    EXPECT_EQ(0, std::memcmp(ResponseLimiter(100, 50, 3, 4, 5, 15, 2, 24, 0,
                                             false, 10).getIPv6Mask(),
                             &mask6[0], 16));
    // all 1 (longest prefixes)
    EXPECT_EQ(0xffffffff,
              ResponseLimiter(100, 50, 3, 4, 5, 15, 2, 32, 56, false, 10).
              getIPv4Mask());
    mask6.assign(16, 0xff);
    EXPECT_EQ(0, std::memcmp(ResponseLimiter(100, 50, 3, 4, 5, 15, 2, 24, 128,
                                             false, 10).getIPv6Mask(),
                             &mask6[0], 16));

    // mask ending with 1000 0000.  also the prefix len is an odd number.
    EXPECT_EQ(htonl(0xffff8000),
              ResponseLimiter(100, 50, 3, 4, 5, 15, 2, 17, 56, false, 10).
              getIPv4Mask());
    mask6.assign(7, 0xff);
    mask6.push_back(0x80);
    mask6.insert(mask6.end(), 8, 0);
    EXPECT_EQ(0, std::memcmp(ResponseLimiter(100, 50, 3, 4, 5, 15, 2, 24, 57,
                                             false, 10).getIPv6Mask(),
                             &mask6[0], 16));
}

TEST_F(ResponseLimiterTest, check) {
    // It should be sufficient to check basic behavior; details tests are
    // done for component classes.

    // TCP is always okay
    EXPECT_EQ(RRL_OK, rrl_.check(*ep4_, true, qclass_, qtype_, &qlabels_,
                                 Rcode::NOERROR(), 20));
    EXPECT_EQ(RRL_OK, rrl_.check(*ep6_, true, qclass_, qtype_, &qlabels_,
                                 Rcode::NOERROR(), 20));

    // First query is okay.  then the next one will be slipped, and then
    // dropped.
    EXPECT_EQ(RRL_OK, rrl_.check(*ep4_, false, qclass_, qtype_, &qlabels_,
                                 Rcode::NOERROR(), 20));
    EXPECT_EQ(RRL_SLIP, rrl_.check(*ep4_, false, qclass_, qtype_, &qlabels_,
                                   Rcode::NOERROR(), 20));
    EXPECT_EQ(RRL_DROP, rrl_.check(*ep4_, false, qclass_, qtype_, &qlabels_,
                                   Rcode::NOERROR(), 20));
    // NXDOMAIN and errors are considered different types.  errors of different
    // Rcodes are considered to be of the same type.
    EXPECT_EQ(RRL_OK, rrl_.check(*ep4_, false, qclass_, qtype_, &qlabels_,
                                 Rcode::NXDOMAIN(), 20));
    EXPECT_EQ(RRL_OK, rrl_.check(*ep4_, false, qclass_, qtype_, &qlabels_,
                                 Rcode::REFUSED(), 20));
    EXPECT_EQ(RRL_OK, rrl_.check(*ep4_, false, qclass_, qtype_, &qlabels_,
                                 Rcode::SERVFAIL(), 20));

    // it will be okay again at least in window-sec later
    EXPECT_EQ(RRL_OK, rrl_.check(*ep4_, false, qclass_, qtype_, &qlabels_,
                                 Rcode::NOERROR(), 35));
}
}
