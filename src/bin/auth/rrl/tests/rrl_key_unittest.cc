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

#include <auth/rrl/rrl_key.h>
#include <auth/rrl/rrl_response_type.h>

#include <dns/name.h>
#include <dns/rrtype.h>
#include <dns/rrclass.h>

#include <asiolink/io_endpoint.h>
#include <asiolink/io_address.h>

#include <gtest/gtest.h>

#include <boost/scoped_ptr.hpp>

#include <netinet/in.h>
#include <arpa/inet.h>

using namespace isc::auth::rrl::detail;
using namespace isc::dns;
using isc::asiolink::IOEndpoint;
using isc::asiolink::IOAddress;

namespace {

uint32_t
htonlWrapper(uint32_t val) {
    return (htonl(val));
}

const uint32_t MASK4 = htonlWrapper(0xffffff00);
const uint32_t MASK6[4] = { 0xffffffff, htonlWrapper(0xfffffff0), 0, 0 };

class RRLKeyTest : public ::testing::Test {
protected:
    RRLKeyTest() :
        ep4_(IOEndpoint::create(IPPROTO_UDP, IOAddress("192.0.2.1"), 53210)),
        ep6_(IOEndpoint::create(IPPROTO_UDP, IOAddress("2001:db8::1"), 53210)),
        qname_("example.com"), qlabels_(qname_)
    {}

    boost::scoped_ptr<const IOEndpoint> ep4_;
    boost::scoped_ptr<const IOEndpoint> ep6_;
    const Name qname_;
    const LabelSequence qlabels_;
};

TEST_F(RRLKeyTest, constructAndCompare) {
    // Check various patterns of construction and compare
    const RRLKey key1(*ep4_, RRType::A(), &qlabels_, RRClass::IN(),
                      RESPONSE_QUERY, MASK4, MASK6, 0);
    // Only differing in "host ID" of the address.  the key should be
    // identical.
    ep4_.reset(IOEndpoint::create(IPPROTO_UDP, IOAddress("192.0.2.2"), 53));
    EXPECT_TRUE(key1 == RRLKey(*ep4_, RRType::A(), &qlabels_, RRClass::IN(),
                               RESPONSE_QUERY, MASK4, MASK6, 0));

    // If the network is different, it should be a different key.
    ep4_.reset(IOEndpoint::create(IPPROTO_UDP, IOAddress("192.0.1.1"), 53));
    EXPECT_FALSE(key1 == RRLKey(*ep4_, RRType::A(), &qlabels_, RRClass::IN(),
                                RESPONSE_QUERY, MASK4, MASK6, 0));

    // same for IPv6
    const RRLKey key2(*ep6_, RRType::A(), &qlabels_, RRClass::IN(),
                      RESPONSE_QUERY, MASK4, MASK6, 0);
    ep6_.reset(IOEndpoint::create(IPPROTO_UDP, IOAddress("2001:db8::2"), 0));
    EXPECT_TRUE(key2 == RRLKey(*ep6_, RRType::A(), &qlabels_, RRClass::IN(),
                               RESPONSE_QUERY, MASK4, MASK6, 0));

    ep6_.reset(IOEndpoint::create(IPPROTO_UDP, IOAddress("2001:db8:0:100::2"),
                                  53));
    EXPECT_FALSE(key2 == RRLKey(*ep6_, RRType::A(), &qlabels_, RRClass::IN(),
                                RESPONSE_QUERY, MASK4, MASK6, 0));

    // If type is different keys, are different
    ep4_.reset(IOEndpoint::create(IPPROTO_UDP, IOAddress("192.0.2.1"), 53));
    EXPECT_FALSE(key1 == RRLKey(*ep4_, RRType::NS(), &qlabels_, RRClass::IN(),
                                RESPONSE_QUERY, MASK4, MASK6, 0));
    // same for qname
    const LabelSequence labels(Name::ROOT_NAME());
    EXPECT_FALSE(key1 == RRLKey(*ep4_, RRType::NS(), &labels, RRClass::IN(),
                                RESPONSE_QUERY, MASK4, MASK6, 0));
    // case of names should be ignored
    const Name name_upper("EXAMPLE.COM");
    const LabelSequence labels_upper(name_upper);
    EXPECT_TRUE(key1 == RRLKey(*ep4_, RRType::A(), &labels_upper,
                               RRClass::IN(), RESPONSE_QUERY, MASK4, MASK6, 0));

    // same for qclass, but only for the least 7 bits
    EXPECT_FALSE(key1 == RRLKey(*ep4_, RRType::A(), &qlabels_, RRClass::CH(),
                                RESPONSE_QUERY, MASK4, MASK6, 0));
    EXPECT_TRUE(key1 == RRLKey(*ep4_, RRType::A(), &qlabels_,
                               RRClass(129), // 129 mod 2^7 == 1
                               RESPONSE_QUERY, MASK4, MASK6, 0));
    // for responses other than QUERY, qtype and class are ignored
    const RRLKey key3(*ep4_, RRType::A(), &qlabels_, RRClass::IN(),
                      RESPONSE_NXDOMAIN, MASK4, MASK6, 0);
    EXPECT_TRUE(key3 == RRLKey(*ep4_, RRType::MX(), &qlabels_, RRClass::IN(),
                               RESPONSE_NXDOMAIN, MASK4, MASK6, 0));
    EXPECT_TRUE(key3 == RRLKey(*ep4_, RRType::A(), &qlabels_, RRClass::CH(),
                               RESPONSE_NXDOMAIN, MASK4, MASK6, 0));
    const RRLKey key4(*ep4_, RRType::A(), &qlabels_, RRClass::IN(),
                      RESPONSE_ERROR, MASK4, MASK6, 0);
    EXPECT_TRUE(key4 == RRLKey(*ep4_, RRType::MX(), &qlabels_, RRClass::IN(),
                               RESPONSE_ERROR, MASK4, MASK6, 0));
    EXPECT_TRUE(key4 == RRLKey(*ep4_, RRType::A(), &qlabels_, RRClass::CH(),
                               RESPONSE_ERROR, MASK4, MASK6, 0));

    // qname could be omitted
    const RRLKey key5(*ep4_, RRType::A(), NULL, RRClass::IN(),
                      RESPONSE_QUERY, MASK4, MASK6, 0);
    EXPECT_TRUE(key5 == RRLKey(*ep4_, RRType::A(), NULL, RRClass::IN(),
                               RESPONSE_QUERY, MASK4, MASK6, 0));
}

TEST_F(RRLKeyTest, getHash) {
    // Equivalent keys should have the same hash
    const RRLKey key1(*ep4_, RRType::A(), &qlabels_, RRClass::IN(),
                      RESPONSE_QUERY, MASK4, MASK6, 0);
    const RRLKey key2(*ep4_, RRType::A(), &qlabels_, RRClass::IN(),
                      RESPONSE_QUERY, MASK4, MASK6, 0);
    EXPECT_TRUE(key1 == key2);  // check the assumption
    EXPECT_EQ(key1.getHash(), key2.getHash());

    // inequivalent keys do not necessarily have different hash values, but
    // we know in these examples they are different (assuming the algorithm
    // won't change soon).
    const RRLKey key3(*ep6_, RRType::A(), &qlabels_, RRClass::IN(),
                      RESPONSE_QUERY, MASK4, MASK6, 0);
    EXPECT_FALSE(key1 == key3);
    EXPECT_NE(key1.getHash(), key3.getHash());
}

TEST_F(RRLKeyTest, getIPText) {
    // IPv4 prefix or address
    const RRLKey key1(*ep4_, RRType::A(), &qlabels_, RRClass::IN(),
                      RESPONSE_QUERY, MASK4, MASK6, 0);
    EXPECT_EQ("192.0.2.0/24", key1.getIPText(24, 56));
    EXPECT_EQ("192.0.2.0", key1.getIPText(32, 56));

    // IPv6 prefix or address
    const RRLKey key2(*ep6_, RRType::A(), &qlabels_, RRClass::IN(),
                      RESPONSE_QUERY, MASK4, MASK6, 0);
    EXPECT_EQ("2001:db8::/56", key2.getIPText(24, 56));
    EXPECT_EQ("2001:db8::", key2.getIPText(24, 128));

    // invalid prefixlen
    EXPECT_THROW(key1.getIPText(33, 56), isc::InvalidParameter);
    EXPECT_THROW(key1.getIPText(24, 129), isc::InvalidParameter);
}
}
