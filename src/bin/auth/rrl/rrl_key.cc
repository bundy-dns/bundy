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

#include <dns/labelsequence.h>
#include <dns/rrtype.h>
#include <dns/rrclass.h>

#include <util/io/sockaddr_util.h>

#include <asiolink/io_endpoint.h>

#include <cstring>
#include <sstream>

#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>

using isc::asiolink::IOEndpoint;
using isc::util::io::internal::convertSockAddr;

namespace isc {
namespace auth {
namespace rrl {
namespace detail {

RRLKey::RRLKey(const IOEndpoint& client_addr, const dns::RRType& qtype,
               const dns::LabelSequence* qname, const dns::RRClass& qclass,
               ResponseType resp_type, uint32_t ipv4_mask,
               const uint32_t ipv6_masks[4], uint32_t hash_seed)
{
    memset(&key_, 0, sizeof(key_));

    key_.rtype = resp_type;

    if (resp_type == RESPONSE_QUERY) {
        key_.qclass = qclass.getCode() & 0x7f;
        key_.qtype = qtype.getCode();
    }

    if (qname) {
        key_.qname_hash = qname->getFullHash(false, hash_seed);
    }

    const struct sockaddr& client_sa = client_addr.getSockAddr();
    switch (client_sa.sa_family) {
    case AF_INET:
        key_.ip[0] =
            (convertSockAddr<sockaddr_in>(&client_sa)->sin_addr.s_addr &
             ipv4_mask);
        break;
    case AF_INET6:
        key_.ipv6 = 1;
        std::memcpy(key_.ip,
                    &convertSockAddr<sockaddr_in6>(&client_sa)->sin6_addr,
                    sizeof(key_.ip));
        for (int i = 0; i < 2; ++i) {
            key_.ip[i] &= ipv6_masks[i];
        }
    }
}

std::string
RRLKey::getIPText(size_t ipv4_prefixlen, size_t ipv6_prefixlen) const {
    if (ipv4_prefixlen > 32) {
        isc_throw(InvalidParameter, "invalid IPv4 prefix len for getIPText: "
                  << ipv4_prefixlen);
    }
    if (ipv6_prefixlen > 128) {
        isc_throw(InvalidParameter, "invalid IPv6 prefix len for getIPText: "
                  << ipv6_prefixlen);
    }

    struct sockaddr_storage ss;
    std::memset(&ss, 0, sizeof(ss));
    struct sockaddr* sa = convertSockAddr<sockaddr_storage>(&ss);
    if (key_.ipv6) {
        struct sockaddr_in6* sa6;
        sa6 = convertSockAddr<sockaddr_in6>(sa);
        sa6->sin6_family = AF_INET6;
        sa6->sin6_len = sizeof(*sa6);
        memcpy(&sa6->sin6_addr, key_.ip, sizeof(key_.ip));
    } else {
        struct sockaddr_in* sa4;
        sa4 = convertSockAddr<sockaddr_in>(sa);
        sa4->sin_family = AF_INET;
        sa4->sin_len = sizeof(*sa4);
        sa4->sin_addr.s_addr = key_.ip[0];
    }
    const socklen_t sa_len = key_.ipv6 ?
        sizeof(sockaddr_in6) : sizeof(sockaddr_in);
    char hbuf[NI_MAXHOST];
    getnameinfo(sa, sa_len, hbuf, NI_MAXHOST, NULL, 0,
                NI_NUMERICHOST | NI_NUMERICSERV);

    std::stringstream sstr;
    sstr << hbuf;
    if (key_.ipv6) {
        if (ipv6_prefixlen < 128) {
            sstr << '/' << ipv6_prefixlen;
        }
    } else if (ipv4_prefixlen < 32) {
        sstr << '/' << ipv4_prefixlen;
    }

    return (sstr.str());
}

} // namespace detail
} // namespace rrl
} // namespace auth
} // namespace isc
