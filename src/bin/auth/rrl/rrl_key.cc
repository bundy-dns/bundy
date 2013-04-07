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

#include <sys/socket.h>

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
    // This is not type safe, but we want to use memcmp for operator==, so
    // all bits should be 0-cleared first.
    memset(this, 0, sizeof(*this));

    rtype_ = resp_type;

    if (resp_type == RESPONSE_QUERY || resp_type == RESPONSE_DELEGATION) {
        qclass_ = qclass.getCode() & 0x7f;
        qtype_ = qtype.getCode();
    }

    if (qname) {
        qname_hash_ = qname->getFullHash(false, hash_seed);
    }

    const struct sockaddr& client_sa = client_addr.getSockAddr();
    switch (client_sa.sa_family) {
    case AF_INET:
        ip_[0] =
            (convertSockAddr<sockaddr_in>(&client_sa)->sin_addr.s_addr &
             ipv4_mask);
        break;
    case AF_INET6:
        ipv6_ = 1;
        std::memcpy(ip_,
                    &convertSockAddr<sockaddr_in6>(&client_sa)->sin6_addr,
                    sizeof(ip_));
        for (int i = 0; i < 2; ++i) {
            ip_[i] &= ipv6_masks[i];
        }
    }
}


} // namespace detail
} // namespace rrl
} // namespace auth
} // namespace isc
