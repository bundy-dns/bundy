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

#ifndef AUTH_RRL_KEY_H
#define AUTH_RRL_KEY_H 1

#include <auth/rrl/rrl_response_type.h>

#include <dns/labelsequence.h>
#include <dns/rrtype.h>
#include <dns/rrclass.h>

#include <boost/functional/hash.hpp>

#include <cstring>

#include <stdint.h>

namespace isc {
namespace asiolink {
class IOEndpoint;
}

namespace auth {
namespace rrl {
namespace detail {

class RRLKey {
public:
    // For requirements of STL containers.  We don't directly use keys
    // constructed by this.
    RRLKey() {}

    RRLKey(const asiolink::IOEndpoint& client_addr, const dns::RRType& qtype,
           const dns::LabelSequence* qname, const dns::RRClass& qclass,
           ResponseType resp_type, uint32_t ipv4_mask,
           const uint32_t ipv6_masks[4], uint32_t hash_seed);

    RRLKey& operator=(const RRLKey& source) {
        // See the constructor's note about ugly memcpy
        std::memcpy(this, &source, sizeof(*this));
        return (*this);
    }

    bool operator==(const RRLKey& other) const {
        return (std::memcmp(this, &other, sizeof(*this)) == 0);
    }

    size_t getHash() const {
        const uint8_t* cp = static_cast<const uint8_t*>(
            static_cast<const void*>(this));
        return (boost::hash_range(cp, cp + sizeof(*this)));
    }

    ResponseType getResponseType() const { return (rtype_); }

private:
    uint32_t ip_[2];            // client IP prefix, up to 64 bits
    uint32_t qname_hash_;
    uint16_t qtype_;            // qtype code value
    uint8_t ipv6_ : 1;          // used for logging
    uint8_t qclass_ : 7;        // least 7 bits of qclass code value
    ResponseType rtype_;
};

} // namespace detail
} // namespace rrl
} // namespace auth
} // namespace isc

#endif // AUTH_RRL_KEY_H

// Local Variables:
// mode: c++
// End:
