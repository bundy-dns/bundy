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
#include <boost/static_assert.hpp>

#include <cstring>
#include <string>

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
    /// \brief The default constructor.
    ///
    /// This is defined for requirements of STL containers.  We don't
    /// directly use keys constructed by this.
    RRLKey() {}

    RRLKey(const asiolink::IOEndpoint& client_addr, const dns::RRType& qtype,
           const dns::LabelSequence* qname, const dns::RRClass& qclass,
           ResponseType resp_type, uint32_t ipv4_mask,
           const uint32_t ipv6_masks[4], uint32_t hash_seed);

    RRLKey& operator=(const RRLKey& source) {
        std::memcpy(&key_, &source.key_, sizeof(key_));
        return (*this);
    }

    bool operator==(const RRLKey& other) const {
        return (std::memcmp(&key_, &other.key_, sizeof(key_)) == 0);
    }

    size_t getHash() const {
        const uint8_t* cp = static_cast<const uint8_t*>(
            static_cast<const void*>(&key_));
        return (boost::hash_range(cp, cp + sizeof(key_)));
    }

    ResponseType getResponseType() const {
        return (static_cast<ResponseType>(key_.rtype));
    }

    /// \brief Return a textual representation of IP prefix of the key.
    ///
    /// The returned string is in the form of <ipv4-or-ipv6 address>[/plen].
    /// Since the caller may not know the address family of the prefix,
    /// this method needs to take prefixlen parameters for both cases.
    /// If it's an IPv6 prefix, ipv6_prefixlen will be used;
    /// otherwise ipv4_prefixlen will be used.  If the prefixlen is too
    /// large for the address family, isc::InvalidParameter will be thrown.
    std::string getIPText(size_t ipv4_prefixlen, size_t ipv6_prefixlen) const;

    /// \brief Return a textual description of the query type.
    ///
    /// Due to internal implementation details not all information of the
    /// query class is stored in the key; only the lower 7 bits are held.
    /// So this method returns a descriptive string for the stored 7 bits
    /// with clarification.
    ///
    /// If the ResponseType is not RESPONSE_QUERY on construction, the stored
    /// 7-bit value is always 0.  This method, if called, returns like other
    /// cases, just treating the value of 0 is the class code.
    std::string getClassText() const;

    /// \brief Return the query type stored in the key.
    ///
    /// If the key is constructed with the response type of RESPONSE_QUERY,
    /// it returns an \c RRType object identical to the given qtype on
    /// construction; otherwise it always returns an RRType object whose code
    /// is 0.
    dns::RRType getType() const {
        return (dns::RRType(key_.qtype));
    }

private:
    // Actual key elements.  We use a separate struct so this part should
    // be plain old data and can be safely used with low level <cstring>
    // APIs (std::memXXX).
    struct {
        uint32_t ip[2];            // client IP prefix, up to 64 bits
        uint32_t qname_hash;       // a hash value of qname
        uint16_t qtype;            // qtype code value
        uint8_t ipv6 : 1; // 1 iff ip is an IPv6 address;used for logging
        uint8_t big_class : 1; // 1 iff qclass code >= (1 << 6)
        uint8_t qclass : 6;        // least 6 bits of qclass code value
        uint8_t rtype;             // ResponseType
    } key_;

    static const uint8_t MAX_ENCODED_CLASS_CODE = 0x3f;
};

// Make sure the key objects are as small as we expect; the specific value
// is not important for the behavior, but it proves our assumption on memory
// footprint.
BOOST_STATIC_ASSERT(sizeof(RRLKey) == 16);

} // namespace detail
} // namespace rrl
} // namespace auth
} // namespace isc

#endif // AUTH_RRL_KEY_H

// Local Variables:
// mode: c++
// End:
