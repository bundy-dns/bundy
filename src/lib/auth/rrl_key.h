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

#include <auth/rrl_response_type.h>

#include <dns/labelsequence.h>
#include <dns/rrtype.h>
#include <dns/rrclass.h>

#include <boost/functional/hash.hpp>
#include <boost/static_assert.hpp>

#include <cstring>
#include <string>

#include <stdint.h>

namespace bundy {
namespace asiolink {
class IOEndpoint;
}

namespace auth {
namespace detail {

/// \brief RRL entry key.
///
/// This class encapsulates keys for RRL entries, containing information
/// such as query name and type.  It's designed to be efficient both in terms
/// of memory footprint and access overhead, while providing as much safety
/// as possible.
///
/// Internally, it's implemented a simple structure of trivial type members
/// with straightforward accessors.  But the layout is hidden in a private
/// member, and all public methods are const member functions.  In fact, once
/// constructed, it's guaranteed that the object will be immutable.
class RRLKey {
public:
    /// \brief The default constructor.
    ///
    /// This is defined for requirements of STL containers.  We don't
    /// directly use keys constructed by this.
    RRLKey() {}

    /// \brief Constructor from key parameters
    ///
    /// This is a straightforward constructor that takes values that consist
    /// of the key, and stores (a copy of) them almost as passed.
    ///
    /// The query name, if given (non-NULL), will be stored in the form of a
    /// hash value to save the space.  Once the RRLKey is constructed, the
    /// complete information of the original query name will be lost.  The
    /// hash value is calculated using the given seed value (hash_seed).
    /// In practice, the use of this class must use the same seed throughout
    /// its lifetime; however, it's highly advisable to use a reasonably
    /// unpredictable random value for every run.
    ///
    /// This constructor is basically exception free.  The only case it can
    /// throw is \c client_addr represents neither IPv6 nor IPv4 address, but
    /// this shouldn't happen due to the restriction of the underlying API.
    /// Should this ever happen, a bundy::Unexpected exception will be thrown.
    ///
    /// \throw Almost none (see description)
    ///
    /// \param client_addr A network end point.  Must correspond to IPv4 or
    /// IPv6 address.
    /// \param qtype The query type.
    /// \param qname The query name in the form of \c LabelSequence.  If NULL,
    /// it means the key does not correspond to a particular name.
    /// \param qclass The query class.
    /// \param resp_type The response type in terms of RRL.
    /// \param ipv4_mask A bit mask to be applied to the address stored in
    /// client_addr, in case it's an IPv4 address.
    /// \param ipv6_masks A bit mask to be applied to the address stored in
    /// client_addr, in case it's an IPv6 address.  In fact, only up to the
    /// higher 64 bits will be used.
    /// \param hash_seed A seed value to calculate a hash for qname.
    RRLKey(const asiolink::IOEndpoint& client_addr, const dns::RRType& qtype,
           const dns::LabelSequence* qname, const dns::RRClass& qclass,
           ResponseType resp_type, uint32_t ipv4_mask,
           const uint32_t ipv6_masks[4], uint32_t hash_seed);

    /// \brief Assignment operator.
    ///
    /// \throw None.
    RRLKey& operator=(const RRLKey& source) {
        std::memcpy(&key_, &source.key_, sizeof(key_));
        return (*this);
    }

    /// \brief Compare this and other RRLKey objects.
    ///
    /// \throw None.
    ///
    /// \return true if \c this is equal to \c other; false otherwise.
    bool operator==(const RRLKey& other) const {
        return (std::memcmp(&key_, &other.key_, sizeof(key_)) == 0);
    }

    /// \brief Return a hash value of the RRLKey object.
    ///
    /// \throw None.
    ///
    /// \return a hash value for the stored key.
    size_t getHash() const {
        const uint8_t* cp = static_cast<const uint8_t*>(
            static_cast<const void*>(&key_));
        return (boost::hash_range(cp, cp + sizeof(key_)));
    }

    /// \brief Return the response type of the RRLKey object.
    ///
    /// It returns the response type specified on construction.
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
    /// large for the address family, bundy::InvalidParameter will be thrown.
    std::string getIPText(size_t ipv4_prefixlen, size_t ipv6_prefixlen) const;

    /// \brief Return a textual description of the query class.
    ///
    /// Due to internal implementation details not all information of the
    /// query class is stored in the key; only the lower 6 bits are held.
    /// If the actual query class value doesn't fit this size, this method
    /// returns a special string of "?".
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

    // Mask to limit the range of query class.
    static const uint8_t MAX_ENCODED_CLASS_CODE = 0x3f;
};

// Make sure the key objects are as small as we expect; the specific value
// is not important for the behavior, but it proves our assumption on memory
// footprint.
BOOST_STATIC_ASSERT(sizeof(RRLKey) == 16);

} // namespace detail
} // namespace auth
} // namespace bundy

#endif // AUTH_RRL_KEY_H

// Local Variables:
// mode: c++
// End:
