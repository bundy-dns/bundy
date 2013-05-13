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

#ifndef AUTH_RRL_ENTRY_H
#define AUTH_RRL_ENTRY_H 1

#include <auth/rrl/rrl_key.h>
#include <auth/rrl/rrl_result.h>
#include <auth/rrl/rrl_rate.h>
#include <auth/rrl/rrl_timestamps.h>

#include <dns/dns_fwd.h>

#include <boost/intrusive/list.hpp>
#include <boost/static_assert.hpp>

#include <cassert>
#include <ctime>
#include <stdint.h>

namespace isc {
namespace auth {
namespace rrl {
namespace detail {

class NamePool;

class RRLEntry {
private:
    static const size_t TIMESTAMP_BITS = 12;
    static const size_t TIMESTAMP_GEN_BITS = 2;
    static const size_t TIMESTAMP_BASES_COUNT = 1 << TIMESTAMP_GEN_BITS;

    // Width of the bit field for indexing pooled names for logging
    static const size_t LOG_QNAMES_BITS = 8;
    // max number of pooled names.  note that we subtract it by 1 so all
    // indices including "max" fit in the LOG_QNAMES_BITS bits.
    static const size_t LOG_QNAMES = (1 << LOG_QNAMES_BITS) - 1;

    // Width of the bit field for elapsed time since the entry is logged
    static const size_t LOG_SECS_BITS = 11;
    // log suppression period in seconds. it must fit in the bit field
    static const size_t MAX_LOG_SECS = 1800;
    BOOST_STATIC_ASSERT(MAX_LOG_SECS < (1 << LOG_SECS_BITS));
public:
    static const int TIMESTAMP_FOREVER = 1 << TIMESTAMP_BITS;
    BOOST_STATIC_ASSERT(TIMESTAMP_FOREVER > (1 << LOG_SECS_BITS));

    static const int STOP_LOG_SECS = 60;
    BOOST_STATIC_ASSERT(STOP_LOG_SECS < (1 << LOG_SECS_BITS));
public:
    boost::intrusive::list_member_hook<> hash_hook_;
    boost::intrusive::list_member_hook<> lru_hook_;

    void reset(const RRLKey& key, unsigned int hash_gen) {
        key_ = key;
        responses_ = 0;
        log_qname_ = LOG_QNAMES;
        timestamp_gen_ = 0;
        timestamp_valid_ = TIMESTAMP_INVALID;
        hash_gen_ = (hash_gen > 0) ? 1 : 0;
        logged_ = 0;
        log_secs_ = 0;
        timestamp_ = 0;
        slip_cnt_ = 0;
    }

    void setHashGen(unsigned int gen) {
        hash_gen_ = (gen > 0) ? 1 : 0;
    }

    unsigned int getHashGen() const {
        return (hash_gen_);
    }

    /// \brief Bases of timestamps for the RRL entries.
    ///
    /// Its template parameters highly depend on the internal constraints of
    /// the RRLEntry class, so it's defined here.
    typedef RRLTimeStampBases<TIMESTAMP_BASES_COUNT, TIMESTAMP_FOREVER>
    TimestampBases;

    int getAge(const TimestampBases& bases, std::time_t now) const {
        if (!timestamp_valid_) {
            return (TIMESTAMP_FOREVER);
        }
        return (TimestampBases::deltaTime(timestamp_ +
                                          bases.getBaseByGen(timestamp_gen_),
                                          now));
    }

    void setAge(TimestampBases& bases, std::time_t now) {
        const std::pair<std::time_t, size_t> base_result =
            bases.getCurrentBase(now);
        const int diff = now - base_result.first;
        timestamp_gen_ = base_result.second;
        timestamp_ = diff >= 0 ? diff : 0;
        timestamp_valid_ = TIMESTAMP_VALID;
    }

    Result updateBalance(TimestampBases& ts_bases, RRLRate& rates,
                         int slip, double qps, std::time_t now, int window);

    /// \brief Return the current balance for the entry, focusing on whether
    /// it's negative.
    ///
    /// If the internal current balance is positive, it simply returns that
    /// value.  Otherwise, it calculates the/ expected next balance with the
    /// given age and returns it.  So the return value of this method should
    /// be used if the corresponding entry is expected to be (still) penalized
    /// or not, rather than to get the absolute balance value.
    int getResponseBalance(const RRLRate& rates, int age) const;

    const RRLKey& getKey() const { return (key_); }

    /// \brief Return true iff the entry is "free".
    ///
    /// An entry is considered to be free if it's allocated but is never
    /// actively used.
    bool isFree() const { return (!hash_hook_.is_linked()); }

    size_t getTimestampGen() const { return (timestamp_gen_); }

    void invalidateTimestamp() { timestamp_valid_ = TIMESTAMP_INVALID; }

    /// \brief Return a string representing the state of the entry with given
    /// parameters.
    std::string makeLogMessage(const char* str1, const char* str2,
                               Result result, const dns::Rcode& rcode,
                               NamePool& names, const dns::Name* qname,
                               bool save_qname, int ipv4_prefixlen,
                               int ipv6_prefixlen);

    /// \brief Dump a log message of an event for a response being
    /// rate-limited.
    ///
    /// Log messages are also rate limited; it's logged first time the
    /// corresponding response is limited, and then suppressed until the limit
    /// is stopped or for 30 minutes.  If logged, log_msg will be set to the
    /// log message (any previous content will be removed) so the caller can
    /// also use the message for its own logging or other purposes.
    ///
    /// \return true if a log is dumped for the entry first time; false
    /// otherwise.
    bool dumpLimitLog(const dns::Name* qname, NamePool& names,
                      const dns::Rcode& rcode, bool log_only,
                      int ipv4_prefixlen, int ipv6_prefixlen,
                      std::string& log_msg);

    void endLimitLog(NamePool& names, bool log_only, int ipv4_prefixlen,
                     int ipv6_prefixlen, std::string* log_msg = NULL);

    /// \brief Create a new name pool object that can be passed to
    /// makeLogMessage().
    ///
    /// Its capacity depends on internal restriction of RRLEntry, so it's
    /// defined as a static member function of the class.  The ownership is
    /// passed to the caller; the caller is responsible to delete it.
    static NamePool* createNamePool();

private:
    static const unsigned int TIMESTAMP_VALID = 1;
    static const unsigned int TIMESTAMP_INVALID = 0;

    RRLKey key_;
    int32_t responses_ : 24;
    uint32_t log_qname_ : LOG_QNAMES_BITS;

    uint32_t timestamp_gen_ : TIMESTAMP_GEN_BITS;
    uint32_t timestamp_valid_ : 1;
    uint32_t hash_gen_ : 1;
    uint32_t logged_ : 1; // 1 iff it's once logged (need to call log_end)
    uint32_t log_secs_ : LOG_SECS_BITS; // seconds since last time it's logged
    uint32_t timestamp_ : TIMESTAMP_BITS;
    uint32_t slip_cnt_ : 4;
};

} // namespace detail
} // namespace rrl
} // namespace auth
} // namespace isc

#endif // AUTH_RRL_ENTRY_H

// Local Variables:
// mode: c++
// End:
