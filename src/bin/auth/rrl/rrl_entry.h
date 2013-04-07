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

#include <boost/intrusive/list.hpp>

#include <cassert>
#include <ctime>
#include <stdint.h>

namespace isc {
namespace auth {
namespace rrl {
namespace detail {

class RRLEntry {
private:
    static const size_t TIMESTAMP_BITS = 12;
    static const size_t TIMESTAMP_GEN_BITS = 2;
    static const size_t TIMESTAMP_BASES_COUNT = 1 << TIMESTAMP_GEN_BITS;
public:
    static const int TIMESTAMP_FOREVER = 1 << TIMESTAMP_BITS;
public:
    boost::intrusive::list_member_hook<> hash_hook_;
    boost::intrusive::list_member_hook<> lru_hook_;

    void reset(const RRLKey& key, unsigned int hash_gen) {
        new(&key_placeholder_) RRLKey(key);
        responses_ = 0;
        log_qname_ = 0;
        timestamp_gen_ = 0;
        timestamp_valid_ = TIMESTAMP_INVALID;
        hash_gen_ = (hash_gen > 0) ? 1 : 0;
        logged_ = 0;
        log_secs_ = 0;
        timestamp_ = 0;
        slip_cnt_ = 0;
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
                         double qps, std::time_t now, int window);

    /// \brief Return the current balance for the entry, focusing on whether
    /// it's negative.
    ///
    /// If the internal current balance is not negative, it simply returns 0
    /// (following the BIND 9 implementation).  Otherwise, it calculates the
    /// expected next balance with the given age and returns it.  So the
    /// return value of this method should be used if the balance is expected
    /// to be (still) negative or not, rather than to get the absolute
    /// balance value.
    int getResponseBalance(const RRLRate& rates, int age) const;

private:
    static const unsigned int TIMESTAMP_VALID = 1;
    static const unsigned int TIMESTAMP_INVALID = 0;

    const RRLKey& getKey() const {
        const void* p = key_placeholder_;
        return (*static_cast<const RRLKey*>(p));
    }

    uint8_t key_placeholder_[sizeof(RRLKey)];
    int32_t responses_ : 24; // response_balance, debit_rrl_entry, debit_log
    uint32_t log_qname_ : 8;

    uint32_t timestamp_gen_ : TIMESTAMP_GEN_BITS; // set in set_age  (fully private?)
    uint32_t timestamp_valid_ : 1; // set in set_age (fully private?)
    uint32_t hash_gen_ : 1;        // set in get_entry (fully private)
    uint32_t logged_ : 1;          // set in log_end, dns_rrl()
    uint32_t log_secs_ : 11;       // set in debit_rrl_entry, dns_rrl()
    uint32_t timestamp_ : TIMESTAMP_BITS;   // set in set_age
    uint32_t slip_cnt_ : 4;     // only used in debit_rrl_entry
};

} // namespace detail
} // namespace rrl
} // namespace auth
} // namespace isc

#endif // AUTH_RRL_ENTRY_H

// Local Variables:
// mode: c++
// End:
