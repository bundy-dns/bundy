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
        key_ = key;
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

private:
    static const unsigned int TIMESTAMP_VALID = 1;
    static const unsigned int TIMESTAMP_INVALID = 0;

    RRLKey key_;
    int32_t responses_ : 24;
    uint32_t log_qname_ : 8;

    uint32_t timestamp_gen_ : TIMESTAMP_GEN_BITS;
    uint32_t timestamp_valid_ : 1;
    uint32_t hash_gen_ : 1;
    uint32_t logged_ : 1;
    uint32_t log_secs_ : 11;
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
