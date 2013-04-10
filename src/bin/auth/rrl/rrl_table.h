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

#ifndef AUTH_RRL_TABLE_H
#define AUTH_RRL_TABLE_H 1

#include <auth/rrl/rrl_entry.h>

#include <boost/shared_ptr.hpp>
#include <boost/scoped_ptr.hpp>
#include <boost/noncopyable.hpp>
#include <boost/intrusive/list.hpp>

#include <ctime>
#include <cassert>
#include <vector>

namespace isc {
namespace auth {
namespace rrl {
namespace detail {
class RRLKey;
class RRLRate;

/// \brief Table maintaining RRL entries.
class RRLTable : boost::noncopyable {
    typedef boost::intrusive::list<
        RRLEntry,
        boost::intrusive::member_hook<
            RRLEntry, boost::intrusive::list_member_hook<>,
            &RRLEntry::hash_hook_> > HashList;

    typedef boost::intrusive::list<
        RRLEntry,
        boost::intrusive::member_hook<
            RRLEntry, boost::intrusive::list_member_hook<>,
            &RRLEntry::lru_hook_> > LRUList;

    struct Hash : boost::noncopyable {
        Hash(unsigned int gen, size_t bin_count) :
            check_time_(0), gen_(gen)
        {
            bins_.assign(bin_count, boost::shared_ptr<HashList>(new HashList));
        }
        std::time_t check_time_;
        const unsigned int gen_;
        // We need to store the lists as pointers as they are non copyable.
        std::vector<boost::shared_ptr<HashList> > bins_;
    };

public:
    RRLTable(size_t max_entries) :
        max_entries_(max_entries), num_entries_(0), hash_gen_(0), searches_(0),
        probes_(0)
    {}

    /// \brief Returns the current number of entries.
    ///
    /// Mostly for testing only (this performs expensive integrity check).
    size_t getEntryCount() const {
        assert(num_entries_ == lru_.size());
        return (num_entries_);
    }

    /// \brief Return the total hash bins inside the table.
    ///
    /// This is only for tests.
    size_t getBinSize() const {
        return ((hash_ ? hash_->bins_.size() : 0) +
                (old_hash_ ? old_hash_->bins_.size() : 0));
    }

    /// \brief Return the current hash table generation ID.
    ///
    /// This is only for tests.
    int getGeneration() const {
        if (!hash_) {
            return (-1);
        }
        assert(hash_->gen_ == hash_gen_);
        return (hash_->gen_);
    }

    /// \brief Expand the table so it can perform search more efficiently.
    void expand(std::time_t now);

    /// \brief Allocate more RRL entries stored in the table.
    void expandEntries(size_t count_to_add);

    /// \brief Search for an entry for a response and optionally create it.
    RRLEntry* getEntry(const RRLKey& key,
                       const RRLEntry::TimestampBases& ts_bases,
                       const RRLRate& rates, std::time_t now, int window);

    void timestampBaseUpdated(size_t gen);

private:
    // Post-search helper of getEntry().
    void refEntry(RRLEntry& entry, int probes, std::time_t now);

    const size_t max_entries_;
    static const size_t MAX_EXPAND_COUNT = 1000; // following BIND 9
    size_t num_entries_;
    // Placeholder of table entries.  This must be placed before the hash
    // and LRU, as they are expected to be (auto)unlinked on destruction.
    std::vector<boost::shared_ptr<std::vector<RRLEntry> > > entry_blocks_;
    boost::scoped_ptr<Hash> hash_;
    boost::scoped_ptr<Hash> old_hash_;
    LRUList lru_;
    unsigned int hash_gen_;
    size_t searches_;
    size_t probes_;
};

} // namespace detail
} // namespace rrl
} // namespace auth
} // namespace isc

#endif // AUTH_RRL_TABLE_H

// Local Variables:
// mode: c++
// End:
