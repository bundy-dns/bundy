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

#include <auth/rrl/rrl_table.h>
#include <auth/rrl/rrl_key.h>
#include <auth/rrl/logger.h>

#include <exceptions/exceptions.h>

#include <log/macros.h>

#include <boost/intrusive/list.hpp>
#include <boost/foreach.hpp>

#include <algorithm>
#include <ctime>
#include <vector>
#include <memory>

using std::vector;

namespace isc {
namespace auth {
namespace rrl {
namespace detail {

const size_t RRLTable::MAX_EXPAND_COUNT;

void
RRLTable::expand(std::time_t now) {
    old_hash_.reset();

    const size_t old_bins = hash_ ? hash_->bins_.size() : 0;
    const size_t new_bins = std::max(old_bins / 8 + old_bins, num_entries_);
    if (new_bins == 0) {
        return;
    }

    const unsigned int new_hash_gen = (hash_gen_ ^ 1);
    std::auto_ptr<Hash> new_hash(new Hash(new_hash_gen, new_bins));

    if (old_bins != 0) {
        const double rate = searches_ > 0 ? probes_ / searches_ : searches_;
        LOG_INFO(logger, AUTH_RRL_TABLE_EXPANDED).arg(old_bins).arg(new_bins).
            arg(num_entries_).arg(rate);
    }

    hash_gen_ = new_hash_gen;
    old_hash_.swap(hash_);
    if (old_hash_) {
        old_hash_->check_time_ = now;
    }
    hash_.reset(new_hash.release());
}

void
RRLTable::expandEntries(size_t count_to_add) {
    if (count_to_add == 0) {
        isc_throw(InvalidParameter, "attempt of expand RRL entries with none");
    }

    if (max_entries_ != 0 && num_entries_ + count_to_add >= max_entries_) {
        if (num_entries_ >= max_entries_) {
            return;
        }
        count_to_add = max_entries_ - num_entries_;
    }

    // Log expansions so that the user can tune max-table-size
    // and min-table-size.
    if (hash_) {
        const double rate = searches_ > 0 ? probes_ / searches_ : searches_;
        LOG_INFO(logger, AUTH_RRL_ENTRY_EXPANDED).arg(num_entries_).
            arg(num_entries_ + count_to_add).arg(hash_->bins_.size()).
            arg(rate);
    }

    boost::shared_ptr<vector<RRLEntry> > new_block(
        new vector<RRLEntry>(count_to_add));
    entry_blocks_.push_back(new_block);
    BOOST_FOREACH(RRLEntry& entry, *new_block) {
        lru_.push_back(entry);
    }
    num_entries_ += count_to_add;
}

RRLEntry*
RRLTable::getEntry(const RRLKey& key, const RRLEntry::TimestampBases& ts_bases,
                   const RRLRate& rates, std::time_t now, int window)
{
    assert(hash_);            // violation of this is an internal bug

    // Look for the entry in the current hash table.
    const size_t hval = key.getHash();
    HashList& new_bin = *hash_->bins_[hval % hash_->bins_.size()];
    size_t probes = 1;
    BOOST_FOREACH(RRLEntry& entry, new_bin) {
        if (entry.getKey() == key) {
            refEntry(entry, probes, now);
            return (&entry);
        }
        ++probes;
    }

    // Look in the old hash table.
    if (old_hash_) {
        HashList& old_bin = *old_hash_->bins_[hval % old_hash_->bins_.size()];
        HashList::iterator const it_end = old_bin.end();
        for (HashList::iterator it = old_bin.begin();
             it != it_end;
             ++it)
        {
            if (it->getKey() == key) {
                RRLEntry& entry = *it;
                // move it to the head of the new bin.
                entry.setHashGen(hash_gen_);
                new_bin.splice(new_bin.begin(), old_bin, it);

                refEntry(entry, probes, now); 
                return (&entry);
            }
        }
        // Discard prevous hash table when all of its entries are old.
        if (RRLEntry::TimestampBases::deltaTime(old_hash_->check_time_, now)
            > window)
        {
            old_hash_.reset();
        }
    }

    // The entry does not exist, so create it by finding a free entry.
    // Keep currently penalized and logged entries.
    // Try to make more entries if none are idle and none are old enough.
    // Steal the oldest entry if we cannot create more.
    const LRUList::reverse_iterator it_end = lru_.rend();
    LRUList::reverse_iterator it = lru_.rbegin();
    for (; it != it_end; ++it) {
        if (!it->hash_hook_.is_linked()) {
            break;
        }
        const int age = it->getAge(ts_bases, now);
        if (age <= 1) { // lease recently used is still too recent; create more
            it = it_end;
            break;
        }
        if (//!it->logged (TBD)
            it->getResponseBalance(rates, age) > 0) {
            break;
        }
    }
    if (it == it_end) {
        expandEntries(std::min((num_entries_ + 1) / 2, MAX_EXPAND_COUNT));
        it = lru_.rbegin();
    }
    // TBD it->logged
    RRLEntry& entry = *it;
    if (entry.hash_hook_.is_linked()) {
        const size_t old_hval = entry.getKey().getHash();
        Hash& h = (entry.getHashGen() == hash_gen_) ? *hash_ : *old_hash_;
        HashList& old_ent_bin = *h.bins_[old_hval % h.bins_.size()];
        old_ent_bin.erase(old_ent_bin.iterator_to(entry));
    }

    new_bin.push_front(entry);
    entry.reset(key, hash_gen_);
    refEntry(entry, probes, now);

    return (&entry);
}

void
RRLTable::refEntry(RRLEntry& entry, int probes, std::time_t now) {
    // Make the entry most recently used.
    const LRUList::const_iterator it = lru_.iterator_to(entry);
    if (it != lru_.begin()) {
        lru_.splice(lru_.begin(), lru_, it);
    }

    // Expand the hash table if it is time and necessary.
    // This will leave the newly referenced entry in a chain in the
    // old hash table.  It will migrate to the new hash table the next
    // time it is used or be cut loose when the old hash table is destroyed.
    probes_ += probes;
    ++searches_;
    if (searches_ > 100 &&
        RRLEntry::TimestampBases::deltaTime(hash_->check_time_, now) > 1) {
        if (probes_ / searches_ > 2) {
            expand(now);
        }
        hash_->check_time_ = now;
        probes_ = 0;
        searches_ = 0;
    }
}

} // namespace detail
} // namespace rrl
} // namespace auth
} // namespace isc

// Local Variables:
// mode: c++
// End:
