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

void
RRLTable::expand(std::time_t /*now*/) {
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
    // TBD update check_time
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

} // namespace detail
} // namespace rrl
} // namespace auth
} // namespace isc

// Local Variables:
// mode: c++
// End:
