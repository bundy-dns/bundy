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

#include <auth/rrl/rrl_name_pool.h>

#include <dns/name.h>

#include <exceptions/exceptions.h>

#include <boost/shared_ptr.hpp>
#include <boost/intrusive/list.hpp>

#include <vector>
#include <utility>

namespace isc {
namespace auth {
namespace rrl {
namespace detail {

namespace {
struct NameEntry {
    NameEntry(size_t index_param, const dns::Name& name_param) :
        index(index_param), name(name_param)
    {}

    boost::intrusive::list_member_hook<> hook;
    size_t index;
    dns::Name name;
};
typedef boost::shared_ptr<NameEntry> NameEntryPtr;
}

struct NamePool::Impl {
    typedef boost::intrusive::list<
        NameEntry,
        boost::intrusive::member_hook<
            NameEntry, boost::intrusive::list_member_hook<>,
            &NameEntry::hook> > FreeList;
    Impl(size_t n_names) : max_names_(n_names) {}

    const size_t max_names_;
    std::vector<NameEntryPtr> names_;
    FreeList free_names_;
};

NamePool::NamePool(size_t n_names) :
    impl_(new Impl(n_names))
{}

NamePool::~NamePool() {
    delete impl_;
}

const dns::Name*
NamePool::getName(size_t index) {
    if (index == impl_->max_names_) {
        return (NULL);
    }
    return (&impl_->names_.at(index)->name);
}


std::pair<bool, size_t>
NamePool::saveName(const dns::Name& name) {
    if (!impl_->free_names_.empty()) {
        NameEntry& entry = impl_->free_names_.front();
        impl_->free_names_.pop_front();
        entry.name = name;
        return (std::pair<bool, size_t>(true, entry.index));
    }
    if (impl_->names_.size() == impl_->max_names_) {
        return (std::pair<bool, size_t>(false, impl_->max_names_));
    }
    impl_->names_.push_back(
        NameEntryPtr(new NameEntry(impl_->names_.size(), name)));
    return (std::pair<bool, size_t>(true, impl_->names_.back()->index));
}

void
NamePool::freeName(size_t index) {
    if (index == impl_->max_names_) {
        return;
    }
    NameEntry& entry = *impl_->names_.at(index);
    if (entry.hook.is_linked()) {
        isc_throw(InvalidOperation, "NamePool::freeName error: double free");
    }
    impl_->free_names_.push_front(entry);
}

size_t
NamePool::getSize() const {
    return (impl_->names_.size() - impl_->free_names_.size());
}

} // namespace detail
} // namespace rrl
} // namespace auth
} // namespace isc
