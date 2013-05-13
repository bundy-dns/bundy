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

#ifndef AUTH_RRL_NAME_POOL_H
#define AUTH_RRL_NAME_POOL_H 1

#include <dns/dns_fwd.h>

#include <boost/noncopyable.hpp>

#include <utility>

namespace isc {
namespace auth {
namespace rrl {
namespace detail {

/// \brief A helper pool of dns::Name objects for logging.
class NamePool : boost::noncopyable {
public:
    /// \brief Constructor.
    ///
    /// \param n_names Max number of names that can be saved in the pool.
    NamePool(size_t n_names);

    /// \brief Destructor.
    ~NamePool();

    /// \brief Save a name in the pool.
    ///
    /// If the pool already has max number of names (specified on
    /// construction) this operation fails, and the first element of the
    /// return value is set to false.
    ///
    /// \param name A Name object to be saved in the pool.
    /// \return A pair indicating the result: first element is true iff
    /// the name can be saved; second element is the pool index for the name
    /// in case the first element is true.
    std::pair<bool, size_t> saveName(const dns::Name& name);

    /// \brief Return a name from the pool by index.
    ///
    /// \throw std::out_of_range index is not valid as described below.
    ///
    /// \param index must be a previously returned index from saveName() or
    /// the max number of names specified on construction.
    ///
    /// \return A non NULL pointer to the saved name object for the index,
    /// or NULL if index is the max number.
    const dns::Name* getName(size_t index);

    /// \brief Free a previously saved name so it can be saved for another
    /// name.
    ///
    /// This method does nothing if index is the max number.  This way
    /// the caller can always call this method whether or not prior call
    /// to saveName() succeeds (indicated in the second element of its
    /// return value).
    ///
    /// \throw InvalidOperation the name of the specified index is already
    /// freed.
    /// \throw std::out_of_range index is invalid.
    ///
    /// \param index The index in the pool for the name to be freed; must be
    /// a value returned by a previous call to saveName().
    void freeName(size_t index);

    /// \brief Return the number of pooled names that are in use.
    ///
    /// This method can be slow and is only intended to be used for tests or
    /// other diagnostic purposes.
    ///
    /// \throw None
    size_t getSize() const;

private:
    struct Impl;
    Impl* impl_;
};

} // namespace detail
} // namespace rrl
} // namespace auth
} // namespace isc

#endif // AUTH_RRL_NAME_POOL_H

// Local Variables:
// mode: c++
// End:
