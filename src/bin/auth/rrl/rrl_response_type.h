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

#ifndef AUTH_RESPONSE_TYPE_H
#define AUTH_RESPONSE_TYPE_H 1

#include <stdint.h>

#include <boost/static_assert.hpp>

namespace isc {
namespace auth {
namespace rrl {
namespace detail {

/// \brief Type of responses in terms of RRL.
enum ResponseType {
    RESPONSE_QUERY = 0,
    RESPONSE_NXDOMAIN,
    RESPONSE_ERROR,
    RESPONSE_TYPE_MAX = RESPONSE_ERROR
};

// Make sure types fit in a 8-bit storage.
BOOST_STATIC_ASSERT(RESPONSE_TYPE_MAX < 256);

} // namespace detail
} // namespace rrl
} // namespace auth
} // namespace isc

#endif // AUTH_RESPONSE_TYPE_H

// Local Variables:
// mode: c++
// End:
