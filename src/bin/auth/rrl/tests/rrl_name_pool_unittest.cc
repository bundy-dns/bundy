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

#include <gtest/gtest.h>

#include <stdexcept>

using namespace isc::auth::rrl::detail;
using namespace isc::auth::rrl;
using namespace isc::dns;

namespace {

// This class is simple; a set of basic case tests should suffice.
TEST(RRLNamePool, tests) {
    NamePool names(2);

    // Initially pool is empty.  getName() would result in out_of_range,
    // except for the special value = max size, in which it returns NULL,
    // indicating the name would have to be saved.
    EXPECT_THROW(names.getName(0), std::out_of_range);
    EXPECT_EQ(static_cast<const Name*>(NULL), names.getName(2));

    // We can save up to 2 names, and we can find them.
    std::pair<bool, size_t> result = names.saveName(Name("example.com"));
    EXPECT_TRUE(result.first);
    EXPECT_EQ(0, result.second);
    EXPECT_EQ(Name("example.com"), *names.getName(0));

    result = names.saveName(Name("example.org"));
    EXPECT_TRUE(result.first);
    EXPECT_EQ(1, result.second);
    EXPECT_EQ(Name("example.org"), *names.getName(1));

    // out-of-range cases still hold
    EXPECT_THROW(names.getName(3), std::out_of_range);
    EXPECT_EQ(static_cast<const Name*>(NULL), names.getName(2));

    // No more names can be saved
    EXPECT_FALSE(names.saveName(Name("example")).first);

    // we can free names; duplicate free attempt would result in exception.
    names.freeName(0);
    EXPECT_THROW(names.freeName(0), isc::InvalidOperation);
    // if index = max size, freeName() should be nop
    EXPECT_NO_THROW(names.freeName(2));

    // then we can add another name again.
    result = names.saveName(Name("example"));
    EXPECT_TRUE(result.first);
    EXPECT_EQ(0, result.second);
    EXPECT_EQ(Name("example"), *names.getName(0));
}
}
