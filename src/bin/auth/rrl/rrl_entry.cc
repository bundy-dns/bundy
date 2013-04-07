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

#include <auth/rrl/rrl_entry.h>
#include <auth/rrl/rrl_result.h>
#include <auth/rrl/rrl_rate.h>

namespace isc {
namespace auth {
namespace rrl {
namespace detail {

const int RRLEntry::TIMESTAMP_FOREVER;

Result
RRLEntry::updateBalance(TimestampBases& ts_bases, RRLRate& rates,
                        double /*qps*/, std::time_t now, int window)
{
    const int rate = rates.getRate(getKey().getResponseType());
    if (rate == 0) {
        return (RRL_OK);
    }

    // Treat time jumps into the recent past as no time.
    // Treat entries older than the window as if they were just created
    // Credit other entries.
    const int age = getAge(ts_bases, now);
    if (age > 0) {
        if (age > window) {
            responses_ = rate;
            //slip_cnt_ = 0;
        } else {
            responses_ += rate * age;
            // The balance cannot be more positive than rate
            if (responses_ > rate) {
                responses_ = rate;
                //slip_cnt_ = 0;
            }
        }
    }
    setAge(ts_bases, now);

    // Debit the entry for this response.  The balance cannot be more negative
    // than -window * rate.
    if (--responses_ >= 0) {
        return (RRL_OK);
    }
    const int min = -window * rate;
    if (responses_ < min) {
        responses_ = min;
    }

    return (RRL_DROP);
}

int
RRLEntry::getResponseBalance(const RRLRate& rates, int age) const {
    const int rate = responses_ >= 0 ? 0 :
        rates.getRate(getKey().getResponseType());
    const int balance = responses_ + age * rate;
    if (balance > rate) {
        return (rate);
    }
    return (balance);
}

} // namespace detail
} // namespace rrl
} // namespace auth
} // namespace isc
