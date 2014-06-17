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

#ifndef AUTH_RRL_TIMESTAMPS_H
#define AUTH_RRL_TIMESTAMPS_H 1

#include <boost/array.hpp>
#include <boost/function.hpp>

#include <ctime>
#include <utility>

namespace bundy {
namespace auth {
namespace detail {

/// \brief timestamp set used in RRL operation.
///
/// This class maintains a set of reasonably recent value of absolute
/// timestamps in a form of a ring buffer.
///
/// Template parameter BASES_COUNT is the buffer size.
/// TIMESTAMP_FOREVER specifies the range of time while a base is considered
/// recent enough.  After that period of seconds passed, it generates a new
/// timestamp base.
template <size_t BASES_COUNT, int TIMESTAMP_FOREVER>
class RRLTimeStampBases {
    static const int MAX_TIME_TRAVEL = 5;
    static const int MAX_TIMESTAMP = TIMESTAMP_FOREVER - 1;
public:
    /// \brief A functor type to be called when new timestamp base is
    /// (about to be) generated.
    ///
    /// Its parameter is the generation ID of the base to be updated.
    typedef boost::function<void(size_t)> BaseChangeCallback;

    /// \brief Constructor.
    ///
    /// \param initial_ts The initial timestamp to be set to the base.
    /// In practice, this is the current time on construction.
    /// \param callback Functor to be called when a base time is changed.
    RRLTimeStampBases(std::time_t initial_ts, BaseChangeCallback callback) :
        current_(0), callback_(callback)
    {
        for (size_t i = 0; i < BASES_COUNT; ++i) {
            bases_[i] = initial_ts;
        }
    }

    /// \brief Returns the timestamp base appropriate for the given time.
    ///
    /// It basically returns the current base timestamp.  But if it's too old
    /// or if it's in the "distant future" (see deltaTime()), make a new
    /// timestamp base and return it.  In the latter case it calls the callback
    /// given on construction with the generation ID of the base to be updated.
    ///
    /// Note also that the current base is in (not distant) future than \c now
    /// depending on how the caller gets it and the timing the base is updated.
    /// Unless it's in the "distant future", this method does not update the
    /// base and returns the current base timestamp.
    ///
    /// This method returns a pair of the timestamp base and of its generation
    /// ID.
    std::pair<std::time_t, size_t>
    getCurrentBase(std::time_t now) {
        const int ts = now - bases_[current_];
        if (ts >= MAX_TIMESTAMP || ts < -MAX_TIME_TRAVEL) {
            const size_t new_current = (current_ + 1) % BASES_COUNT;
            callback_(new_current);

            current_ = new_current;
            bases_[current_] = now;
        }
        return (std::pair<std::time_t, size_t>(bases_[current_], current_));
    }

    /// \brief Return the specified generation of timestamp base.
    std::time_t getBaseByGen(size_t gen) const {
        return (bases_.at(gen));
    }

    /// \brief Utility for calculating difference between times.
    ///
    /// It returns the difference between the given current time (\c now)
    /// and (supposedly) past time (\c timestamp).  If the "past" time is
    /// in future for more than 5 seconds from \c now, it assumes there's a
    /// system clock change, and returns a special value of
    /// \c TIMESTAMP_FOREVER.  Otherwise, it returns 0, considering the
    /// difference is within a margin.
    ///
    /// The algorithm is independent from this class, but refers to its
    /// constants, so defined here as a static member function.
    static int
    deltaTime(std::time_t timestamp, std::time_t now) {
        const int delta = now - timestamp;
        if (delta >= 0) {
            return (delta);
        }

        // The timestamp is in the future.  That future might result from
        // re-ordered requests, because we use timestamps on requests
        // instead of consulting a clock.  Timestamps in the distant future are
        // assumed to result from clock changes.  When the clock changes to
        // the past, make existing timestamps appear to be in the past.
        if (delta < -MAX_TIME_TRAVEL) {
            return (TIMESTAMP_FOREVER);
        }
        return (0);
    }
private:
    boost::array<std::time_t, BASES_COUNT> bases_;
    size_t current_;
    const BaseChangeCallback callback_;
};

} // namespace detail
} // namespace auth
} // namespace bundy

#endif // AUTH_RRL_TIMESTAMPS_H

// Local Variables:
// mode: c++
// End:
