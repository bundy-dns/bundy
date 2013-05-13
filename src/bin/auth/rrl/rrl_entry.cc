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
#include <auth/rrl/rrl_name_pool.h>
#include <auth/rrl/logger.h>

#include <dns/rcode.h>

#include <algorithm>
#include <utility>

using namespace isc::dns;

namespace isc {
namespace auth {
namespace rrl {
namespace detail {

const int RRLEntry::TIMESTAMP_FOREVER;

Result
RRLEntry::updateBalance(TimestampBases& ts_bases, RRLRate& rates,
                        int slip, double /*qps*/, std::time_t now, int window)
{
    const int rate = rates.getRate(key_.getResponseType());
    if (rate == 0) {
        return (RRL_OK);
    }

    // Treat time jumps into the recent past as no time.
    // Treat entries older than the window as if they were just created
    // Credit other entries.  The slip count will be reset after some
    // period of no query.
    const int age = getAge(ts_bases, now);
    if (age > 0) {
        // Credit tokens earned during elapsed time.
        if (age > window) {
            responses_ = rate;
            slip_cnt_ = 0;
        } else {
            responses_ += rate * age;
            // The balance cannot be more positive than rate
            if (responses_ > rate) {
                responses_ = rate;
                slip_cnt_ = 0;
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

    // Drop this response unless it should slip.  If configured slip count
    // is 1, all penalized queries will result in slip.
    if (slip != 0) {
        if (slip == 1 || slip_cnt_++ == 0) {
            // TBD: log it
            return (RRL_SLIP);
        } else if (slip_cnt_ >= slip) {
            slip_cnt_ = 0;
        }
    }
    // TBD: log it.
    return (RRL_DROP);
}

NamePool*
RRLEntry::createNamePool() {
    return (new NamePool(LOG_QNAMES));
}

int
RRLEntry::getResponseBalance(const RRLRate& rates, int age) const {
    if (responses_ > 0) {
        return (responses_);
    }
    const int rate = rates.getRate(key_.getResponseType());
    const int balance = responses_ + age * rate;
    return (std::min(rate, balance));
}

std::string
RRLEntry::makeLogMessage(const char* str1, const char* str2, Result result,
                         const Rcode& rcode, NamePool& names,
                         const Name* qname, bool save_qname,
                         int ipv4_prefixlen, int ipv6_prefixlen)
{
    std::stringstream ss;

    if (str1) {
        ss << str1;
    }
    if (str2) {
        ss << str2;
    }

    switch (result) {
    case RRL_OK:
        break;
    case RRL_DROP:
        ss << "drop ";
        break;
    case RRL_SLIP:
        ss << "slip ";
        break;
    }

    const ResponseType resp_type = key_.getResponseType();
    switch (resp_type) {
    case RESPONSE_QUERY:
        break;
    case RESPONSE_NXDOMAIN:
        ss << "NXDOMAIN ";
        break;
    case RESPONSE_ERROR:
        if (rcode == Rcode::NOERROR()) {
            ss << "error ";
        } else {
            ss << rcode << " error ";
        }
        break;
    }
    ss << "response to " << key_.getIPText(ipv4_prefixlen, ipv6_prefixlen);

    if (resp_type == RESPONSE_QUERY || resp_type == RESPONSE_NXDOMAIN) {
        const Name* saved_qname = names.getName(log_qname_);
        if (!saved_qname && save_qname && qname) {
            const std::pair<bool, size_t> save_result = names.saveName(*qname);
            if (save_result.first) {
                log_qname_ = save_result.second;
            }
        }
        if (qname || saved_qname) {
            ss << " for "
               << (qname ? qname->toText(true) : saved_qname->toText(true));
        } else {
            ss << " for (?)";
        }

        if (resp_type == RESPONSE_QUERY) {
            ss << ' ' << key_.getClassText();
            const RRType qtype = key_.getType();
            if (qtype != RRType(0)) {
                ss << ' ' << qtype;
            }
        }
    }
    return (ss.str());
}

bool
RRLEntry::dumpLimitLog(const Name* qname, NamePool& names,
                       const dns::Rcode& rcode, bool log_only,
                       int ipv4_prefixlen, int ipv6_prefixlen,
                       std::string& log_msg)
{
    bool newly_logged = false;
    if ((!logged_ || log_secs_ >= MAX_LOG_SECS) && logger.isInfoEnabled()) {
        log_msg = makeLogMessage(log_only ? "would " : NULL,
                                 logged_ ? "continue limiting " : "limit ",
                                 RRL_OK, rcode, names, qname, true,
                                 ipv4_prefixlen, ipv6_prefixlen);
        logger.info(AUTH_RRL_LIMIT).arg(log_msg);

        if (!logged_) {
            newly_logged = true;
            logged_ = true;
        }
        log_secs_ = 0;
    }
    return (newly_logged);
}

} // namespace detail
} // namespace rrl
} // namespace auth
} // namespace isc
