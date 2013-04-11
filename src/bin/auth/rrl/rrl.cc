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

#include <auth/rrl/rrl.h>
#include <auth/rrl/rrl_rate.h>
#include <auth/rrl/rrl_table.h>
#include <auth/rrl/rrl_entry.h>
#include <auth/rrl/rrl_response_type.h>

#include <dns/name.h>
#include <dns/labelsequence.h>
#include <dns/rcode.h>
#include <dns/rrtype.h>
#include <dns/rrclass.h>

#include <exceptions/exceptions.h>

#include <asiolink/io_endpoint.h>

#include <boost/bind.hpp>

#include <cstring>
#include <vector>

using isc::asiolink::IOEndpoint;
using namespace isc::dns;

namespace isc {
namespace auth {
namespace rrl {
using namespace detail;

namespace {
void
setMask(void* mask, size_t mask_len, int plen) {
    std::vector<uint8_t> buf;
    while (plen > 8) {
        buf.push_back(0xff);
        plen -= 8;
    }
    if (plen > 0) {
        buf.push_back(0xff << (8 - plen));
    }
    assert(buf.size() <= mask_len);
    buf.insert(buf.end(), mask_len - buf.size(), 0);
    assert(buf.size() == mask_len);

    std::memcpy(mask, &buf[0], mask_len);
}
}

struct ResponseLimiter::ResponseLimiterImpl {
    ResponseLimiterImpl(size_t max_entries, int min_entries,
                        int responses_per_second,
                        int nxdomains_per_second, int errors_per_second,
                        int window, int slip, int ipv4_prefixlen,
                        int ipv6_prefixlen, bool log_only, std::time_t now) :
        table_(max_entries),
        rates_(responses_per_second, nxdomains_per_second, errors_per_second),
        window_(window), slip_(slip),
        ts_bases_(now, boost::bind(&RRLTable::timestampBaseUpdated, &table_,
                                   _1)),
        log_only_(log_only)
    {
        if (ipv4_prefixlen < 0 || ipv4_prefixlen > 32) {
            isc_throw(InvalidParameter, "bad IPv4 prefix: " << ipv4_prefixlen);
        }
        if (ipv6_prefixlen < 0 || ipv6_prefixlen > 128) {
            isc_throw(InvalidParameter, "bad IPv6 prefix: " << ipv6_prefixlen);
        }
        setMask(&ipv4_mask_, sizeof(ipv4_mask_), ipv4_prefixlen);
        setMask(&ipv6_mask_, sizeof(ipv6_mask_), ipv6_prefixlen);

        table_.expandEntries(min_entries);
        table_.expand(now);
    }
    RRLTable table_;
    RRLRate rates_;
    const int window_;
    const int slip_;
    RRLEntry::TimestampBases ts_bases_;
    const bool log_only_;
    uint32_t ipv4_mask_;
    uint32_t ipv6_mask_[4];
};

ResponseLimiter::ResponseLimiter(size_t max_entries, size_t min_entries,
                                 int responses_per_second,
                                 int nxdomains_per_second,
                                 int errors_per_second, int window, int slip,
                                 int ipv4_prefixlen, int ipv6_prefixlen,
                                 bool log_only, std::time_t now) :
    impl_(new ResponseLimiterImpl(max_entries, min_entries,
                                  responses_per_second, nxdomains_per_second,
                                  errors_per_second, window, slip,
                                  ipv4_prefixlen, ipv6_prefixlen, log_only,
                                  now))
{}

ResponseLimiter::~ResponseLimiter() {
    delete impl_;
}

int
ResponseLimiter::getResponseRate() const {
    return (impl_->rates_.getRate(RESPONSE_QUERY));
}

int
ResponseLimiter::getNXDOMAINRate() const {
    return (impl_->rates_.getRate(RESPONSE_NXDOMAIN));
}

int
ResponseLimiter::getErrorRate() const {
    return (impl_->rates_.getRate(RESPONSE_ERROR));
}

size_t
ResponseLimiter::getEntryCount() const {
    return (impl_->table_.getEntryCount());
}

int
ResponseLimiter::getWindow() const {
    return (impl_->window_);
}

int
ResponseLimiter::getSlip() const {
    return (impl_->slip_);
}

std::time_t
ResponseLimiter::getCurrentTimestampBase(std::time_t now) const {
    return (impl_->ts_bases_.getCurrentBase(now).first);
}

bool
ResponseLimiter::isLogOnly() const {
    return (impl_->log_only_);
}

uint32_t
ResponseLimiter::getIPv4Mask() const {
    return (impl_->ipv4_mask_);
}

const uint32_t*
ResponseLimiter::getIPv6Mask() const {
    return (impl_->ipv6_mask_);
}

namespace {
inline
ResponseType
convertRcode(const Rcode& rcode) {
    if (rcode == Rcode::NOERROR()) {
        return (RESPONSE_QUERY);
    } else if (rcode == Rcode::NXDOMAIN()) {
        return (RESPONSE_NXDOMAIN);
    }
    return (RESPONSE_ERROR);
}
}

Result
ResponseLimiter::check(const asiolink::IOEndpoint& client_addr,
                       bool is_tcp, const RRClass& qclass,
                       const RRType& qtype, const LabelSequence* qname,
                       const Rcode& rcode, std::time_t now)
{
    // Notice TCP responses when scaling limits by qps (not yet)
    // Do not try to rate limit TCP responses.
    if (is_tcp) {
        return (RRL_OK);
    }

    const ResponseType resp_type = convertRcode(rcode);

    // Find the right kind of entry, creating it if necessary.
    // If that is impossible (it's actually never impossible, we assert it),
    // then nothing more can be done.
    RRLEntry* entry =
        impl_->table_.getEntry(RRLKey(client_addr, qtype, qname, qclass,
                                      resp_type, impl_->ipv4_mask_,
                                      impl_->ipv6_mask_, 1128),
                               impl_->ts_bases_, impl_->rates_, now,
                               impl_->window_);
    assert(entry);

    const Result result =
        entry->updateBalance(impl_->ts_bases_, impl_->rates_, impl_->slip_, 0,
                             now, impl_->window_);

    // TBD: log non OK results here.

    return (result);
}

} // namespace rrl
} // namespace auth
} // namespace isc
