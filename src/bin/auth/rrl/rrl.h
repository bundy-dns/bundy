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

#ifndef AUTH_RRL_H
#define AUTH_RRL_H 1

#include <auth/rrl/rrl_result.h>

#include <dns/dns_fwd.h>
#include <dns/labelsequence.h>

#include <asiolink/io_endpoint.h>

#include <boost/noncopyable.hpp>

#include <ctime>
#include <string>
#include <stdint.h>

namespace isc {
namespace asiolink {
class IOEndpoint;
}
namespace auth {
namespace rrl {

class ResponseLimiter : boost::noncopyable {
public:
    /// \brief Constructor.
    ResponseLimiter(size_t max_table_size, size_t min_table_size,
                    int responses_per_second, int nxdomains_per_second,
                    int errors_per_second, int window, int slip,
                    int ipv4_prefixlen, int ipv6_prefixlen, bool log_only,
                    std::time_t now);

    /// \brief Destructor
    ~ResponseLimiter();

    Result check(const asiolink::IOEndpoint& client_addr,
                 bool is_tcp, const dns::RRClass& qclass,
                 const dns::RRType& qtype, const dns::LabelSequence* qname,
                 const dns::Rcode& rcode, std::time_t now,
                 std::string& log_msg);

    /// getters basically for testing purposes
    int getResponseRate() const;
    int getNXDOMAINRate() const;
    int getErrorRate() const;
    size_t getEntryCount() const;
    int getWindow() const;
    int getSlip() const;
    std::time_t getCurrentTimestampBase(std::time_t now) const;
    bool isLogOnly() const;
    uint32_t getIPv4Mask() const;
    const uint32_t* getIPv6Mask() const;

private:
    struct ResponseLimiterImpl;
    ResponseLimiterImpl* impl_;
};

} // namespace rrl
} // namespace auth
} // namespace isc

#endif // AUTH_RRL_H

// Local Variables:
// mode: c++
// End:
