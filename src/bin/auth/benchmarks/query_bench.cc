// Copyright (C) 2010  Internet Systems Consortium, Inc. ("ISC")
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

#include <config.h>

#include <bench/benchmark.h>
#include <bench/benchmark_util.h>

#include <auth/rrl/rrl.h>

#include <util/buffer.h>

#include <dns/message.h>
#include <dns/name.h>
#include <dns/question.h>
#include <dns/rrclass.h>

#include <log/logger_support.h>
#include <xfr/xfrout_client.h>

#include <util/unittests/mock_socketsession.h>

#include <auth/auth_srv.h>
#include <auth/auth_config.h>
#include <auth/datasrc_config.h>
#include <auth/datasrc_clients_mgr.h>
#include <auth/query.h>

#include <asiodns/asiodns.h>
#include <asiolink/asiolink.h>

#include <boost/shared_ptr.hpp>

#include <stdlib.h>

#include <iostream>
#include <vector>
#include <ctime>
#include <csignal>
#include <unistd.h>

using namespace std;
using namespace isc;
using namespace isc::data;
using namespace isc::auth;
using namespace isc::dns;
using namespace isc::log;
using namespace isc::util;
using namespace isc::util::unittests;
using namespace isc::xfr;
using namespace isc::bench;
using namespace isc::asiodns;
using namespace isc::asiolink;

namespace {
// Commonly used constant:
XfroutClient xfrout_client("dummy_path"); // path doesn't matter

std::time_t now;

// Just something to pass as the server to resume
class DummyServer : public DNSServer {
    public:
        virtual void operator()(asio::error_code, size_t) {}
        virtual void resume(const bool) {}
        virtual DNSServer* clone() {
            return (new DummyServer(*this));
        }
};

class QueryBenchMark {
protected:
    // Maintain dynamically generated objects via shared pointers because
    // QueryBenchMark objects will be copied.
    typedef boost::shared_ptr<AuthSrv> AuthSrvPtr;
private:
    typedef boost::shared_ptr<const IOEndpoint> IOEndpointPtr;
protected:
    QueryBenchMark(const BenchQueries& queries, Message& query_message,
                   OutputBuffer& buffer, bool enable_rrl, size_t num_sources,
                   size_t* slip_count, size_t* drop_count) :
        server_(new AuthSrv(xfrout_client, ddns_forwarder)),
        queries_(queries),
        query_message_(query_message),
        buffer_(buffer),
        dummy_socket(IOSocket::getDummyUDPSocket()),
        enable_rrl_(enable_rrl), slip_count_(slip_count),
        drop_count_(drop_count)
    {
        if (enable_rrl) {
            now = std::time(NULL);
            server_->setRRL(new auth::rrl::ResponseLimiter(
                                200000, 200000, 5, 5, 5, 15, 2, 32, 56, false,
                                now));
        }
        for (uint32_t i = 0; i < num_sources; ++i) {
            const string addr_txt =
                boost::lexical_cast<string>((i >> 24) & 0xff) + "." +
                boost::lexical_cast<string>((i >> 16) & 0xff) + "." +
                boost::lexical_cast<string>((i >> 8) & 0xff) + "." +
                boost::lexical_cast<string>(i & 0xff);
            dummy_endpoints.push_back(IOEndpointPtr(IOEndpoint::create(
                                                        IPPROTO_UDP,
                                                        IOAddress(addr_txt),
                                                        53210)));
        }
        ep_begin_ = dummy_endpoints.begin();
        ep_end_ = dummy_endpoints.end();
        ep_it_ = ep_begin_;
    }
public:
    unsigned int run() {
        BenchQueries::const_iterator query;
        const BenchQueries::const_iterator query_end = queries_.end();
        DummyServer server;
        for (query = queries_.begin(); query != query_end; ++query) {
            IOMessage io_message(&(*query)[0], (*query).size(), dummy_socket,
                                 **ep_it_);
            if (++ep_it_ == ep_end_) {
                ep_it_ = ep_begin_;
            }
            query_message_.clear(Message::PARSE);
            buffer_.clear();
            server_->processMessage(io_message, query_message_, buffer_,
                                    &server, now);
            if (enable_rrl_) {
                if (buffer_.getLength() == 0) {
                    ++*drop_count_;
                } else if (query_message_.getHeaderFlag(
                               Message::HEADERFLAG_TC)) {
                    ++*slip_count_;
                }
            }
        }

        return (queries_.size());
    }
private:
    MockSocketSessionForwarder ddns_forwarder;
protected:
    AuthSrvPtr server_;
private:
    const BenchQueries& queries_;
    Message& query_message_;
    OutputBuffer& buffer_;
    IOSocket& dummy_socket;
    vector<IOEndpointPtr> dummy_endpoints;
    vector<IOEndpointPtr>::const_iterator ep_begin_;
    vector<IOEndpointPtr>::const_iterator ep_end_;
    vector<IOEndpointPtr>::const_iterator ep_it_;
    const bool enable_rrl_;
    size_t* slip_count_;
    size_t* drop_count_;
};

class Sqlite3QueryBenchMark  : public QueryBenchMark {
public:
    Sqlite3QueryBenchMark(const char* const datasrc_file,
                          const BenchQueries& queries,
                          Message& query_message,
                          OutputBuffer& buffer,
                          bool enable_rrl, size_t num_sources,
                          size_t* slip_count, size_t* drop_count) :
        QueryBenchMark(queries, query_message, buffer, enable_rrl, num_sources,
                       slip_count, drop_count)
    {
        // Note: setDataSrcClientLists() may be deprecated, but until then
        // we use it because we want to be synchronized with the server.
        server_->getDataSrcClientsMgr().setDataSrcClientLists(
            configureDataSource(
                Element::fromJSON("{\"IN\":"
                                  "  [{\"type\": \"sqlite3\","
                                  "    \"params\": {"
                                  "      \"database_file\": \"" +
                                  string(datasrc_file) + "\"}}]}")));
    }
};

class MemoryQueryBenchMark  : public QueryBenchMark {
public:
    MemoryQueryBenchMark(const char* const zone_file,
                         const char* const zone_origin,
                         const BenchQueries& queries,
                         Message& query_message,
                         OutputBuffer& buffer,
                         bool enable_rrl, size_t num_sources,
                         size_t* slip_count, size_t* drop_count) :
        QueryBenchMark(queries, query_message, buffer, enable_rrl, num_sources,
                       slip_count, drop_count)
    {
        server_->getDataSrcClientsMgr().setDataSrcClientLists(
            configureDataSource(
                Element::fromJSON("{\"IN\":"
                                  "  [{\"type\": \"MasterFiles\","
                                  "    \"cache-enable\": true, "
                                  "    \"params\": {\"" +
                                  string(zone_origin) + "\": \"" +
                                  string(zone_file) + "\"}}]}")));
    }
};

void
printQPSResult(unsigned int iteration, double duration,
               double iteration_per_second)
{
    cout.precision(6);
    cout << "Processed " << iteration << " queries in "
         << fixed << duration << "s";
    cout.precision(2);
    cout << " (" << fixed << iteration_per_second << "qps)" << endl;
}
}

namespace isc {
namespace bench {
template<>
void
BenchMark<Sqlite3QueryBenchMark>::printResult() const {
    printQPSResult(getIteration(), getDuration(), getIterationPerSecond());
}

template<>
void
BenchMark<MemoryQueryBenchMark>::printResult() const {
    printQPSResult(getIteration(), getDuration(), getIterationPerSecond());
}
}
}

namespace {
void
updateCurrentTime(int) {
    alarm(1);
    now = std::time(NULL);
}

const int ITERATION_DEFAULT = 1;
const size_t SOURCES_DEFAULT = 1;
enum DataSrcType {
    SQLITE3,
    MEMORY
};

void
usage() {
    cerr <<
        "Usage: query_bench [-d] [-n iterations] [-t datasrc_type] [-o origin]"
        " [-r] [-s num] datasrc_file query_datafile\n"
        "  -d Enable debug logging to stdout\n"
        "  -n Number of iterations per test case (default: "
         << ITERATION_DEFAULT << ")\n"
        "  -t Type of data source: sqlite3|memory (default: sqlite3)\n"
        "  -o Origin name of datasrc_file necessary for \"memory\", "
        "ignored for others\n"
        "  -r enable response rate limit\n"
        "  -s number of client's source addresses (useful with -r)\n"
        "  datasrc_file: sqlite3 DB file for \"sqlite3\", "
        "textual master file for \"memory\" datasrc\n"
        "  query_datafile: queryperf style input data"
         << endl;
    exit (1);
}
}

int
main(int argc, char* argv[]) {
    int ch;
    int iteration = ITERATION_DEFAULT;
    size_t num_sources = SOURCES_DEFAULT;
    const char* opt_datasrc_type = "sqlite3";
    const char* origin = NULL;
    bool enable_rrl = false;
    bool debug_log = false;
    while ((ch = getopt(argc, argv, "dn:t:o:rs:")) != -1) {
        switch (ch) {
        case 'n':
            iteration = atoi(optarg);
            break;
        case 't':
            opt_datasrc_type = optarg;
            break;
        case 'o':
            origin = optarg;
            break;
        case 'r':
            enable_rrl = true;
            break;
        case 's':
            num_sources = atoi(optarg);
            break;
        case 'd':
            debug_log = true;
            break;
        case '?':
        default:
            usage();
        }
    }
    argc -= optind;
    argv += optind;
    if (argc < 2) {
        usage();
    }
    const char* const datasrc_file = argv[0];
    const char* const query_data_file = argv[1];

    // By default disable logging to avoid unwanted noise.
    initLogger("query-bench", debug_log ? isc::log::DEBUG : isc::log::NONE,
               isc::log::MAX_DEBUG_LEVEL, NULL);

    DataSrcType datasrc_type = SQLITE3;
    if (strcmp(opt_datasrc_type, "sqlite3") == 0) {
        ;                       // no need to override
    } else if (strcmp(opt_datasrc_type, "memory") == 0) {
        datasrc_type = MEMORY;
    } else {
        cerr << "Unknown data source type: " << datasrc_type << endl;
        return (1);
    }

    if (datasrc_type == MEMORY && origin == NULL) {
        cerr << "'-o Origin' is missing for memory data source " << endl;
        return (1);
    }

    try {
        BenchQueries queries;
        loadQueryData(query_data_file, queries, RRClass::IN());
        OutputBuffer buffer(4096);
        Message message(Message::PARSE);

        cout << "Parameters:" << endl;
        cout << "  Iterations: " << iteration << endl;
        cout << "  Data Source: type=" << opt_datasrc_type << ", file=" <<
            datasrc_file << endl;
        if (origin != NULL) {
            cout << "  Origin: " << origin << endl;
        }
        cout << "  Query data: file=" << query_data_file << " ("
             << queries.size() << " queries)" << endl << endl;

        if (enable_rrl) {
            alarm(1);
            std::signal(SIGALRM, updateCurrentTime);
        }

        size_t slip_count = 0;
        size_t drop_count = 0;
        switch (datasrc_type) {
        case SQLITE3:
            cout << "Benchmark with SQLite3" << endl;
            BenchMark<Sqlite3QueryBenchMark>(
                iteration, Sqlite3QueryBenchMark(datasrc_file, queries,
                                                 message, buffer, enable_rrl,
                                                 num_sources, &slip_count,
                                                 &drop_count));
            break;
        case MEMORY:
            cout << "Benchmark with In Memory Data Source" << endl;
            BenchMark<MemoryQueryBenchMark>(
                iteration, MemoryQueryBenchMark(datasrc_file, origin, queries,
                                                message, buffer, enable_rrl,
                                                num_sources, &slip_count,
                                                &drop_count));
            break;
        }
        if (enable_rrl) {
            std::cout << "Slip: " << slip_count << ", Drop: " << drop_count
                      << std::endl;
        }
    } catch (const std::exception& ex) {
        cout << "Test unexpectedly failed: " << ex.what() << endl;
        return (1);
    }

    return (0);
}
