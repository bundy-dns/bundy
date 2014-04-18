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

#include <datasrc/cache_config.h>
#include <datasrc/client.h>
#include <datasrc/memory/load_action.h>
#include <datasrc/memory/zone_data_loader.h>

#include <util/memory_segment.h>

#include <dns/name.h>
#include <dns/rrclass.h>

#include <cc/data.h>
#include <exceptions/exceptions.h>

#include <boost/bind.hpp>

#include <cassert>
#include <map>
#include <string>

using namespace bundy::data;

namespace bundy {
namespace datasrc {
namespace internal {

namespace {
bool
getEnabledFromConf(const Element& conf) {
    return (conf.contains("cache-enable") &&
            conf.get("cache-enable")->boolValue());
}

std::string
getSegmentTypeFromConf(const Element& conf) {
    // If cache-type is not explicitly configured, use the default type.
    // (Ideally we should retrieve the default from the spec).
    if (!conf.contains("cache-type")) {
        return ("local");
    }
    return (conf.get("cache-type")->stringValue());
}
}

CacheConfig::CacheConfig(const std::string& datasrc_type,
                         const DataSourceClient* datasrc_client,
                         const Element& datasrc_conf,
                         bool allowed) :
    enabled_(allowed && getEnabledFromConf(datasrc_conf)),
    segment_type_(getSegmentTypeFromConf(datasrc_conf)),
    datasrc_client_(datasrc_client)
{
    ConstElementPtr params = datasrc_conf.get("params");
    if (!params) {
        params.reset(new NullElement());
    }
    if (datasrc_type == "MasterFiles") {
        if (datasrc_client_) {
            bundy_throw(InvalidParameter,
                      "data source client is given for MasterFiles");
        }

        if (!enabled_) {
            bundy_throw(CacheConfigError,
                      "The cache must be enabled for the MasterFiles type: "
                      << datasrc_conf);
        }

        typedef std::map<std::string, ConstElementPtr> ZoneToFile;
        const ZoneToFile& zone_to_file = params->mapValue();
        ZoneToFile::const_iterator const it_end = zone_to_file.end();
        for (ZoneToFile::const_iterator it = zone_to_file.begin();
             it != it_end;
             ++it)
        {
            zone_config_[dns::Name(it->first)] = it->second->stringValue();
        }
    } else {
        if (!datasrc_client_) {
            bundy_throw(InvalidParameter,
                      "data source client is missing for data source type: "
                      << datasrc_type);
        }
        if (!enabled_) {
            return;
        }

        if (!datasrc_conf.contains("cache-zones")) {
            bundy_throw(NotImplemented, "Auto-detection of zones "
                      "to cache is not yet implemented, supply "
                      "cache-zones parameter: "
                      << datasrc_conf);
            // TODO: Auto-detect list of all zones in the
            // data source.
        }

        const ConstElementPtr zones = datasrc_conf.get("cache-zones");
        for (size_t i = 0; i < zones->size(); ++i) {
            const dns::Name zone_name(zones->get(i)->stringValue());
            if (!zone_config_.insert(Zones::value_type(zone_name,
                                                       "")).second) {
                bundy_throw(CacheConfigError, "Duplicate cache zone: " <<
                          zone_name);
            }
        }
    }
}

namespace {
// We can't use the loadZoneData function directly in boost::bind, since
// it is overloaded and the compiler can't choose the correct version
// reliably and fails. So we simply wrap it into an unique name.
memory::ZoneDataLoader*
createLoaderFromFile(util::MemorySegment& segment, const dns::RRClass& rrclass,
                     const dns::Name& name, const std::string& filename,
                     memory::ZoneData* old_data)
{
    return (new memory::ZoneDataLoader(segment, rrclass, name, filename,
                                       old_data));
}

memory::ZoneDataLoader*
createLoaderFromDataSource(util::MemorySegment& segment,
                           const dns::RRClass& rrclass,
                           const dns::Name& name,
                           const DataSourceClient* datasrc_client,
                           memory::ZoneData* old_data)
{
    return (new memory::ZoneDataLoader(segment, rrclass, name,
                                       *datasrc_client, old_data));
}

} // unnamed namespace

memory::ZoneDataLoaderCreator
CacheConfig::getLoaderCreator(const dns::RRClass& rrclass,
                              const dns::Name& zone_name) const
{
    // First, check if the specified zone is configured to be cached.
    Zones::const_iterator found = zone_config_.find(zone_name);
    if (found == zone_config_.end()) {
        return (memory::ZoneDataLoaderCreator());
    }

    if (!found->second.empty()) {
        // This is "MasterFiles" data source.
        return (boost::bind(createLoaderFromFile, _1, rrclass, zone_name,
                            found->second, _2));
    }

    // Otherwise there must be a "source" data source (ensured by constructor)
    assert(datasrc_client_);

    // If the specified zone name does not exist in our client of the source,
    // NoSuchZone is thrown, which is exactly the result what we
    // want, so no need to handle it.
    ZoneIteratorPtr iterator(datasrc_client_->getIterator(zone_name));
    if (!iterator) {
        // This shouldn't happen for a compliant implementation of
        // DataSourceClient, but we'll protect ourselves from buggy
        // implementations.
        bundy_throw(Unexpected, "getting loader creator for " << zone_name
                  << "/" << rrclass << " resulted in Null zone iterator");
    }

    // Wrap the iterator into the correct functor (which keeps it alive as
    // long as it is needed).
    return (boost::bind(createLoaderFromDataSource, _1, rrclass, zone_name,
                        datasrc_client_, _2));
}

} // namespace internal
} // namespace datasrc
} // namespace bundy
