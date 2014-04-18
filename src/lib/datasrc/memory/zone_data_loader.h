// Copyright (C) 2012  Internet Systems Consortium, Inc. ("ISC")
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

#ifndef DATASRC_ZONE_DATA_LOADER_H
#define DATASRC_ZONE_DATA_LOADER_H 1

#include <datasrc/exceptions.h>
#include <datasrc/memory/zone_data.h>
#include <datasrc/zone_iterator.h>
#include <dns/dns_fwd.h>
#include <util/memory_segment.h>

namespace bundy {
namespace datasrc {
class DataSourceClient;

namespace memory {

/// \brief Zone is invalid exception.
///
/// This is thrown if an invalid zone would be created during
/// \c loadZoneData().
struct ZoneValidationError : public ZoneLoaderException {
    ZoneValidationError(const char* file, size_t line, const char* what) :
        ZoneLoaderException(file, line, what)
    {}
};

/// \brief Utility class for loading/updating a zone from a given source.
///
/// Some of the methods are defined as virtual so that tests can mock the
/// behavior of class.  For other purposes this class shouldn't be derived.
class ZoneDataLoader {
protected:
    ZoneDataLoader() : impl_(NULL) {}

public:
    /// \brief Constructor for loading from a file.
    ///
    /// \param mem_sgmt The memory segment.
    /// \param rrclass The RRClass.
    /// \param zone_name The name of the zone that is being loaded.
    /// \param zone_file Filename which contains the zone data for \c zone_name.
    /// \param old_data If non-NULL, zone data currently being used.
    ZoneDataLoader(util::MemorySegment& mem_sgmt,
                   const dns::RRClass& rrclass,
                   const dns::Name& zone_name,
                   const std::string& zone_file,
                   ZoneData* old_data = NULL);

    /// \brief Constructor for loading from a given data source.
    ///
    /// Most of the parameters are the same as the other version.
    ///
    /// \param datasrc_client A client for the data source from which new
    /// zone data should be loaded.
    ZoneDataLoader(util::MemorySegment& mem_sgmt,
                   const dns::RRClass& rrclass,
                   const dns::Name& zone_name,
                   const DataSourceClient& datasrc_client,
                   ZoneData* old_data = NULL);

    /// Destructor.
    virtual ~ZoneDataLoader();

    /// \brief Create and return a ZoneData instance populated from the
    /// source passed on construction.
    ///
    /// \throw ZoneDataUpdater::AddError Invalid or inconsistent data found.
    /// \throw EmptyZone If an empty zone would be created
    /// \throw bundy::Unexpected An empty RRset is given from the source
    ///        (shouldn't happen, but possible for a buggy data source
    ///         implementation).
    ///
    /// \return A \c ZoneData containing zone data loaded from the source.
    virtual ZoneData* load();

private:
    class ZoneDataLoaderImpl;
    ZoneDataLoaderImpl* impl_;
};
} // namespace memory
} // namespace datasrc
} // namespace bundy

#endif // DATASRC_ZONE_DATA_LOADER_H

// Local Variables:
// mode: c++
// End:
