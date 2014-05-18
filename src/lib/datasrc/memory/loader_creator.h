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

#ifndef LOAD_ACTION_H
#define LOAD_ACTION_H

#include <boost/function.hpp>

namespace bundy {
// Forward declarations
namespace util{
class MemorySegment;
}
namespace datasrc {
namespace memory {
class ZoneData;
class ZoneDataLoader;

/// \brief A factory of ZoneDataLoader
///
/// This is called from the \c ZoneWriter whenever there's need to load the
/// zone data.  It creates a new \c ZoneDataLoader object, with which the
/// \c ZoneWriter can perform loading.  This factory object encapsulates
/// other detailed information for loading, such as the zone name and RR class,
/// and the source of the zone data.
///
/// All data should be allocated from the passed MemorySegment. The ownership
/// is passed onto the caller.
typedef boost::function<ZoneDataLoader*(util::MemorySegment& mem_sgmt,
                                        ZoneData* zone_data)>
ZoneDataLoaderCreator;
}
}
}

#endif
