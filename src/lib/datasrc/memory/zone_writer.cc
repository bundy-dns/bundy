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

#include <datasrc/memory/zone_writer.h>
#include <datasrc/memory/zone_data.h>
#include <datasrc/memory/zone_data_loader.h>
#include <datasrc/memory/zone_table_segment.h>
#include <datasrc/memory/segment_object_holder.h>

#include <boost/scoped_ptr.hpp>

#include <dns/rrclass.h>

#include <datasrc/exceptions.h>

#include <memory>

using std::auto_ptr;

namespace bundy {
namespace datasrc {
namespace memory {

ZoneTableSegment&
checkZoneTableSegment(ZoneTableSegment& segment) {
    if (!segment.isWritable()) {
        bundy_throw(bundy::InvalidOperation,
                  "Attempt to construct ZoneWriter for a read-only segment");
    }
    return (segment);
}

struct ZoneWriter::Impl {
    Impl(ZoneTableSegment& segment,
         const ZoneDataLoaderCreator & loader_creator,
         const dns::Name& origin, const dns::RRClass& rrclass,
         bool throw_on_load_error) :
        // We validate segment first so we can use it to initialize
        // data_holder_ safely.
        segment_(checkZoneTableSegment(segment)),
        loader_creator_(loader_creator),
        origin_(origin),
        rrclass_(rrclass),
        state_(ZW_UNUSED),
        catch_load_error_(throw_on_load_error),
        destroy_old_data_(true)
    {
        while (true) {
            try {
                data_holder_.reset(
                    new ZoneDataHolder(segment.getMemorySegment(), rrclass_));
                break;
            } catch (const bundy::util::MemorySegmentGrown&) {}
        }
    }

    ZoneTableSegment& segment_;
    const ZoneDataLoaderCreator loader_creator_;
    const dns::Name origin_;
    const dns::RRClass rrclass_;
    enum State {
        ZW_UNUSED,
        ZW_LOADED,
        ZW_INSTALLED,
        ZW_CLEANED
    };
    State state_;
    const bool catch_load_error_;
    typedef detail::SegmentObjectHolder<ZoneData, dns::RRClass> ZoneDataHolder;
    boost::scoped_ptr<ZoneDataHolder> data_holder_;
    boost::scoped_ptr<ZoneDataLoader> loader_;
    bool destroy_old_data_;
};

ZoneWriter::ZoneWriter(ZoneTableSegment& segment,
                       const ZoneDataLoaderCreator& loader_creator,
                       const dns::Name& origin,
                       const dns::RRClass& rrclass,
                       bool throw_on_load_error) :
    impl_(new Impl(segment, loader_creator, origin, rrclass,
                   throw_on_load_error))
{
}

ZoneWriter::~ZoneWriter() {
    // Clean up everything there might be left if someone forgot, just
    // in case.
    cleanup();
    delete impl_;
}

namespace {
ZoneTable*
getZoneTable(ZoneTableSegment& table_sgmt) {
    ZoneTable* const table = table_sgmt.getHeader().getTable();
    if (!table) {
        // This can only happen for buggy ZoneTableSegment implementation.
        bundy_throw(bundy::Unexpected, "No zone table present");
    }
    return (table);
}
}

void
ZoneWriter::load(std::string* error_msg) {
    if (impl_->state_ != Impl::ZW_UNUSED) {
        bundy_throw(bundy::InvalidOperation, "Trying to load twice");
    }

    ZoneTable* const table = getZoneTable(impl_->segment_);
    const ZoneTable::MutableFindResult ztresult =
        table->findZone(impl_->origin_);
    ZoneData* const old_data =
        (ztresult.code == result::SUCCESS) ? ztresult.zone_data : NULL;

    try {
        impl_->loader_.reset(impl_->loader_creator_(
                                 impl_->segment_.getMemorySegment(), old_data));
        const ZoneDataLoader::LoadResult result = impl_->loader_->load();
        ZoneData* const zone_data = result.first;
        impl_->destroy_old_data_ = result.second;

        if (!zone_data) {
            // Bug inside ZoneDataLoader.
            bundy_throw(bundy::InvalidOperation,
                        "No data returned from load action");
        }

        impl_->data_holder_->set(zone_data);
    } catch (const ZoneLoaderException& ex) {
        if (!impl_->catch_load_error_) {
            throw;
        }
        if (error_msg) {
            *error_msg = ex.what();
        }
    }

    impl_->state_ = Impl::ZW_LOADED;
}

void
ZoneWriter::install() {
    if (impl_->state_ != Impl::ZW_LOADED) {
        bundy_throw(bundy::InvalidOperation, "No data to install");
    }

    // Check the internal integrity assumption: we should have non NULL
    // zone data or we've allowed load error to create an empty zone.
    assert(impl_->data_holder_.get() || impl_->catch_load_error_);

    while (impl_->state_ != Impl::ZW_INSTALLED) {
        try {
            ZoneTable* const table = getZoneTable(impl_->segment_);
            // We still need to hold the zone data until we return from
            // addZone in case it throws, but we then need to immediately
            // release it as the ownership is transferred to the zone table.
            // In case we are also to destroy old data, we release the new
            // data by (re)setting it to the old; that way we can use the
            // holder for the final cleanup.
            const ZoneTable::AddResult result(
                impl_->data_holder_->get() ?
                table->addZone(impl_->segment_.getMemorySegment(),
                               impl_->origin_, impl_->data_holder_->get()) :
                table->addEmptyZone(impl_->segment_.getMemorySegment(),
                                    impl_->origin_));
            if (impl_->destroy_old_data_) {
                impl_->data_holder_->set(result.zone_data);
            } else {
                impl_->data_holder_->release();
            }
            impl_->state_ = Impl::ZW_INSTALLED;
        } catch (const bundy::util::MemorySegmentGrown&) {}
    }
}

void
ZoneWriter::cleanup() {
    // We eat the data (if any) now.

    ZoneData* zone_data = impl_->data_holder_->release();
    if (zone_data) {
        ZoneData::destroy(impl_->segment_.getMemorySegment(), zone_data,
                          impl_->rrclass_);
        impl_->state_ = Impl::ZW_CLEANED;
    }
}

}
}
}
