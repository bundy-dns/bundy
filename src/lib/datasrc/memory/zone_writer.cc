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

#include <datasrc/memory/logger.h>
#include <datasrc/memory/zone_writer.h>
#include <datasrc/memory/zone_data.h>
#include <datasrc/memory/zone_data_loader.h>
#include <datasrc/memory/zone_table_segment.h>
#include <datasrc/memory/segment_object_holder.h>

#include <boost/scoped_ptr.hpp>

#include <dns/rrclass.h>

#include <datasrc/exceptions.h>

#include <memory>
#include <stdexcept>

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

    void installToTable();
    void installFailed(const std::exception* ex);

    ZoneTableSegment& segment_;
    const ZoneDataLoaderCreator loader_creator_;
    const dns::Name origin_;
    const dns::RRClass rrclass_;
    enum State {
        ZW_UNUSED,
        ZW_LOADING,
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

bool
ZoneWriter::load(size_t count_limit, std::string* error_msg) {
    if (impl_->state_ != Impl::ZW_UNUSED && impl_->state_ != Impl::ZW_LOADING) {
        bundy_throw(bundy::InvalidOperation, "Trying to load twice");
    }

    try {
        // If this is the first call, initialize some stuff.
        if (!impl_->loader_) {
            ZoneTable* const table = getZoneTable(impl_->segment_);
            const ZoneTable::MutableFindResult ztresult =
                table->findZone(impl_->origin_);
            ZoneData* const old_data =
                (ztresult.code == result::SUCCESS) ? ztresult.zone_data : NULL;
            impl_->loader_.reset(impl_->loader_creator_(
                                     impl_->segment_.getMemorySegment(),
                                     old_data));
            impl_->state_ = Impl::ZW_LOADING;
        }
        impl_->destroy_old_data_ = !impl_->loader_->isDataReused();
        const bool completed = impl_->loader_->loadIncremental(count_limit);
        if (!completed) {
            return (false);
        }
        ZoneData* const zone_data = impl_->loader_->getLoadedData();

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
    return (true);
}

// This is called when ZoneDataLoader::commit() fails in install() other
// than due to MemorySegmentGrown.  Based on our assumption that the
// application should have validated zone data before this stage, and since
// the current zone data may have been modified and are mostly impossible to
// recover from that anyway, we'll only try to make it fail as cleanly as
// possible.  First, resetting the data to NULL will make the now-invalid zone
// unusable.  In this context, installToTable() should succeed without an
// exception, so it should be safe until at that point.  We'll also try to
// leave a log message as it's extremely unexpected.  This attempt could
// result in further exception in a very unlucky and rare case, in which case
// we'll simply let the process die.
void
ZoneWriter::Impl::installFailed(const std::exception* ex) {
    data_holder_->set(NULL);
    destroy_old_data_ = true;
    installToTable();
    LOG_ERROR(logger, DATASRC_MEMORY_MEM_LOAD_UNEXPECTED_ERROR).
        arg(origin_).arg(rrclass_).arg(ex ? ex->what() : "(unknown)");
}

// A commonly used subroutine of install(), installing the final zone data
// to the zone table.
void
ZoneWriter::Impl::installToTable() {
    while (state_ != Impl::ZW_INSTALLED) {
        try {
            ZoneTable* const table = getZoneTable(segment_);
            // We still need to hold the zone data until we return from
            // addZone in case it throws, but we then need to immediately
            // release it as the ownership is transferred to the zone table.
            // In case we are also to destroy old data, we release the new
            // data by (re)setting it to the old; that way we can use the
            // holder for the final cleanup.
            const ZoneTable::AddResult result(
                data_holder_->get() ?
                table->addZone(segment_.getMemorySegment(),
                               origin_, data_holder_->get()) :
                table->addEmptyZone(segment_.getMemorySegment(), origin_));
            if (destroy_old_data_) {
                data_holder_->set(result.zone_data);
            } else {
                data_holder_->release();
            }
            state_ = Impl::ZW_INSTALLED;
        } catch (const bundy::util::MemorySegmentGrown&) {}
    }
}

void
ZoneWriter::install() {
    if (impl_->state_ != Impl::ZW_LOADED) {
        bundy_throw(bundy::InvalidOperation, "No data to install");
    }

    // Check the internal integrity assumption: we should have non NULL
    // zone data or we've allowed load error to create an empty zone.
    assert(impl_->data_holder_.get() || impl_->catch_load_error_);

    while (true) {
        try {
            // Let the loader do any final work.  commit() can throw
            // MemorySegmentGrown, so we need another while-try-catch here.
            ZoneData* zone_data = impl_->data_holder_->get();
            if (zone_data) {
                zone_data = impl_->loader_->commit(impl_->data_holder_->get());
                assert(zone_data);  // API ensures this
            }
            impl_->data_holder_->set(zone_data);
            impl_->installToTable();
            break;
        } catch (const bundy::util::MemorySegmentGrown&) {
            ;                   // just retry with the grown segment
        } catch (const bundy::Exception& ex) {
            // In this case, this is most likely a bug of other module (feeding
            // a bad diff sequence), so it's probably better to proceed, just
            // invalidating the zone.
            impl_->installFailed(&ex);
            break;
        } catch (const std::exception& ex) {
            // Other exceptions are really unexpected, and we should probably
            // let the process die.  But we'll try to make one final cleanup
            // (making the zone bad) before that.
            impl_->installFailed(&ex);
            throw;
        } catch (...) {
            impl_->installFailed(NULL);
            throw;
        }
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
