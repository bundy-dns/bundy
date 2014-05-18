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

#include <datasrc/master_loader_callbacks.h>
#include <datasrc/memory/zone_data_loader.h>
#include <datasrc/memory/zone_data_updater.h>
#include <datasrc/memory/logger.h>
#include <datasrc/memory/segment_object_holder.h>
#include <datasrc/memory/util_internal.h>
#include <datasrc/memory/rrset_collection.h>
#include <datasrc/memory/treenode_rrset.h>
#include <datasrc/client.h>

#include <dns/labelsequence.h>
#include <dns/master_loader.h>
#include <dns/rrcollator.h>
#include <dns/rdataclass.h>
#include <dns/rrset.h>
#include <dns/zone_checker.h>

#include <boost/foreach.hpp>
#include <boost/bind.hpp>
#include <boost/optional.hpp>
#include <boost/noncopyable.hpp>

#include <map>

using namespace bundy::dns;
using namespace bundy::dns::rdata;

namespace bundy {
namespace datasrc {
namespace memory {

using detail::SegmentObjectHolder;
using detail::getCoveredType;

namespace { // unnamed namespace

// A helper internal class for \c ZoneDataLoader().  make it non-copyable
// to avoid accidental copy.
//
// The current internal implementation no longer expects that both a
// normal (non RRSIG) RRset and (when signed) its RRSIG are added at
// once, but we do that here anyway to avoid merging RdataSets every
// single time which can be inefficient.
//
// We hold all RRsets of the same owner name in node_rrsets_ and
// node_rrsigsets_, and add/remove the matching pairs of RRsets to the zone
// when we see a new owner name. We do this to limit the size of
// NodeRRsets below. However, RRsets can occur in any order.
//
// The caller is responsible for adding/removing the RRsets of the last group
// in the input sequence by explicitly calling flushNodeRRsets() at the
// end.  It's cleaner and more robust if we let the destructor of this class
// do it, but since we cannot guarantee the adding/removing operation is
// exception free, we don't choose that option to maintain the common
// expectation for destructors.
class ZoneDataUpdaterHelper : boost::noncopyable {
public:
    enum OP_MODE {ADD, DELETE};

    // A functor type used for loading.
    typedef boost::function<void(bundy::dns::ConstRRsetPtr, OP_MODE)>
    LoadCallback;

    ZoneDataUpdaterHelper(util::MemorySegment& mem_sgmt,
                         const bundy::dns::RRClass& rrclass,
                         const bundy::dns::Name& zone_name,
                         ZoneData& zone_data) :
        updater_(mem_sgmt, rrclass, zone_name, zone_data)
    {}

    void updateFromLoad(const bundy::dns::ConstRRsetPtr& rrset, OP_MODE mode);
    void flushNodeRRsets();

private:
    typedef std::map<bundy::dns::RRType, bundy::dns::ConstRRsetPtr> NodeRRsets;
    typedef NodeRRsets::value_type NodeRRsetsVal;

    // A helper to identify the covered type of an RRSIG.
    const bundy::dns::Name& getCurrentName() const;

private:
    NodeRRsets node_rrsets_;
    NodeRRsets node_rrsigsets_;
    std::vector<bundy::dns::ConstRRsetPtr> non_consecutive_rrsets_;
    ZoneDataUpdater updater_;
    boost::optional<OP_MODE> current_mode_;
};

void
ZoneDataUpdaterHelper::updateFromLoad(const ConstRRsetPtr& rrset, OP_MODE mode)
{
    // Set current mode.  If the mode is changing, we first need to flush all
    // changes in the previous mode.
    if (current_mode_ && *current_mode_ != mode) {
        flushNodeRRsets();
    }
    current_mode_ = mode;

    // If we see a new name, flush the temporary holders, adding or removing the
    // pairs of RRsets and RRSIGs of the previous name to the zone.
    if ((!node_rrsets_.empty() || !node_rrsigsets_.empty() ||
         !non_consecutive_rrsets_.empty()) &&
        (getCurrentName() != rrset->getName())) {
        flushNodeRRsets();
    }

    // Store this RRset until it can be added/removed in the zone. If an rrtype
    // that's already been seen is found, queue it in a different vector
    // to be merged later.
    const bool is_rrsig = rrset->getType() == RRType::RRSIG();
    NodeRRsets& node_rrsets = is_rrsig ? node_rrsigsets_ : node_rrsets_;
    const RRType& rrtype = is_rrsig ? getCoveredType(rrset) : rrset->getType();
    if (!node_rrsets.insert(NodeRRsetsVal(rrtype, rrset)).second) {
        non_consecutive_rrsets_.insert(non_consecutive_rrsets_.begin(), rrset);
    }

    if (rrset->getRRsig()) {
        updateFromLoad(rrset->getRRsig(), mode);
    }
}

void
ZoneDataUpdaterHelper::flushNodeRRsets() {
    // There has been no add or remove operation.  Then flush is no-op too.
    if (!current_mode_) {
        return;
    }

    boost::function<void(const ConstRRsetPtr&, const ConstRRsetPtr&)> op =
        (*current_mode_ == ADD) ?
        boost::bind(&ZoneDataUpdater::add, &updater_, _1, _2) :
        boost::bind(&ZoneDataUpdater::remove, &updater_, _1, _2);

    BOOST_FOREACH(NodeRRsetsVal val, node_rrsets_) {
        // Identify the corresponding RRSIG for the RRset, if any.  If
        // found add/remove both the RRset and its RRSIG at once.
        ConstRRsetPtr sig_rrset;
        NodeRRsets::iterator sig_it = node_rrsigsets_.find(val.first);
        if (sig_it != node_rrsigsets_.end()) {
            sig_rrset = sig_it->second;
            node_rrsigsets_.erase(sig_it);
        }
        op(val.second, sig_rrset);
    }

    // Normally rrsigsets map should be empty at this point, but it's still
    // possible that an RRSIG that doesn't have covered RRset is added/removed;
    // they still remain in the map.  We add/remove them to the zone separately.
    BOOST_FOREACH(NodeRRsetsVal val, node_rrsigsets_) {
        op(ConstRRsetPtr(), val.second);
    }

    // Add/remove any non-consecutive rrsets too.
    BOOST_FOREACH(ConstRRsetPtr rrset, non_consecutive_rrsets_) {
        if (rrset->getType() == RRType::RRSIG()) {
            op(ConstRRsetPtr(), rrset);
        } else {
            op(rrset, ConstRRsetPtr());
        }
    }

    node_rrsets_.clear();
    node_rrsigsets_.clear();
    non_consecutive_rrsets_.clear();
}

const Name&
ZoneDataUpdaterHelper::getCurrentName() const {
    if (!node_rrsets_.empty()) {
        return (node_rrsets_.begin()->second->getName());
    }
    assert(!node_rrsigsets_.empty());
    return (node_rrsigsets_.begin()->second->getName());
}

void
logWarning(const dns::Name* zone_name, const dns::RRClass* rrclass,
           const std::string& reason)
{
    LOG_WARN(logger, DATASRC_MEMORY_CHECK_WARNING).arg(*zone_name).
        arg(*rrclass).arg(reason);
}

void
logError(const dns::Name* zone_name, const dns::RRClass* rrclass,
         const std::string& reason)
{
    LOG_ERROR(logger, DATASRC_MEMORY_CHECK_ERROR).arg(*zone_name).arg(*rrclass).
        arg(reason);
}

boost::optional<dns::Serial>
getSerialFromRRset(const dns::AbstractRRset& rrset) {
    if (rrset.getRdataCount() != 1) {
        // This is basically a bug of the data source implementation, but we
        // should at least crash ourselves.
        bundy_throw(Unexpected,
                    "broken SOA RRset is given to zone data loader: " <<
                    rrset.getRdataCount() << " RDATAs (should be 1)");
    }
    dns::RdataIteratorPtr rdit = rrset.getRdataIterator();
    const dns::rdata::generic::SOA& soa =
        dynamic_cast<const dns::rdata::generic::SOA&>(rdit->getCurrent());
    return (soa.getSerial());
}

boost::optional<dns::Serial>
getSerialFromZoneData(RRClass rrclass, ZoneData* zone_data) {
    if (zone_data) {
        const ZoneNode* origin_node = zone_data->getOriginNode();
        const RdataSet* rdataset = origin_node->getData();
        rdataset = RdataSet::find(rdataset, RRType::SOA());
        if (rdataset) {
            return (getSerialFromRRset(
                        TreeNodeRRset(rrclass, origin_node, rdataset, false)));
        }
    }
    return (boost::optional<dns::Serial>());
}

void
validateOldData(const Name& origin, ZoneData* old_data) {
    if (!old_data) {  // need validation only when old data are given.
        return;
    }

    uint8_t buf[LabelSequence::MAX_SERIALIZED_LENGTH];
    const LabelSequence old_name =
        old_data->getOriginNode()->getAbsoluteLabels(buf);
    if (!(old_name == LabelSequence(origin))) {
        bundy_throw(BadValue, "zone data loader is given bad old data: "
                    "origin=" << old_name << ", expecting " << origin);
    }
}
} // end of unnamed namespace

class ZoneDataLoader::ZoneDataLoaderImpl {
public:
    virtual ~ZoneDataLoaderImpl() {}
    ZoneDataLoaderImpl(util::MemorySegment& mem_sgmt,
                       const dns::RRClass& rrclass,
                       const dns::Name& zone_name,
                       ZoneData* old_data,
                       const boost::optional<dns::Serial>& old_serial) :
        mem_sgmt_(mem_sgmt), rrclass_(rrclass), zone_name_(zone_name),
        old_data_(old_data), old_serial_(old_serial), loaded_data_(NULL)
    {
        validateOldData(zone_name, old_data);
    }

    virtual bool doLoad(size_t count_limit) {
        initUpdate(NULL);
        const bool completed = doLoadCommon(count_limit);
        if (completed) {
            finishUpdate();
        }
        return (completed);
    }

    virtual ZoneData* commitDiffs(ZoneData* update_data) {
        return (update_data);
    }

    virtual bool isDataReused() const = 0;

    ZoneData* getLoadedData() const {
        return (loaded_data_);
    }

protected:
    bool doLoadCommon(size_t count_limit);

    virtual void initUpdate(ZoneData* const zone_data) {
        if (data_holder_) {
            return;             // nothing to do, already initialized
        }
        while (true) {
            try {
                boost::scoped_ptr<SegmentObjectHolder<ZoneData, RRClass> >
                    holder(new SegmentObjectHolder<ZoneData, RRClass>
                           (mem_sgmt_, rrclass_));
                if (zone_data) {
                    holder->set(zone_data);
                } else {
                    holder->set(ZoneData::create(mem_sgmt_, zone_name_));
                }
                data_holder_.swap(holder);
                break;
            } catch (const util::MemorySegmentGrown&) {
                // If we are using existing zone data, this exception must be
                // handled at a higher level that holds the ownership of the
                // original data.  Otherwise, try as long as it takes to load
                // and grow the segment.
                if (zone_data) {
                    throw;
                }
            }
        }
        update_helper_.reset(new ZoneDataUpdaterHelper(mem_sgmt_, rrclass_,
                                                       zone_name_,
                                                       *data_holder_->get()));
    }

    void finishUpdate();

    virtual bool updateRRsets(size_t count_limit) = 0;

protected:
    util::MemorySegment& mem_sgmt_;
    const dns::RRClass rrclass_;
    const dns::Name zone_name_;
    ZoneData* const old_data_;
    const boost::optional<dns::Serial> old_serial_;
    boost::scoped_ptr<SegmentObjectHolder<ZoneData, RRClass> > data_holder_;
    boost::scoped_ptr<ZoneDataUpdaterHelper> update_helper_;
    ZoneData* loaded_data_;
};

void
ZoneDataLoader::ZoneDataLoaderImpl::finishUpdate() {
    const ZoneNode* origin_node = data_holder_->get()->getOriginNode();
    const RdataSet* rdataset = origin_node->getData();
    ZoneData* const loaded_data = data_holder_->get();
    // If the zone is and NSEC3-signed, check if it has NSEC3PARAM.
    // If not, it may either just go to NSEC3-unsigned, or there's an
    // operational error in that step, depending on whether there's any
    // NSEC3 RRs in the zone.
    if (loaded_data->isNSEC3Signed() &&
        RdataSet::find(rdataset, RRType::NSEC3PARAM()) == NULL) {
        if (loaded_data->getNSEC3Data()->isEmpty()) {
            // becoming NSEC3-unsigned.
            LOG_INFO(logger, DATASRC_MEMORY_MEM_NSEC3_UNSIGNED).arg(zone_name_).
                arg(rrclass_);
            NSEC3Data* old_n3data = loaded_data->setNSEC3Data(NULL);
            NSEC3Data::destroy(mem_sgmt_, old_n3data, rrclass_);
        } else {
            LOG_WARN(logger, DATASRC_MEMORY_MEM_NO_NSEC3PARAM).arg(zone_name_).
                arg(rrclass_);
        }
    }

    RRsetCollection collection(*loaded_data, rrclass_);
    const dns::ZoneCheckerCallbacks
        callbacks(boost::bind(&logError, &zone_name_, &rrclass_, _1),
                  boost::bind(&logWarning, &zone_name_, &rrclass_, _1));
    if (!dns::checkZone(zone_name_, rrclass_, collection, callbacks)) {
        bundy_throw(ZoneValidationError, "Errors found when validating zone: "
                    << zone_name_ << "/" << rrclass_);
    }

    // Check loaded serial.  Note that if checkZone() passed, we
    // should have SOA in the ZoneData.
    const dns::Serial new_serial =
        *getSerialFromZoneData(rrclass_, loaded_data);
    if (old_serial_ && *old_serial_ >= new_serial) {
        LOG_WARN(logger, DATASRC_MEMORY_LOADED_SERIAL_NOT_INCREASED).
            arg(zone_name_).arg(rrclass_).
            arg(old_serial_->getValue()).arg(new_serial.getValue());
    }
    LOG_DEBUG(logger, DBG_TRACE_BASIC, DATASRC_MEMORY_LOADED).
        arg(zone_name_).arg(rrclass_).arg(new_serial.getValue()).
        arg(loaded_data->isSigned() ? " (DNSSEC signed)" : "");

    loaded_data_ = data_holder_->release();
}

bool
ZoneDataLoader::ZoneDataLoaderImpl::doLoadCommon(const size_t count_limit) {
    // if the count is unlimited (0), use an arbitrarily large number for
    // the temporary limit.
    const size_t update_count_limit = count_limit == 0 ? 100000 : count_limit;
    try {
        bool completed = false;
        do {
            completed = updateRRsets(update_count_limit);
        } while (!completed && count_limit == 0);
        // Add any last RRsets that were left
        update_helper_->flushNodeRRsets();
        if (completed) {
            // we're done with the updater.  Release internal resources sooner.
            update_helper_.reset();
        }
        return (completed);
    } catch (const util::MemorySegmentGrown&) {
        // Nothing after creating the data holder should throw
        // MemorySegmentGrown.  We make it sure here.
        assert(false);
    }
}

namespace {
class MasterFileLoader : public ZoneDataLoader::ZoneDataLoaderImpl {
public:
    MasterFileLoader(util::MemorySegment& mem_sgmt, const dns::RRClass& rrclass,
                     const dns::Name& zone_name, const std::string& zone_file,
                     ZoneData* old_data) :
        ZoneDataLoader::ZoneDataLoaderImpl(mem_sgmt, rrclass, zone_name,
                                           old_data,
                                           boost::optional<dns::Serial>()),
        zone_file_(zone_file)
    {}
    virtual ~MasterFileLoader() {}
    virtual bool isDataReused() const { return (false); }

protected:
    virtual void initUpdate(ZoneData* const zone_data) {
        if (master_loader_) {
            return;             // already initialized
        }

        // perform common initialization, and create MasterLoader (we need to
        // hold off creating it until this point since we need update_helper_).
        ZoneDataLoader::ZoneDataLoaderImpl::initUpdate(zone_data);

        // Below, we convert the two callback types.  Note the mostly redundant
        // wrapper of boost::bind.  It converts function<void(ConstRRsetPtr)>
        // to function<void(RRsetPtr)> (MasterLoader expects the latter).
        // SunStudio doesn't seem to do this conversion if we just pass a
        // combined boost::bind object.
        ZoneDataUpdaterHelper::LoadCallback update_helper_callback =
            boost::bind(&ZoneDataUpdaterHelper::updateFromLoad,
                        update_helper_.get(), _1, _2);
        rrcollator_.reset(
            new dns::RRCollator(boost::bind(update_helper_callback, _1,
                                            ZoneDataUpdaterHelper::ADD)));
        master_loader_.reset(
            new dns::MasterLoader(zone_file_.c_str(), zone_name_, rrclass_,
                                  createMasterLoaderCallbacks(zone_name_,
                                                              rrclass_,
                                                              &load_ok_),
                                  rrcollator_->getCallback()));
    }

    virtual bool updateRRsets(size_t count_limit) {
        try {
            if (!master_loader_->loadIncremental(count_limit)) {
                return (false);
            }
            rrcollator_->flush();
        } catch (const dns::MasterLoaderError& e) {
            bundy_throw(ZoneLoaderException, e.what());
        }
        return (true);
    }

private:
    bool load_ok_; // we actually don't use it; only need a placeholder
    const std::string zone_file_;
    boost::scoped_ptr<dns::RRCollator> rrcollator_;
    boost::scoped_ptr<dns::MasterLoader> master_loader_;
};

class IteratorLoader : public ZoneDataLoader::ZoneDataLoaderImpl {
public:
    IteratorLoader(util::MemorySegment& mem_sgmt, const dns::RRClass& rrclass,
                   const dns::Name& zone_name, ZoneIteratorPtr iterator,
                   ZoneData* old_data,
                   const boost::optional<dns::Serial>& old_serial) :
        ZoneDataLoader::ZoneDataLoaderImpl(mem_sgmt, rrclass, zone_name,
                                           old_data, old_serial),
        iterator_(iterator)
    {}
    virtual ~IteratorLoader() {}
    virtual bool isDataReused() const { return (false); }

protected:
    // The installer called for ZoneDataLoader using a zone iterator
    virtual bool updateRRsets(size_t count_limit) {
        size_t count = 0;
        ConstRRsetPtr rrset;
        while (count < count_limit &&
               (rrset = iterator_->getNextRRset()) != NULL) {
            update_helper_->updateFromLoad(rrset, ZoneDataUpdaterHelper::ADD);
            count++;
        }
        return (!rrset);   // we are done iff we reach end of the iterator
    }
private:
    ZoneIteratorPtr iterator_;
};

class ReuseLoader : public ZoneDataLoader::ZoneDataLoaderImpl {
public:
    ReuseLoader(util::MemorySegment& mem_sgmt,
                const dns::RRClass& rrclass, const dns::Name& zone_name,
                ZoneData* old_data,
                const boost::optional<dns::Serial>& old_serial,
                const std::string& dsrc_name) :
        ZoneDataLoader::ZoneDataLoaderImpl(mem_sgmt, rrclass, zone_name,
                                           old_data, old_serial)
    {
        LOG_DEBUG(logger, DBG_TRACE_BASIC, DATASRC_MEMORY_LOAD_SAME_SERIAL).
            arg(zone_name).arg(rrclass).arg(old_serial->getValue()).
            arg(dsrc_name);
    }
    virtual ~ReuseLoader() {}
    virtual bool doLoad(size_t) {
        loaded_data_ = old_data_;
        return (true);
    }
    virtual bool isDataReused() const { return (true); }
protected:
    virtual bool updateRRsets(size_t) {
        assert(false);          // this version shouldn't be called
    }
};

class JournalLoader : public ZoneDataLoader::ZoneDataLoaderImpl {
public:
    JournalLoader(util::MemorySegment& mem_sgmt,
                  const dns::RRClass& rrclass, const dns::Name& zone_name,
                  ZoneData* old_data,
                  const boost::optional<dns::Serial>& old_serial,
                  const dns::Serial& new_serial,
                  const DataSourceClient& datasrc_client) :
        ZoneDataLoader::ZoneDataLoaderImpl(mem_sgmt, rrclass, zone_name,
                                           old_data, old_serial)
    {
        const std::pair<ZoneJournalReader::Result, ZoneJournalReaderPtr>
            result = datasrc_client.getJournalReader(
                zone_name, old_serial->getValue(), new_serial.getValue());
        jnl_reader_ = result.second;
        if (jnl_reader_) {
            LOG_DEBUG(logger, DBG_TRACE_BASIC, DATASRC_MEMORY_LOAD_USE_JOURNAL).
                arg(zone_name_).arg(rrclass_).arg(old_serial->getValue()).
                arg(new_serial.getValue()).
                arg(datasrc_client.getDataSourceName());
        }
    }
    virtual ~JournalLoader() {}
    virtual bool isDataReused() const { return (true); }
    virtual bool doLoad(size_t) {
        saveDiffs();
        loaded_data_ = old_data_;
        return (true);
    }
    virtual ZoneData* commitDiffs(ZoneData* update_data) {
        // Constructing SegmentObjectHolder can result in MemorySegmentGrown.
        // This needs to be handled at the caller as update_data could now be
        // invalid.  But before propagating the exception, we should release the
        // data because the caller has the ownership and we shouldn't destroy
        // it.
        initUpdate(update_data);
        try {
            // On success, finishUpdate release the zone data in the holder.
            doLoadCommon(0);    // must return true
            finishUpdate();
            return (getLoadedData());
        } catch (...) {
            data_holder_->release();
            throw;
        }
    }

protected:
    // The installer called for ZoneDataLoader using a zone journal reader.
    // It performs some minimal sanity checks on the sequence of data, but
    // the basic assumption is that any invalid data mean implementation defect
    // (not bad user input) and shouldn't happen anyway.
    virtual bool updateRRsets(size_t) {
        enum DIFF_MODE {INIT, ADD, DELETE} mode = INIT;
        ConstRRsetPtr rrset;
        std::vector<ConstRRsetPtr>::const_iterator it = saved_diffs_.begin();
        const std::vector<ConstRRsetPtr>::const_iterator it_end =
            saved_diffs_.end();
        while ((rrset = nextDiff(it, it_end))) {
            if (rrset->getType() == RRType::SOA()) {
                mode = (mode == INIT || mode == ADD) ? DELETE : ADD;
            } else if (mode == INIT) {
                // diff sequence doesn't begin with SOA. It means broken journal
                // reader implementation.
                bundy_throw(bundy::Unexpected,
                            "broken journal reader: diff not begin with SOA");
            }
            update_helper_->updateFromLoad(rrset,
                                           (mode == ADD) ?
                                           ZoneDataUpdaterHelper::ADD :
                                           ZoneDataUpdaterHelper::DELETE);
        }
        if (mode != ADD) {
            // Diff must end in the add mode (there should at least be one
            // add for the final SOA)
            bundy_throw(bundy::Unexpected, "broken journal reader: incomplete");
        }

        return (true);
    }

private:
    void saveDiffs() {
        int count = 0;
        ConstRRsetPtr rrset;
        while (count++ < MAX_SAVED_DIFFS_ &&
               (rrset = jnl_reader_->getNextDiff())) {
            saved_diffs_.push_back(rrset);
        }
        if (!rrset) {
            jnl_reader_.reset();
            if (saved_diffs_.empty()) {
                // In our expected form of diff sequence, it shouldn't be empty,
                // since there should be at least begin and end SOAs.
                // Eliminating this case at this point makes the later
                // processing easier.
                bundy_throw(ZoneValidationError,
                            "empty diff sequence is provided for load");
            }
        }
    }

    ConstRRsetPtr
    nextDiff(std::vector<ConstRRsetPtr>::const_iterator& it,
             const std::vector<ConstRRsetPtr>::const_iterator& it_end)
    {
        ConstRRsetPtr next_diff;    // null by default
        if (it != it_end) {
            next_diff = *it;
            ++it;
        } else if (jnl_reader_) {
            next_diff = jnl_reader_->getNextDiff();
        }
        return (next_diff);
    }

    ZoneJournalReaderPtr jnl_reader_;

    // To minimize the risk of hitting an exception from the journal reader
    // in commitDiffs(), we save up to MAX_SAVED_DIFFS_ diff RRs in the
    // load() phase.  While it doesn't guarantee a success in commitDiffs()
    // (if it fails we fall back to invalidate the zone and reload the entire
    // zone), this should work for many cases with small updates (like in
    // dynamic updates).
    static const unsigned int MAX_SAVED_DIFFS_ = 100;
    std::vector<ConstRRsetPtr> saved_diffs_;
};
}

ZoneDataLoader::ZoneDataLoader(util::MemorySegment& mem_sgmt,
                               const dns::RRClass& rrclass,
                               const dns::Name& zone_name,
                               const std::string& zone_file,
                               ZoneData* old_data) :
    impl_(NULL)                 // defer until logging to avoid leak
{
    LOG_DEBUG(logger, DBG_TRACE_BASIC, DATASRC_MEMORY_MEM_LOAD_FROM_FILE).
        arg(zone_name).arg(rrclass).arg(zone_file);

    impl_ = new MasterFileLoader(mem_sgmt, rrclass, zone_name, zone_file,
                                 old_data);
}

ZoneDataLoader::ZoneDataLoader(util::MemorySegment& mem_sgmt,
                               const dns::RRClass& rrclass,
                               const dns::Name& zone_name,
                               const DataSourceClient& datasrc_client,
                               ZoneData* old_data) :
    impl_(NULL)
{
    const std::string& dsrc_name = datasrc_client.getDataSourceName();
    LOG_DEBUG(logger, DBG_TRACE_BASIC, DATASRC_MEMORY_MEM_LOAD_FROM_DATASRC).
        arg(zone_name).arg(rrclass).arg(dsrc_name);

    ZoneIteratorPtr iterator = datasrc_client.getIterator(zone_name);
    if (!iterator) {
        // This shouldn't happen for a compliant implementation of
        // DataSourceClient, but we'll protect ourselves from buggy
        // implementations.
        bundy_throw(Unexpected, "getting loader creator for " << zone_name
                    << "/" << rrclass << " resulted in Null zone iterator");
    }

    const dns::ConstRRsetPtr new_soarrset = iterator->getSOA();
    if (!new_soarrset) {
        // If the source data source doesn't contain SOA, post-load check
        // will fail anyway, so rejecting loading at this point makes sense.
        bundy_throw(ZoneValidationError, "No SOA found for "
                    << zone_name << "/" << rrclass << "in " << dsrc_name);
    }
    const boost::optional<dns::Serial> old_serial =
        getSerialFromZoneData(rrclass, old_data);
    const boost::optional<dns::Serial> new_serial =
        getSerialFromRRset(*new_soarrset);
    if (old_serial && (*old_serial == *new_serial)) {
        impl_ = new ReuseLoader(mem_sgmt, rrclass, zone_name, old_data,
                                old_serial, dsrc_name);
        return;
    } else if (old_serial && (*old_serial < *new_serial)) {
        try {
            impl_ = new JournalLoader(mem_sgmt, rrclass, zone_name, old_data,
                                      old_serial, *new_serial, datasrc_client);
            return;
        } catch (const bundy::NotImplemented&) {
            // handle this case just like no journal is available for the
            // serials.
        }
    }
    impl_ = new IteratorLoader(mem_sgmt, rrclass, zone_name, iterator,
                               old_data, old_serial);
}

ZoneDataLoader::~ZoneDataLoader() {
    delete impl_;
}

bool
ZoneDataLoader::isDataReused() const {
    return (impl_->isDataReused());
}

bool
ZoneDataLoader::loadIncremental(size_t count_limit) {
    return (impl_->doLoad(count_limit));
}

ZoneData*
ZoneDataLoader::load() {
    const bool completed = loadIncremental(0);
    assert(completed);
    return (getLoadedData());
}

ZoneData*
ZoneDataLoader::getLoadedData() const {
    return (impl_->getLoadedData());
}

ZoneData*
ZoneDataLoader::commit(ZoneData* update_data) {
    return (impl_->commitDiffs(update_data));
}

} // namespace memory
} // namespace datasrc
} // namespace bundy
