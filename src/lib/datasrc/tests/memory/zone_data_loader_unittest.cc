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

#include <config.h>

#include <datasrc/memory/zone_data_loader.h>
#include <datasrc/memory/rdataset.h>
#include <datasrc/memory/zone_data.h>
#include <datasrc/memory/zone_data_updater.h>
#include <datasrc/memory/segment_object_holder.h>
#include <datasrc/client.h>
#include <datasrc/zone_iterator.h>

#include <exceptions/exceptions.h>

#include <util/buffer.h>

#include <dns/name.h>
#include <dns/rrclass.h>
#include <dns/rdataclass.h>
#include <dns/rrset.h>
#ifdef USE_SHARED_MEMORY
#include <util/memory_segment_mapped.h>
#endif
#include <util/memory_segment_local.h>

#include <datasrc/tests/memory/memory_segment_mock.h>

#include <gtest/gtest.h>

#include <vector>

using namespace bundy::dns;
using namespace bundy::datasrc;
using namespace bundy::datasrc::memory;
#ifdef USE_SHARED_MEMORY
using bundy::util::MemorySegmentMapped;
#endif
using bundy::datasrc::memory::detail::SegmentObjectHolder;

namespace {

class MockIterator : public ZoneIterator {
public:
    MockIterator(const Name& zone_name, uint32_t serial,
                 bool use_null_soa, bool use_broken_soa, bool nsec3) :
        soa_(new RRset(zone_name, RRClass::IN(), RRType::SOA(), RRTTL(3600)))
    {
        soa_->addRdata(rdata::generic::SOA(zone_name, zone_name, serial,
                                           3600, 3600, 3600, 3600));
        rrsets_.push_back(soa_);
        const RRsetPtr ns(new RRset(zone_name, RRClass::IN(), RRType::NS(),
                                    RRTTL(3600)));
        ns->addRdata(rdata::generic::NS(Name("ns.example")));
        rrsets_.push_back(ns);
        if (nsec3) { // making NSEC3-signed zone.  adding NSEC3PARAM is enough.
            const RRsetPtr nsec3p(new RRset(zone_name, RRClass::IN(),
                                            RRType::NSEC3PARAM(), RRTTL(3600)));
            nsec3p->addRdata(rdata::generic::NSEC3PARAM("1 1 1 D399EAAB"));
            rrsets_.push_back(nsec3p);
        }
        rrsets_.push_back(ConstRRsetPtr());
        it_ = rrsets_.begin();

        if (use_null_soa) {
            soa_.reset();
        } else if (use_broken_soa) {
            EXPECT_FALSE(use_null_soa); // these two shouldn't coexist
            soa_.reset(new RRset(zone_name, RRClass::IN(), RRType::SOA(),
                                 RRTTL(3600))); // reset it to an empty RRset
        }
    }
    virtual ConstRRsetPtr getNextRRset() {
        const ConstRRsetPtr result = *it_;
        ++it_;       // should be safe as long as caller stops at NULL
        return (result);
    }
    virtual bundy::dns::ConstRRsetPtr getSOA() const {
        return (soa_);
    }
private:
    RRsetPtr soa_;
    std::vector<ConstRRsetPtr> rrsets_;
    std::vector<ConstRRsetPtr>::const_iterator it_;
};

class MockJournalReader : public ZoneJournalReader {
public:
    MockJournalReader(const Name& zone_name, uint32_t beg_serial,
                      uint32_t end_serial, bool broken, bool remove_nsec3)
    {
        EXPECT_TRUE(beg_serial < end_serial);

        RRsetPtr ns(new RRset(zone_name, RRClass::IN(), RRType::NS(),
                              RRTTL(3600)));
        ns->addRdata(rdata::generic::NS(Name("ns.example")));
        for (size_t s = beg_serial; s < end_serial; ++s) {
            RRsetPtr soa(new RRset(zone_name, RRClass::IN(), RRType::SOA(),
                                   RRTTL(3600)));
            soa->addRdata(rdata::generic::SOA(zone_name, zone_name, s,
                                              3600, 3600, 3600, 3600));
            diffs_.push_back(soa); // delete old SOA
            diffs_.push_back(ns); // delete old NS
            if (remove_nsec3 && s == beg_serial) {
                const RRsetPtr nsec3p(new RRset(zone_name, RRClass::IN(),
                                                RRType::NSEC3PARAM(),
                                                RRTTL(3600)));
                nsec3p->addRdata(rdata::generic::NSEC3PARAM("1 1 1 D399EAAB"));
                diffs_.push_back(nsec3p);
            }
            soa.reset(new RRset(zone_name, RRClass::IN(), RRType::SOA(),
                                RRTTL(3600)));
            soa->addRdata(rdata::generic::SOA(zone_name, zone_name, s + 1,
                                              3600, 3600, 3600, 3600));
            if (broken) {
                // intentionally adding non-existent RRset.  update will fail.
                RRsetPtr badset(new RRset(zone_name, RRClass::IN(), RRType::A(),
                                          RRTTL(3600)));
                badset->addRdata(rdata::in::A("192.0.2.1"));
                diffs_.push_back(badset);
            }
            diffs_.push_back(soa); // add new SOA
            diffs_.push_back(ns); // add new NS
            it_ = diffs_.begin();
        }
        diffs_.push_back(ConstRRsetPtr());
    }
    virtual ConstRRsetPtr getNextDiff() {
        const ConstRRsetPtr result = *it_;
        ++it_;
        return (result);
    }

private:
    std::vector<ConstRRsetPtr> diffs_;
    std::vector<ConstRRsetPtr>::const_iterator it_;
};

// Emulate broken DataSourceClient implementation: it returns a null iterator
// from getIterator()
class MockDataSourceClient : public DataSourceClient {
public:
    MockDataSourceClient() :
        DataSourceClient("test"), use_journal_(false),
        use_null_iterator_(false), use_null_soa_(false),
        use_broken_soa_(false), use_broken_journal_(false), use_nsec3_(false),
        remove_nsec3_(false), serial_(1)
    {}
    virtual FindResult findZone(const Name&) const { throw 0; }
    virtual ZoneIteratorPtr getIterator(const Name& zname, bool) const {
        if (use_null_iterator_) {
            return (ZoneIteratorPtr());
        } else {
            return (ZoneIteratorPtr(new MockIterator(zname, serial_,
                                                     use_null_soa_,
                                                     use_broken_soa_,
                                                     use_nsec3_)));
        }
    }
    virtual ZoneUpdaterPtr getUpdater(const Name&, bool, bool) const {
        throw 0;
    }
    virtual std::pair<ZoneJournalReader::Result, ZoneJournalReaderPtr>
    getJournalReader(const Name& zname, uint32_t beg, uint32_t end) const {
        if (use_journal_) {
            ZoneJournalReaderPtr reader(new MockJournalReader(
                                            zname, beg, end,
                                            use_broken_journal_,
                                            remove_nsec3_));
            return (std::pair<ZoneJournalReader::Result, ZoneJournalReaderPtr>(
                        ZoneJournalReader::SUCCESS, reader));
        }
        bundy_throw(bundy::NotImplemented, "not implemented");
    }

    // Allow direct access from tests for convenience
    bool use_journal_;
    bool use_null_iterator_;
    bool use_null_soa_;
    bool use_broken_soa_;
    bool use_broken_journal_;
    bool use_nsec3_;
    bool remove_nsec3_;
    uint32_t serial_;
};

class ZoneDataLoaderTest : public ::testing::Test {
protected:
    ZoneDataLoaderTest() : zclass_(RRClass::IN()), zone_data_(NULL) {}
    void TearDown() {
        if (zone_data_ != NULL) {
            ZoneData::destroy(mem_sgmt_, zone_data_, zclass_);
        }
        EXPECT_TRUE(mem_sgmt_.allMemoryDeallocated()); // catch any leak here.
    }
    ZoneData* checkLoad(ZoneDataLoader& loader, bool incremental,
                        bool expect_immediate = false)
    {
        // Initially, loaded data should be NULL.
        EXPECT_FALSE(loader.getLoadedData());

        ZoneData* zone_data;
        if (incremental) {
            if (expect_immediate) {
                // If load is expected to complete immediately, the minimal
                // incremental load should return true.
                EXPECT_TRUE(loader.loadIncremental(1));
            } else {
                // Otherwise, there'll be at least two different RRsets to be
                // installed, so loadIncremental with count_limit=1 should
                // always return false.
                EXPECT_FALSE(loader.loadIncremental(1));
                EXPECT_FALSE(loader.getLoadedData()); // should still be NULL
                // And then it should eventually succeed.
                while (!loader.loadIncremental(2)) {
                    // and, as long as load is continued, this should be NULL.
                    EXPECT_FALSE(loader.getLoadedData());
                }
            }
            zone_data = loader.getLoadedData();
        } else {
            zone_data = loader.load();
            EXPECT_EQ(zone_data, loader.getLoadedData());
        }
        return (zone_data);
    }
    void loadFromDataSourceCommon(bool incremental);
    void relocateCommon(bool incremental);
    const RRClass zclass_;
    test::MemorySegmentMock mem_sgmt_;
    ZoneData* zone_data_;
};

TEST_F(ZoneDataLoaderTest, loadRRSIGFollowsNothing) {
    // This causes the situation where an RRSIG is added without a covered
    // RRset.  It will be accepted, and corresponding "sig-only" rdata will
    // be created.
    zone_data_ = ZoneDataLoader(mem_sgmt_, zclass_, Name("example.org"),
                                TEST_DATA_DIR
                                "/example.org-rrsig-follows-nothing.zone").
        load();
    ZoneNode* node = NULL;
    zone_data_->insertName(mem_sgmt_, Name("ns1.example.org"), &node);
    ASSERT_NE(static_cast<ZoneNode*>(NULL), node);
    const RdataSet* rdset = node->getData();
    ASSERT_NE(static_cast<RdataSet*>(NULL), rdset);
    EXPECT_EQ(RRType::A(), rdset->type); // there should be only 1 data here
    EXPECT_EQ(0, rdset->getRdataCount()); // no RDATA
    EXPECT_EQ(1, rdset->getSigRdataCount()); // but 1 SIG

    // Teardown checks for memory segment leaks
}

TEST_F(ZoneDataLoaderTest, zoneMinTTL) {
    // This should hold outside of the loader class, but we do double check.
    zone_data_ = ZoneDataLoader(mem_sgmt_, zclass_, Name("example.org"),
                                TEST_DATA_DIR
                                "/example.org-nsec3-signed.zone").load();
    bundy::util::InputBuffer b(zone_data_->getMinTTLData(), sizeof(uint32_t));
    EXPECT_EQ(RRTTL(1200), RRTTL(b));
}

void
ZoneDataLoaderTest::loadFromDataSourceCommon(bool incremental) {
    const Name origin("example.com");
    MockDataSourceClient dsc;

    // First load: Load should succeed, and the ZoneData should be newly created
    ZoneDataLoader loader1(mem_sgmt_, zclass_, origin, dsc);
    zone_data_ = checkLoad(loader1, incremental);
    EXPECT_TRUE(zone_data_);
    EXPECT_FALSE(loader1.isDataReused());

    // Next, the serial doesn't change, so the actual load is skipped,
    // same ZoneData will be returned.
    ZoneDataLoader loader2(mem_sgmt_, zclass_, origin, dsc, zone_data_);
    ZoneData* zone_data2 = zone_data_ = checkLoad(loader2, incremental, true);
    EXPECT_TRUE(zone_data2);
    EXPECT_TRUE(loader2.isDataReused());
    EXPECT_EQ(zone_data_, zone_data2);

    // Normal update case: the serial of the new version is larger than current.
    // It'll be loaded just like the initial case.
    dsc.serial_ = 10;
    ZoneDataLoader loader3(mem_sgmt_, zclass_, origin, dsc, zone_data_);
    ZoneData* zone_data3 = checkLoad(loader3, incremental);
    EXPECT_TRUE(zone_data3);
    EXPECT_FALSE(loader3.isDataReused());
    EXPECT_NE(zone_data2, zone_data3);
    ZoneData::destroy(mem_sgmt_, zone_data2, zclass_);

    // Even if the new version has a smaller serial, it will be loaded
    // (but it'll internally trigger a warning log message).
    dsc.serial_ = 9;
    ZoneDataLoader loader4(mem_sgmt_, zclass_, origin, dsc, zone_data3);
    zone_data_ = checkLoad(loader4, incremental);
    EXPECT_TRUE(zone_data_);
    EXPECT_FALSE(loader4.isDataReused());
    EXPECT_NE(zone_data3, zone_data_);
    ZoneData::destroy(mem_sgmt_, zone_data_, zclass_);
    ZoneData::destroy(mem_sgmt_, zone_data3, zclass_);

    // Unusual case: old data don't contain SOA.  It should itself be an issue,
    // but for ZoneDataLoader this is no different from loading new data.
    ZoneData* old_data = ZoneData::create(mem_sgmt_, origin); // empty zone
    ZoneDataLoader loader5(mem_sgmt_, zclass_, origin, dsc, old_data);
    zone_data_ = checkLoad(loader5, incremental);
    EXPECT_TRUE(zone_data_);
    EXPECT_FALSE(loader5.isDataReused());
    EXPECT_NE(old_data, zone_data_);
    ZoneData::destroy(mem_sgmt_, old_data, zclass_);

    // enable diff based loading
    dsc.serial_ = 12;
    dsc.use_journal_ = true;
    ZoneDataLoader loader6(mem_sgmt_, zclass_, origin, dsc, zone_data_);
    ZoneData* zone_data6 = checkLoad(loader6, incremental, true);
    EXPECT_EQ(zone_data_, zone_data6);
    EXPECT_TRUE(loader6.isDataReused());
    EXPECT_EQ(zone_data_, loader6.commit(zone_data_));

    // increase the end serial sufficiently large so the internal vector
    // will be full and JournalReader still has some data.
    dsc.serial_ = 120;
    ZoneDataLoader loader7(mem_sgmt_, zclass_, origin, dsc, zone_data_);
    ZoneData* zone_data7 = checkLoad(loader7, incremental, true);
    EXPECT_EQ(zone_data_, zone_data7);
    EXPECT_TRUE(loader7.isDataReused());
    EXPECT_EQ(zone_data_, loader7.commit(zone_data_));

    // broken data from journal.  commit() propagates the exception.
    dsc.serial_ = 125;
    dsc.use_broken_journal_ = true;
    ZoneDataLoader loader8(mem_sgmt_, zclass_, origin, dsc, zone_data_);
    ZoneData* zone_data8 = checkLoad(loader8, incremental, true);
    EXPECT_EQ(zone_data_, zone_data8);
    EXPECT_TRUE(loader8.isDataReused());
    EXPECT_THROW(loader8.commit(zone_data_), ZoneDataUpdater::RemoveError);
}

TEST_F(ZoneDataLoaderTest, loadFromDataSource) {
    loadFromDataSourceCommon(false);
}

TEST_F(ZoneDataLoaderTest, loadFromDataSourceIncremental) {
    loadFromDataSourceCommon(true);
}

TEST_F(ZoneDataLoaderTest, loadFromBadDataSource) {
    // Even if getIterator() returns NULL, it shouldn't cause a crash.
    MockDataSourceClient dsc;
    dsc.use_null_iterator_ = true;
    EXPECT_THROW(ZoneDataLoader(mem_sgmt_, zclass_, Name("example.com"),
                                dsc).load(), bundy::Unexpected);

    // If iterator doesn't return SOA, load should fail.
    dsc.use_null_iterator_ = false;
    dsc.use_null_soa_ = true;
    EXPECT_THROW(ZoneDataLoader(mem_sgmt_, zclass_, Name("example.com"),
                                dsc).load(), ZoneValidationError);

    // If an empty SOA is returned, it will be considered an implementation
    // error.
    dsc.use_null_soa_ = false;
    dsc.use_broken_soa_ = true;
    EXPECT_THROW(ZoneDataLoader(mem_sgmt_, zclass_, Name("example.com"),
                                dsc).load(), bundy::Unexpected);

    // Not really a bad data source, but a buggy case: given old data don't
    // have the correct origin name.
    dsc.use_broken_soa_ = false;
    ZoneData* old_data = ZoneData::create(mem_sgmt_, Name("example.org"));
    EXPECT_THROW(ZoneDataLoader(mem_sgmt_, zclass_, Name("example.com"),
                                dsc, old_data), bundy::BadValue);
    ZoneData::destroy(mem_sgmt_, old_data, zclass_);
}

TEST_F(ZoneDataLoaderTest, loadToBeNSEC3Unsigned) {
    const Name origin("example.com");
    MockDataSourceClient dsc;

    // First load.  Make the zone NSEC3-signed by adding NSEC3PARAM.
    dsc.use_nsec3_ = true;
    zone_data_ = ZoneDataLoader(mem_sgmt_, zclass_, origin, dsc).load();
    EXPECT_TRUE(zone_data_);
    EXPECT_TRUE(zone_data_->isNSEC3Signed());

    // Perform diff-based load, removing the NSEC3PARAM.
    ++dsc.serial_;
    dsc.use_journal_ = true;
    dsc.remove_nsec3_ = true;
    ZoneDataLoader loader(mem_sgmt_, zclass_, origin, dsc, zone_data_);
    EXPECT_EQ(zone_data_, loader.load());
    EXPECT_EQ(zone_data_, loader.commit(zone_data_));
    EXPECT_FALSE(zone_data_->isNSEC3Signed());
}

// Load bunch of small zones, hoping some of the relocation will happen
// during the memory creation, not only Rdata creation.
// Note: this doesn't even compile unless USE_SHARED_MEMORY is defined.
void
ZoneDataLoaderTest::relocateCommon(bool incremental) {
    const char* const mapped_file = TEST_DATA_BUILDDIR "/test.mapped";
    MemorySegmentMapped segment(mapped_file,
                                bundy::util::MemorySegmentMapped::CREATE_ONLY,
                                4096);
    const size_t zone_count = 10000;
    typedef SegmentObjectHolder<ZoneData, RRClass> Holder;
    typedef boost::shared_ptr<Holder> HolderPtr;
    std::vector<HolderPtr> zones;
    for (size_t i = 0; i < zone_count; ++i) {
        // Load some zone
        ZoneDataLoader loader(segment, RRClass::IN(), Name("example.org"),
                              TEST_DATA_DIR "/example.org-nsec3-signed.zone");
        ZoneData* data = checkLoad(loader, incremental);
        // Store it, so it is cleaned up later
        zones.push_back(HolderPtr(new Holder(segment, RRClass::IN())));
        zones.back()->set(data);

    }
    // Deallocate all the zones now.
    zones.clear();
    EXPECT_TRUE(segment.allMemoryDeallocated());
    EXPECT_EQ(0, unlink(mapped_file));
}

TEST_F(ZoneDataLoaderTest,
#ifdef USE_SHARED_MEMORY
       relocate
#else
       DISABLED_relocate
#endif
)
{
    relocateCommon(false);
}

TEST_F(ZoneDataLoaderTest,
#ifdef USE_SHARED_MEMORY
       relocateIncremental
#else
       DISABLED_relocateIncremental
#endif
)
{
    relocateCommon(true);             
}
}
