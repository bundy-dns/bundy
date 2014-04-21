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
                 bool use_null_soa, bool use_broken_soa) :
        soa_(new RRset(zone_name, RRClass::IN(), RRType::SOA(), RRTTL(3600))),
        ns_(new RRset(zone_name, RRClass::IN(), RRType::NS(), RRTTL(3600)))
    {
        soa_->addRdata(rdata::generic::SOA(zone_name, zone_name, serial,
                                           3600, 3600, 3600, 3600));
        rrsets_.push_back(soa_);
        ns_->addRdata(rdata::generic::NS(Name("ns.example")));
        rrsets_.push_back(ns_);
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
    const RRsetPtr ns_;
    std::vector<ConstRRsetPtr> rrsets_;
    std::vector<ConstRRsetPtr>::const_iterator it_;
};

class MockJournalReader : public ZoneJournalReader {
public:
    MockJournalReader(const Name& zone_name, uint32_t beg_serial,
                      uint32_t end_serial, bool broken)
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
        use_broken_soa_(false), use_broken_journal_(false), serial_(1)
    {}
    virtual FindResult findZone(const Name&) const { throw 0; }
    virtual ZoneIteratorPtr getIterator(const Name& zname, bool) const {
        if (use_null_iterator_) {
            return (ZoneIteratorPtr());
        } else {
            return (ZoneIteratorPtr(new MockIterator(zname, serial_,
                                                     use_null_soa_,
                                                     use_broken_soa_)));
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
                                            use_broken_journal_));
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
        load().first;
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
                                "/example.org-nsec3-signed.zone").load().first;
    bundy::util::InputBuffer b(zone_data_->getMinTTLData(), sizeof(uint32_t));
    EXPECT_EQ(RRTTL(1200), RRTTL(b));
}

TEST_F(ZoneDataLoaderTest, loadFromDataSource) {
    const Name origin("example.com");
    MockDataSourceClient dsc;

    // First load: Load should succeed, and the ZoneData should be newly created
    ZoneDataLoader loader1(mem_sgmt_, zclass_, origin, dsc);
    const ZoneDataLoader::LoadResult result1 = loader1.load();
    zone_data_ = result1.first;
    EXPECT_TRUE(zone_data_);
    EXPECT_TRUE(result1.second);

    // Next, the serial doesn't change, so the actual load is skipped,
    // same ZoneData will be returned.
    ZoneDataLoader loader2(mem_sgmt_, zclass_, origin, dsc, zone_data_);
    const ZoneDataLoader::LoadResult result2 = loader2.load();
    zone_data_ = result2.first;
    EXPECT_TRUE(zone_data_);
    EXPECT_FALSE(result2.second);
    EXPECT_EQ(result1.first, result2.first);

    // Normal update case: the serial of the new version is larger than current.
    // It'll be loaded just like the initial case.
    dsc.serial_ = 10;
    ZoneDataLoader loader3(mem_sgmt_, zclass_, origin, dsc, zone_data_);
    const ZoneDataLoader::LoadResult result3 = loader3.load();
    zone_data_ = result3.first;
    EXPECT_TRUE(zone_data_);
    EXPECT_TRUE(result3.second);
    EXPECT_NE(result2.first, zone_data_);
    ZoneData::destroy(mem_sgmt_, result2.first, zclass_);

    // Even if the new version has a smaller serial, it will be loaded
    // (but it'll internally trigger a warning log message).
    dsc.serial_ = 9;
    ZoneDataLoader loader4(mem_sgmt_, zclass_, origin, dsc, zone_data_);
    const ZoneDataLoader::LoadResult result4 = loader4.load();
    zone_data_ = result4.first;
    EXPECT_TRUE(zone_data_);
    EXPECT_TRUE(result4.second);
    EXPECT_NE(result3.first, zone_data_);
    ZoneData::destroy(mem_sgmt_, zone_data_, zclass_);
    ZoneData::destroy(mem_sgmt_, result3.first, zclass_);

    // Unusual case: old data don't contain SOA.  It should itself be an issue,
    // but for ZoneDataLoader this is no different from loading new data.
    ZoneData* old_data = ZoneData::create(mem_sgmt_, origin); // empty zone
    ZoneDataLoader loader5(mem_sgmt_, zclass_, origin, dsc, old_data);
    const ZoneDataLoader::LoadResult result5 = loader5.load();
    zone_data_ = result5.first;
    EXPECT_TRUE(zone_data_);
    EXPECT_TRUE(result5.second);
    EXPECT_NE(old_data, zone_data_);
    ZoneData::destroy(mem_sgmt_, old_data, zclass_);

    // enable diff based loading
    dsc.serial_ = 12;
    dsc.use_journal_ = true;
    ZoneDataLoader loader6(mem_sgmt_, zclass_, origin, dsc, zone_data_);
    const ZoneDataLoader::LoadResult result6 = loader6.load();
    EXPECT_EQ(zone_data_, result6.first);
    EXPECT_FALSE(result6.second);
    EXPECT_EQ(zone_data_, loader6.commit(zone_data_));

    // broken data from journal.  commit() propagates the exception.
    dsc.serial_ = 15;
    dsc.use_broken_journal_ = true;
    ZoneDataLoader loader7(mem_sgmt_, zclass_, origin, dsc, zone_data_);
    const ZoneDataLoader::LoadResult result7 = loader7.load();
    EXPECT_EQ(zone_data_, result7.first);
    EXPECT_FALSE(result7.second);
    EXPECT_THROW(loader7.commit(zone_data_), ZoneDataUpdater::RemoveError);
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

// Load bunch of small zones, hoping some of the relocation will happen
// during the memory creation, not only Rdata creation.
// Note: this doesn't even compile unless USE_SHARED_MEMORY is defined.
#ifdef USE_SHARED_MEMORY
TEST(ZoneDataLoaterTest, relocate) {
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
        ZoneData* data = ZoneDataLoader(segment, RRClass::IN(),
                                        Name("example.org"),
                                        TEST_DATA_DIR
                                        "/example.org-nsec3-signed.zone").
            load().first;
        // Store it, so it is cleaned up later
        zones.push_back(HolderPtr(new Holder(segment, RRClass::IN())));
        zones.back()->set(data);

    }
    // Deallocate all the zones now.
    zones.clear();
    EXPECT_TRUE(segment.allMemoryDeallocated());
    EXPECT_EQ(0, unlink(mapped_file));
}
#endif

}
