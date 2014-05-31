// Copyright (C) 2014  The Bundy Project.
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

// Copyright (C) 2011  Internet Systems Consortium, Inc. ("ISC")
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

#include <string>

#include <util/buffer.h>
#include <util/encode/hex.h>

#include <dns/messagerenderer.h>
#include <dns/rdata.h>
#include <dns/rdataclass.h>

#include <dns/rdata/generic/detail/ds_like.h>

using namespace std;
using namespace bundy::util;
using namespace bundy::util::encode;
using namespace bundy::dns::rdata::generic::detail;

// BEGIN_BUNDY_NAMESPACE
// BEGIN_RDATA_NAMESPACE

CDS::CDS(const std::string& cds_str) :
    impl_(new CDSImpl(cds_str))
{}

CDS::CDS(InputBuffer& buffer, size_t rdata_len) :
    impl_(new CDSImpl(buffer, rdata_len))
{}

CDS::CDS(MasterLexer& lexer, const Name* origin, MasterLoader::Options options,
         MasterLoaderCallbacks& callbacks) :
    impl_(new CDSImpl(lexer, origin, options, callbacks))
{}

CDS::CDS(const CDS& source) :
    Rdata(), impl_(new CDSImpl(*source.impl_))
{}

CDS&
CDS::operator=(const CDS& source) {
    if (this == &source) {
        return (*this);
    }

    CDSImpl* newimpl = new CDSImpl(*source.impl_);
    delete impl_;
    impl_ = newimpl;

    return (*this);
}

CDS::~CDS() {
    delete impl_;
}

string
CDS::toText() const {
    return (impl_->toText());
}

void
CDS::toWire(OutputBuffer& buffer) const {
    impl_->toWire(buffer);
}

void
CDS::toWire(AbstractMessageRenderer& renderer) const {
    impl_->toWire(renderer);
}

int
CDS::compare(const Rdata& other) const {
    const CDS& other_cds = dynamic_cast<const CDS&>(other);

    return (impl_->compare(*other_cds.impl_));
}

uint16_t
CDS::getTag() const {
    return (impl_->getTag());
}

// END_RDATA_NAMESPACE
// END_BUNDY_NAMESPACE
