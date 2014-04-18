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

#ifndef UTIL_UNITTEST_RESOLVER_H
#define UTIL_UNITTEST_RESOLVER_H

/// \file resolver.h
/// \brief Fake resolver

#include <map>
#include <dns/rrset.h>
#include <dns/question.h>
#include <dns/message.h>
#include <dns/opcode.h>
#include <dns/rcode.h>
#include <dns/rrttl.h>
#include <resolve/resolver_interface.h>
#include <gtest/gtest.h>

namespace bundy {
namespace util {
namespace unittests {

/// \brief Put rrset into a message as an answer
inline static bundy::dns::MessagePtr
createResponseMessage(bundy::dns::RRsetPtr answer_rrset)
{
    bundy::dns::MessagePtr response(new bundy::dns::Message(
        bundy::dns::Message::RENDER));
    response->setOpcode(bundy::dns::Opcode::QUERY());
    response->setRcode(bundy::dns::Rcode::NOERROR());
    response->addRRset(bundy::dns::Message::SECTION_ANSWER, answer_rrset);
    return response;
}

/// \brief Mock resolver
///
/// This class pretends to be a resolver. However, it only stores the
/// requests and can answer them right away by prepared answers. It doesn't
/// do any real work and is intended for testing purposes.
class TestResolver : public bundy::resolve::ResolverInterface {
    private:
        bool checkIndex(size_t index) {
            return (requests.size() > index);
        }

        typedef std::map<bundy::dns::Question, bundy::dns::RRsetPtr>
            PresetAnswers;
        PresetAnswers answers_;
    public:
        typedef std::pair<bundy::dns::QuestionPtr, CallbackPtr> Request;
        /// \brief List of requests the tested class sent through resolve
        std::vector<Request> requests;

        /// \brief Destructor
        ///
        /// This is important.  All callbacks in the requests vector must be
        /// called to remove them from internal loops.  Without this, destroying
        /// the NSAS object will leave memory assigned.
        ~TestResolver() {
            for (size_t i = 0; i < requests.size(); ++i) {
                requests[i].second->failure();
            }
        }

        /// \brief Testing version of resolve
        ///
        /// If there's a prepared answer (provided by addPresetAnswer), it
        /// answers it right away. Otherwise it just stores the request in
        /// the requests member so it can be examined later.
        virtual void resolve(const bundy::dns::QuestionPtr& q,
                             const CallbackPtr& c)
        {
            PresetAnswers::iterator it(answers_.find(*q));
            if (it == answers_.end()) {
                requests.push_back(Request(q, c));
            } else {
                if (it->second) {
                    c->success(createResponseMessage(it->second));
                } else {
                    c->failure();
                }
            }
        }

        /// \brief Add a preset answer.
        ///
        /// Add a preset answer. If shared_ptr() is passed (eg. NULL),
        /// it will generate failure. If the question is not preset,
        /// it goes to requests and you can answer later.
        void addPresetAnswer(const bundy::dns::Question& question,
            bundy::dns::RRsetPtr answer)
        {
            answers_[question] = answer;
        }

        /// \brief Thrown if the query at the given index does not exist.
        class NoSuchRequest : public std::exception { };

        /// \brief Thrown if the answer does not match the query
        class DifferentRequest : public std::exception { };

        /// \brief Provides the question of request on given answer
        bundy::dns::QuestionPtr operator[](size_t index) {
            if (index >= requests.size()) {
                throw NoSuchRequest();
            }
            return (requests[index].first);
        }
        /// \brief Test it asks for IP addresses
        /// Looks if the two provided requests in resolver are A and AAAA.
        /// Sorts them so index1 is A.
        ///
        /// Returns false if there aren't enough elements
        bool asksIPs(const bundy::dns::Name& name, size_t index1,
                     size_t index2)
        {
            size_t max = (index1 < index2) ? index2 : index1;
            if (!checkIndex(max)) {
                return false;
            }
            EXPECT_EQ(name, (*this)[index1]->getName());
            EXPECT_EQ(name, (*this)[index2]->getName());
            EXPECT_EQ(bundy::dns::RRClass::IN(), (*this)[index1]->getClass());
            EXPECT_EQ(bundy::dns::RRClass::IN(), (*this)[index2]->getClass());
            // If they are the other way around, swap
            if ((*this)[index1]->getType() == bundy::dns::RRType::AAAA() &&
                (*this)[index2]->getType() == bundy::dns::RRType::A())
            {
                TestResolver::Request tmp((*this).requests[index1]);
                (*this).requests[index1] =
                    (*this).requests[index2];
                (*this).requests[index2] = tmp;
            }
            // Check the correct addresses
            EXPECT_EQ(bundy::dns::RRType::A(), (*this)[index1]->getType());
            EXPECT_EQ(bundy::dns::RRType::AAAA(), (*this)[index2]->getType());
            return (true);
        }

        /// \brief Answer a request
        /// Sends a simple answer to a query.
        /// 1) Provide index of a query and the address(es) to pass.
        /// 2) Provide index of query and components of address to pass.
        void answer(size_t index, bundy::dns::RRsetPtr& set) {
            if (index >= requests.size()) {
                throw NoSuchRequest();
            }
            requests[index].second->success(createResponseMessage(set));
        }

        void answer(size_t index, const bundy::dns::Name& name,
                    const bundy::dns::RRType& type,
                    const bundy::dns::rdata::Rdata& rdata, size_t TTL = 100)
        {
            bundy::dns::RRsetPtr set(new bundy::dns::RRset(name,
                                                       bundy::dns::RRClass::IN(),
                                                       type,
                                                       bundy::dns::RRTTL(TTL)));
            set->addRdata(rdata);
            answer(index, set);
        }
        /// \Answer the query at index by list of nameservers
        void provideNS(size_t index, bundy::dns::RRsetPtr nameservers)
        {
            if (index >= requests.size()) {
                throw NoSuchRequest();
            }
            if (requests[index].first->getName() != nameservers->getName() ||
                requests[index].first->getType() != bundy::dns::RRType::NS())
            {
                throw DifferentRequest();
            }
            requests[index].second->success(createResponseMessage(nameservers));
        }
};

}
}
}

#endif
