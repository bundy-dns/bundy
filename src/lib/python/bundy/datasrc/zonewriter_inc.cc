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

namespace {

const char* const ZoneWriter_doc = "\
Does an update to a zone.\n\
\n\
This represents the work of a (re)load of a zone. The work is divided\n\
into three stages  load(), install() and cleanup(). They should be\n\
called in this order for the effect to take place.\n\
\n\
We divide them so the update of zone data can be done asynchronously,\n\
in a different thread. The install() operation is the only one that\n\
needs to be done in a critical section.\n\
\n\
This class provides strong exception guarantee for each public method.\n\
That is, when any of the methods throws, the entire state stays the\n\
same as before the call.\n\
\n\
ZoneWriter objects cannot be constructed directly. They have to be\n\
obtained by using get_cached_zone_writer() on a ConfigurableClientList.\n\
\n\
";

const char* const ZoneWriter_load_doc = "\
load(int) -> bool\n\
\n\
Get the zone data into memory.\n\
\n\
This is the part that does the time-consuming loading into the memory.\n\
This can be run in a separate thread, for example. It has no effect on\n\
the data actually served, it only prepares them for future use.\n\
\n\
This is the first method you should call on the object. Never call it\n\
multiple times.\n\
\n\
The optional parameter 'count_limit' specifies the amount of items\n\
to be loaded in this call to this method.  The precise definition of\n\
'item' varies depending on internal details of the load implementation,\n\
but it's more or less compatible to the number of RRs to be loaded.\n\
If it's 0 (default), it means unlimited, i.e., this method continues\n\
until all the zone data are loaded.  Specifying a non-0 value allows\n\
the caller to perform incremental loading.\n\
\n\
This method returns True if the load is completed in the call.\n\
Otherwise it returns False to indicate the caller needs to call it\n\
again.\n\
\n\
Non-fatal load errors, such as a syntax error in zone file will result\n\
in the bundy.datasrc.Error exception.  Other unexpected errors, which\n\
are generally fatal, will result in SystemError.\n\
\n\
Exceptions:\n\
  bundy.datasrc.Error load related error.\n\
\n\
Parameter:\n\
  count_limit (int): number of items to be loaded in this call.\n\
                     0 means no limitation.\n\
Return:\n\
  True if the load is completed; otherwise False.\n\
";

const char* const ZoneWriter_install_doc = "\
install() -> void\n\
\n\
Put the changes to effect.\n\
\n\
This replaces the old version of zone with the one previously prepared\n\
by load(). It takes ownership of the old zone data, if any.\n\
\n\
You may call it only after successful load() and at most once. It\n\
includes the case the writer is constructed to allow load errors,\n\
and load() encountered and caught a DataSourceError exception.\n\
In this case this method installs a special empty zone to\n\
the table.\n\
\n\
The operation is expected to be fast and is meant to be used inside a\n\
critical section.\n\
\n\
This may throw in rare cases. If it throws, you still need to call\n\
cleanup().\n\
\n\
Exceptions:\n\
  bundy.InvalidOperation if called without previous load() or for the\n\
             second time or cleanup() was called already.\n\
\n\
";

const char* const ZoneWriter_cleanup_doc = "\
cleanup() -> void\n\
\n\
Clean up resources.\n\
\n\
This releases all resources held by owned zone data. That means the\n\
one loaded by load() in case install() was not called or was not\n\
successful, or the one replaced in install().\n\
\n\
Exceptions:\n\
  none\n\
\n\
";

} // unnamed namespace
