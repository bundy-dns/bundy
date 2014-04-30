# Copyright (C) 2013  Internet Systems Consortium.
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SYSTEMS CONSORTIUM
# DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
# INTERNET SYSTEMS CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
# FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
# NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
# WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

import json
from bundy.datasrc import ConfigurableClientList
import bundy.datasrc
from bundy.memmgr.datasrc_info import SegmentInfo

from bundy.log_messages.libmemmgr_messages import *
from bundy.memmgr.logger import logger

class MemorySegmentBuilder:
    """The builder runs in a different thread in the memory manager. It
    waits for commands from the memory manager, and then executes them
    in the given order sequentially.
    """

    # Internal return code for __reset_segment()
    __RESET_SEGMENT_OK = 0
    __RESET_SEGMENT_FAILED = 1
    __RESET_SEGMENT_CREATED = 2

    def __init__(self, sock, cv, command_queue, response_queue):
        """ The constructor takes the following arguments:

            sock: A socket using which this builder object notifies the
                  main thread that it has a response waiting for it.

            cv: A condition variable object that is used by the main
                thread to tell this builder object that new commands are
                available to it. Note that this is also used for
                synchronizing access to the queues, so code that uses
                MemorySegmentBuilder must use this condition variable's
                lock object to synchronize its access to the queues.

            command_queue: A list of commands sent by the main thread to
                           this object. Commands should be executed
                           sequentially in the given order by this
                           object.

            response_queue: A list of responses sent by this object to
                            the main thread. The format of this is
                            currently not strictly defined. Future
                            tickets will be able to define it based on
                            how it's used.
        """

        self._sock = sock
        self._cv = cv
        self._command_queue = command_queue
        self._response_queue = response_queue
        self._shutdown = False

    def __handle_shutdown(self):
        # This method is called when handling the 'shutdown' command. The
        # following tuple is passed:
        #
        # ('shutdown',)
        self._shutdown = True

    def __handle_bad_command(self, bad_command):
        # A bad command was received. Raising an exception is not useful
        # in this case as we are likely running in a different thread
        # from the main thread which would need to be notified. Instead
        # return this in the response queue.
        logger.error(LIBMEMMGR_BUILDER_BAD_COMMAND_ERROR, bad_command)
        self._response_queue.append(('bad_command',))
        self._shutdown = True

    def __handle_validate(self, args):
        """Handle 'validate' command.

        Command arguments are the same 'load' except the last one:
        'action': callable without any parameter itself, encapsulating
                  any segment-specific validation logic.  It returns
                  a result of the validation.

        This method simply calls the passed action, and returns the result
        back to the memmgr with other command arguments.  This is run in
        the builder thread simply because it may take time.

        """
        _, dsrc_info, rrclass, dsrc_name, action = args

        logger.debug(logger.DBGLVL_TRACE_BASIC,
                     LIBMEMMGR_BUILDER_SEGMENT_VALIDATE, dsrc_name, rrclass)
        try:
            result = action()
        except Exception as ex:
            logger.error(LIBMEMMGR_BUILDER_SEGMENT_VALIDATE_FAIL, dsrc_name,
                         rrclass, ex)
            result = False
        self._response_queue.append(('validate-completed', dsrc_info, rrclass,
                                     dsrc_name, result))

    def __reset_segment(self, clist, dsrc_name, rrclass, params):
        try:
            clist.reset_memory_segment(dsrc_name,
                                       ConfigurableClientList.READ_WRITE,
                                       params)
            logger.debug(logger.DBGLVL_TRACE_BASIC,
                         LIBMEMMGR_BUILDER_SEGMENT_RESET, dsrc_name, rrclass)
            return self.__RESET_SEGMENT_OK
        except Exception as ex:
            logger.error(LIBMEMMGR_BUILDER_RESET_SEGMENT_ERROR, dsrc_name,
                         rrclass, ex)
        try:
            clist.reset_memory_segment(dsrc_name, ConfigurableClientList.CREATE,
                                       params)
            logger.info(LIBMEMMGR_BUILDER_SEGMENT_CREATED, dsrc_name, rrclass)
            return self.__RESET_SEGMENT_CREATED
        except Exception as ex:
            logger.error(LIBMEMMGR_BUILDER_SEGMENT_CREATE_ERROR, dsrc_name,
                         rrclass, ex)
        return self.__RESET_SEGMENT_FAILED

    def _handle_load(self, zone_name, dsrc_info, rrclass, dsrc_name):
        # This method is called when handling the 'load' command. The
        # following tuple is passed:
        #
        # ('load', zone_name, dsrc_info, rrclass, dsrc_name)
        #
        # where:
        #
        #  * zone_name is None or bundy.dns.Name, specifying the zone name
        #    to load. If it's None, it means all zones to be cached in
        #    the specified data source (used for initialization).
        #
        #  * dsrc_info is a DataSrcInfo object corresponding to the
        #    generation ID of the set of data sources for this loading.
        #
        #  * rrclass is an bundy.dns.RRClass object, the RR class of the
        #    data source.
        #
        #  * dsrc_name is a string, specifying a data source name.
        #
        # This is essentially a 'private' method, but allows tests to call it
        # directly; for other purposes shouldn't be called outside of the class.

        clist = dsrc_info.clients_map[rrclass]
        sgmt_info = dsrc_info.segment_info_map[(rrclass, dsrc_name)]
        params = json.dumps(sgmt_info.get_reset_param(SegmentInfo.WRITER))
        result = self.__reset_segment(clist, dsrc_name, rrclass, params)
        if result == self.__RESET_SEGMENT_FAILED:
            self._response_queue.append(('load-completed', dsrc_info, rrclass,
                                         dsrc_name, False))
            return

        # If we were told to load a single zone but had to create a new
        # segment, we'll need to load all zones, not just this one.
        if result == self.__RESET_SEGMENT_CREATED and zone_name is not None:
            logger.info(LIBMEMMGR_BUILDER_SEGMENT_LOAD_ALL, zone_name, rrclass,
                        dsrc_name)
            zone_name = None
        if zone_name is not None:
            zones = [(None, zone_name)]
        else:
            zones = clist.get_zone_table_accessor(dsrc_name, True)

        errors = 0
        for _, zname in zones:  # note: don't override zone_name here
            # install empty zone initially
            catch_load_error = (zname is None)
            try:
                result, writer = clist.get_cached_zone_writer(zname,
                                                              catch_load_error,
                                                              dsrc_name)
                if result != ConfigurableClientList.CACHE_STATUS_ZONE_SUCCESS:
                    # handle this with other genuine exceptions below
                    raise bundy.datasrc.Error('result=%d' % result)
            except bundy.datasrc.Error as ex:
                logger.error(LIBMEMMGR_BUILDER_GET_ZONE_WRITER_ERROR,
                             zname, dsrc_name, ex)
                errors += 1
                continue

            try:
                error = writer.load()
                if error is not None:
                    logger.error(LIBMEMMGR_BUILDER_ZONE_WRITER_LOAD_1_ERROR,
                                 zname, dsrc_name, error)
                    errors += 1
                    continue
                writer.install()
            except Exception as e:
                logger.error(LIBMEMMGR_BUILDER_ZONE_WRITER_LOAD_2_ERROR,
                             zname, dsrc_name, e)
                errors += 1
                # fall through to cleanup
            writer.cleanup()

        # need to reset the segment so readers can read it (note: memmgr
        # itself doesn't have to keep it open, but there's currently no
        # public API to just clear the segment).  This 'reset' should succeed,
        # so we'll let any exception be propagated.
        clist.reset_memory_segment(dsrc_name,
                                   ConfigurableClientList.READ_ONLY,
                                   params)

        # At this point, we consider the load a failure only if loading a
        # specific zone has failed.
        succeeded = True if (zone_name is None or errors == 0) else False
        self._response_queue.append(('load-completed', dsrc_info, rrclass,
                                     dsrc_name, succeeded))

    def run(self):
        """ This is the method invoked when the builder thread is
            started.  In this thread, be careful when modifying
            variables passed-by-reference in the constructor. If they
            are reassigned, they will not refer to the main thread's
            objects any longer. Any use of command_queue and
            response_queue must be synchronized by acquiring the lock in
            the condition variable. This method must normally terminate
            only when the 'shutdown' command is sent to it.
        """

        # Acquire the condition variable while running the loop.
        with self._cv:
            while not self._shutdown:
                while not self._command_queue:
                    self._cv.wait()
                # Move the queue content to a local queue. Be careful of
                # not making assignments to reference variables.
                local_command_queue = self._command_queue[:]
                del self._command_queue[:]

                # Run commands passed in the command queue sequentially
                # in the given order.  For now, it only supports the
                # "shutdown" command, which just exits the thread.
                for command_tuple in local_command_queue:
                    command = command_tuple[0]
                    logger.debug(logger.DBGLVL_TRACE_BASIC,
                                 LIBMEMMGR_BUILDER_RECEIVED_COMMAND, command)
                    if command == 'validate':
                        self.__handle_validate(command_tuple)
                    elif command == 'load':
                        # See the comments for _handle_load() for
                        # details of the tuple passed to the "load"
                        # command.
                        _, zone_name, dsrc_info, rrclass, dsrc_name = \
                            command_tuple
                        self._handle_load(zone_name, dsrc_info, rrclass,
                                          dsrc_name)
                    elif command == 'shutdown':
                        self.__handle_shutdown()
                        # When the shutdown command is received, we do
                        # not process any further commands.
                        break
                    else:
                        self.__handle_bad_command(command)
                        # When a bad command is received, we do not
                        # process any further commands.
                        break

                # Notify (any main thread) on the socket about a
                # response. Otherwise, the main thread may wait in its
                # loop without knowing there was a problem.
                if self._response_queue:
                    while self._sock.send(b'x') != 1:
                        continue
