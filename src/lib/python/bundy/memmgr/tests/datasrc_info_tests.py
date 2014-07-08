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
import os
import unittest
import glob

from bundy.dns import *
import bundy.config
import bundy.datasrc
import bundy.log
from bundy.server_common.datasrc_clients_mgr import DataSrcClientsMgr
from bundy.memmgr.datasrc_info import *

# Defined for easier tests with DataSrcClientsMgr.reconfigure(), which
# only needs get_value() method
class MockConfigData:
    def __init__(self, data):
        self.__data = data

    def get_value(self, identifier):
        return self.__data[identifier], False

class TestSegmentInfo(unittest.TestCase):
    def setUp(self):
        self.__mapped_file_dir = os.environ['TESTDATA_WRITE_PATH']
        self.__sgmt_info = self.__create_sgmtinfo()
        self.__ver_file = self.__mapped_file_dir + \
            '/zone-IN-0-sqlite3-mapped-vers.json'
        self.__mapped_file_base = self.__mapped_file_dir + \
            '/zone-IN-0-sqlite3-mapped.'
        self.__orig_unlink = os.unlink

    def __create_sgmtinfo(self):
        return SegmentInfo.create('mapped', 0, RRClass.IN,
                                  'sqlite3', {'mapped_file_dir':
                                              self.__mapped_file_dir})

    def tearDown(self):
        os.unlink = self.__orig_unlink
        for f in glob.glob(self.__mapped_file_dir + '/*sqlite3-mapped-vers*'):
            os.unlink(f)

    def __check_sgmt_reset_param(self, user_type, expected_ver, sgmt_info=None):
        """Common check on the return value of get_reset_param() for
        MappedSegmentInfo.

        """
        if sgmt_info is None:
            sgmt_info = self.__sgmt_info # by default, we use the common info

        param = sgmt_info.get_reset_param(user_type)
        if expected_ver is None:
            self.assertEqual(None, param['mapped-file'])
        else:
            self.assertEqual(self.__mapped_file_base + str(expected_ver),
                             param['mapped-file'])

    def test_initial_params(self):
        self.__check_sgmt_reset_param(SegmentInfo.WRITER, 1)
        self.__check_sgmt_reset_param(SegmentInfo.READER, None)

        self.assertEqual(self.__sgmt_info.get_state(), SegmentInfo.INIT)
        self.assertEqual(self.__sgmt_info.get_generation_id(), 0)
        self.assertEqual(len(self.__sgmt_info.get_readers()), 0)
        self.assertEqual(len(self.__sgmt_info.get_old_readers()), 0)
        self.assertEqual(len(self.__sgmt_info.get_events()), 0)

        raction, waction = self.__sgmt_info.start_validate()
        self.assertEqual(False, raction())
        self.assertEqual(False, waction())

    def test_init_with_verfile(self):
        # Initialize with versions file, storing non-default versions
        vers = {'reader': 1, 'writer': 0}
        with open(self.__ver_file, 'w') as f:
            f.write(json.dumps(vers) + '\n')
        # Create faked mapped files.  For now, they only need to exist.
        with open(self.__mapped_file_base + '0', 'w'): pass
        with open(self.__mapped_file_base + '1', 'w'): pass

        # re-create the segment info, confirm the expected initial versions.
        self.__sgmt_info = self.__create_sgmtinfo()
        self.__check_sgmt_reset_param(SegmentInfo.WRITER, 0)
        self.__check_sgmt_reset_param(SegmentInfo.READER, None)

        # since the files exist, both actions should return True
        raction, waction = self.__sgmt_info.start_validate()
        self.assertEqual(True, raction())
        self.assertEqual(True, waction())

        # If either of the mapped files does't exist, Xaction returns False.
        os.unlink(self.__mapped_file_base + '0')
        self.assertEqual(True, raction()) # shouldn't be changed
        self.assertEqual(False, waction())
        os.unlink(self.__mapped_file_base + '1')
        self.assertEqual(False, raction())
        self.assertEqual(False, waction()) # should be the same result

    def __si_to_rvalidate_state(self):
        # Go to a default starting state
        self.__sgmt_info = SegmentInfo.create('mapped', 0, RRClass.IN,
                                              'sqlite3',
                                              {'mapped_file_dir':
                                                   self.__mapped_file_dir})
        self.__sgmt_info.start_validate()
        self.assertEqual(self.__sgmt_info.get_state(), SegmentInfo.R_VALIDATING)

    def __si_to_ready_state(self):
        self.__si_to_synchronizing2_state()
        self.__sgmt_info.sync_reader(3)
        # purge any existing readers so we can begin from a fresh 'ready' state
        for r in list(self.__sgmt_info.get_readers()):
            self.__sgmt_info.remove_reader(r)
        self.assertEqual(self.__sgmt_info.get_state(), SegmentInfo.READY)

    def __si_to_vsynchronizing_state(self):
        self.__si_to_rvalidate_state()
        self.__sgmt_info.add_event((42,))
        self.__sgmt_info.add_reader(3)
        self.assertIsNone(self.__sgmt_info.complete_validate(True))
        self.assertEqual(self.__sgmt_info.get_state(),
                         SegmentInfo.V_SYNCHRONIZING)
        self.assertSetEqual(self.__sgmt_info.get_old_readers(), {3})

    def __si_to_updating_state(self, initial_load=False):
        # If initial_load is True, this method moves the test segment info
        # to the initial updating state just after validation; otherwise
        # it emulates a subsequent update after initial loading.  Note that
        # the __si_xxx methods are recursively called, we need to carefully
        # specify 'initial_load' to avoid a recursion loop.
        if initial_load:
            self.__si_to_rvalidate_state()
            self.__sgmt_info.add_event(42)
            self.__sgmt_info.add_event((42,))
            self.assertEqual(self.__sgmt_info.complete_validate(True), 42)
            self.assertTupleEqual(self.__sgmt_info.complete_validate(True),
                                  (42, ))
        else:
            self.__si_to_ready_state()
            self.__sgmt_info.add_event((42,))
            self.assertEqual(self.__sgmt_info.start_update(), (42,))
        self.__sgmt_info.add_reader(3)
        self.assertSetEqual(self.__sgmt_info.get_readers(), {3})
        self.assertEqual(self.__sgmt_info.get_state(), SegmentInfo.UPDATING)

    def __si_to_synchronizing_state(self, initial_load=False):
        self.__si_to_updating_state(initial_load)
        self.__sgmt_info.complete_update(True)
        self.assertEqual(self.__sgmt_info.get_state(),
                         SegmentInfo.SYNCHRONIZING)

    def __si_to_copying_state(self, initial_load=False):
        self.__si_to_synchronizing_state(initial_load)
        self.__sgmt_info.sync_reader(3)
        self.assertEqual(self.__sgmt_info.get_state(), SegmentInfo.COPYING)

    def __si_to_synchronizing2_state(self):
        self.__si_to_copying_state(True)
        self.__sgmt_info.complete_update(True)
        self.assertEqual(self.__sgmt_info.get_state(),
                         SegmentInfo.SYNCHRONIZING2)

    def test_add_event(self):
        self.assertEqual(len(self.__sgmt_info.get_events()), 0)
        self.__sgmt_info.add_event(None)
        self.assertEqual(len(self.__sgmt_info.get_events()), 1)
        self.assertListEqual(self.__sgmt_info.get_events(), [None])

    def test_add_reader(self):
        self.assertSetEqual(self.__sgmt_info.get_readers(), set())
        self.assertSetEqual(self.__sgmt_info.get_old_readers(), set())
        self.__sgmt_info.add_reader(1)
        self.assertSetEqual(self.__sgmt_info.get_readers(), {1})
        self.__sgmt_info.add_reader(3)
        self.assertSetEqual(self.__sgmt_info.get_readers(), {1, 3})
        self.__sgmt_info.add_reader(2)
        self.assertSetEqual(self.__sgmt_info.get_readers(), {1, 2, 3})

        # adding the same existing reader must throw
        self.assertRaises(SegmentInfoError, self.__sgmt_info.add_reader, (1))
        # but the existing readers must be untouched
        self.assertSetEqual(self.__sgmt_info.get_readers(), {1, 3, 2})

        # none of this touches the old readers
        self.assertSetEqual(self.__sgmt_info.get_old_readers(), set())

    def test_start_update(self):
        # in READY state
        # a) there are no events
        self.__si_to_ready_state()
        e = self.__sgmt_info.start_update()
        self.assertIsNone(e)
        # if there are no events, there is nothing to update
        self.assertEqual(self.__sgmt_info.get_state(), SegmentInfo.READY)

        # b) there are events. this is the same as calling
        # self.__si_to_updating_state(), but let's try to be
        # descriptive.
        self.__si_to_ready_state()
        self.__sgmt_info.add_event((42,))
        e = self.__sgmt_info.start_update()
        self.assertTupleEqual(e, (42,))
        self.assertEqual(self.__sgmt_info.get_state(), SegmentInfo.UPDATING)

        # in UPDATING state, it should always return None and not
        # change state.
        self.__si_to_updating_state()
        self.assertIsNone(self.__sgmt_info.start_update())
        self.assertEqual(self.__sgmt_info.get_state(), SegmentInfo.UPDATING)

        # in SYNCHRONIZING state, it should always return None
        # and not change state.
        self.__si_to_synchronizing_state()
        self.assertIsNone(self.__sgmt_info.start_update())
        self.assertEqual(self.__sgmt_info.get_state(),
                         SegmentInfo.SYNCHRONIZING)

        # in COPYING state, it should always return None and not
        # change state.
        self.__si_to_copying_state()
        self.assertIsNone(self.__sgmt_info.start_update())
        self.assertEqual(self.__sgmt_info.get_state(), SegmentInfo.COPYING)

    def test_complete_update(self):
        self.__ver_switched = 0        # number of version switches
        def count_verswitch():
            self.__ver_switched += 1

        # in READY state
        self.__si_to_ready_state()
        self.assertRaises(SegmentInfoError,
                          self.__sgmt_info.complete_update, True)
        self.assertEqual(self.__sgmt_info.get_state(), SegmentInfo.READY)

        # in UPDATING state this is the same as calling
        # self.__si_to_synchronizing_state(), but let's try to be
        # descriptive.
        #
        # a) with no events
        self.__si_to_updating_state()
        self.__sgmt_info._switch_versions = lambda: count_verswitch()
        e = self.__sgmt_info.complete_update(True)
        self.assertIsNone(e)
        self.assertEqual(self.__sgmt_info.get_state(),
                         SegmentInfo.SYNCHRONIZING)
        self.assertEqual(1, self.__ver_switched)

        # a') with no events, update fails, initial load.  In this case,
        # we move to the SYNCHRONIZING state anyway.
        self.__si_to_updating_state(True)
        self.__sgmt_info._switch_versions = lambda: count_verswitch()
        e = self.__sgmt_info.complete_update(False)
        self.assertIsNone(e)
        self.assertEqual(self.__sgmt_info.get_state(),
                         SegmentInfo.SYNCHRONIZING)
        self.assertEqual(2, self.__ver_switched)

        # a'') with no events, update fails, subsequent update.  This load
        # is ignored, and it moves back to the READY state.
        self.__si_to_updating_state()
        self.__ver_switched = 1
        self.__sgmt_info._switch_versions = lambda: count_verswitch()
        e = self.__sgmt_info.complete_update(False)
        self.assertIsNone(e)
        self.assertEqual(self.__sgmt_info.get_state(), SegmentInfo.READY)
        self.assertEqual(1, self.__ver_switched) # no switch

        # b) with events
        self.__si_to_updating_state()
        self.__sgmt_info._switch_versions = lambda: count_verswitch()
        self.__sgmt_info.add_event((81,))
        e = self.__sgmt_info.complete_update(True)
        self.assertIsNone(e) # old_readers is not empty
        self.assertEqual(self.__sgmt_info.get_state(),
                         SegmentInfo.SYNCHRONIZING)
        self.assertEqual(2, self.__ver_switched)

        # b') with events, update fails
        self.__si_to_updating_state()
        self.__sgmt_info._switch_versions = lambda: count_verswitch()
        self.__sgmt_info.add_event((81,))
        self.assertEqual((81,), self.__sgmt_info.complete_update(False))
        self.assertEqual(self.__sgmt_info.get_state(), SegmentInfo.UPDATING)
        self.assertEqual(2, self.__ver_switched) # no switch

        # c) with no readers, complete_update() from UPDATING must go
        # directly to COPYING state
        self.__si_to_ready_state()
        self.__sgmt_info._switch_versions = lambda: count_verswitch()
        self.__sgmt_info.add_event((42,))
        e = self.__sgmt_info.start_update()
        self.assertTupleEqual(e, (42,))
        self.assertSetEqual(self.__sgmt_info.get_readers(), set())
        self.assertEqual(self.__sgmt_info.get_state(), SegmentInfo.UPDATING)
        e = self.__sgmt_info.complete_update(True)
        self.assertEqual(3, self.__ver_switched) # version still switched
        self.assertTupleEqual(e, (42,))
        self.assertEqual(self.__sgmt_info.get_state(), SegmentInfo.COPYING)

        # in SYNCHRONIZING state
        self.__si_to_synchronizing_state()
        self.assertRaises(SegmentInfoError,
                          self.__sgmt_info.complete_update, True)
        self.assertEqual(self.__sgmt_info.get_state(),
                         SegmentInfo.SYNCHRONIZING)

        # in COPYING state.  No version switch in this case.  no old readers
        self.__si_to_copying_state()
        e = self.__sgmt_info.complete_update(True)
        self.assertIsNone(e)
        self.assertEqual(self.__sgmt_info.get_state(), SegmentInfo.READY)
        self.assertEqual(3, self.__ver_switched)
        self.assertEqual(set(), self.__sgmt_info.get_old_readers())

        # in COPYING state on initial load.  No version switch, but move to
        # SYNCHRONIZING2 state, and the current readers are considered 'old'
        # for synchronization.
        self.__si_to_copying_state(True)
        e = self.__sgmt_info.complete_update(True)
        self.assertIsNone(e)
        self.assertEqual(self.__sgmt_info.get_state(),
                         SegmentInfo.SYNCHRONIZING2)
        self.assertEqual(3, self.__ver_switched)
        self.assertEqual(set({3}), self.__sgmt_info.get_old_readers())

        # in COPYING state with outstanding event.  It will start next update.
        self.__si_to_copying_state()
        self.__sgmt_info.add_event('x')
        self.assertEqual('x', self.__sgmt_info.complete_update(True))
        self.assertEqual(self.__sgmt_info.get_state(), SegmentInfo.UPDATING)
        self.assertEqual(3, self.__ver_switched) # no switch

    def __check_complete_validate(self, validated, with_reader):
        info = self.__create_sgmtinfo()
        info.start_validate()

        info.add_event('wopen') # dummy event, but should work
        info.add_event('1st-load') # ditto
        # Initially, the reader segment is not opened
        self.__check_sgmt_reset_param(SegmentInfo.READER, None, info)
        if with_reader:
            info.add_reader('x')

        # complete open.  next state and the returned event will depend on
        # whether we have an existing reader.
        expected_ev = None if with_reader else 'wopen'
        self.assertEqual(info.complete_validate(validated), expected_ev)
        expected_state = SegmentInfo.V_SYNCHRONIZING if with_reader else \
                         SegmentInfo.W_VALIDATING
        self.assertEqual(info.get_state(), expected_state)

        # If it succeeds, reader version will now be available,
        # should be set to the default (0).
        expected_rver = 0 if validated else None
        self.__check_sgmt_reset_param(SegmentInfo.READER, expected_rver, info)

        # completing validate in W_VALIDATING state change the state to UPDATING
        # for the initial load, regardless of whether validate succeeded.
        if expected_state == SegmentInfo.W_VALIDATING:
            self.assertEqual(info.complete_validate(validated), '1st-load')
            self.assertEqual(info.get_state(), SegmentInfo.UPDATING)

        # Calling complte_validate in other state is a bug, result in exception.
        self.assertRaises(SegmentInfoError, info.complete_validate, True)

    def test_complete_validate(self):
        self.__check_complete_validate(True, False)
        self.__check_complete_validate(False, False)
        self.__check_complete_validate(True, True)
        self.__check_complete_validate(False, True)

    # A helper for test_sync_reader(), it mostly works same for both
    # V_SYNCHRONIZING and SYNCHRONIZING states.
    def __check_sync_reader_in_sync(self, stage):
        in_validate_stage = False
        if stage == 'validation':
            init_fn = lambda: self.__si_to_vsynchronizing_state()
            in_validate_stage = True
            cur_state = SegmentInfo.V_SYNCHRONIZING
            next_state = SegmentInfo.W_VALIDATING
        elif stage in ('initial-load', 'initial-load-event'):
            init_fn = lambda: self.__si_to_synchronizing2_state()
            cur_state = SegmentInfo.SYNCHRONIZING2
            if stage == 'initial-load':
                next_state = SegmentInfo.READY
            else:
                next_state = SegmentInfo.UPDATING
        else:                   # normal update case
            init_fn = lambda: self.__si_to_synchronizing_state()
            cur_state = SegmentInfo.SYNCHRONIZING
            next_state = SegmentInfo.COPYING

        # a) ID is not in old readers set. The following call sets up ID 3
        # to be in the old readers set.
        init_fn()
        self.assertSetEqual(self.__sgmt_info.get_old_readers(), {3})
        self.assertSetEqual(self.__sgmt_info.get_readers(), set())
        self.assertRaises(SegmentInfoError, self.__sgmt_info.sync_reader, (1))
        self.assertEqual(self.__sgmt_info.get_state(), cur_state)

        # b) ID is in old readers set, but also in readers set.
        init_fn()
        self.__sgmt_info.add_reader(3)
        self.assertSetEqual(self.__sgmt_info.get_old_readers(), {3})
        self.assertSetEqual(self.__sgmt_info.get_readers(), {3})
        self.assertRaises(SegmentInfoError, self.__sgmt_info.sync_reader, (3))
        self.assertEqual(self.__sgmt_info.get_state(), cur_state)

        # c) ID is in old readers set, but not in readers set, and
        # old_readers becomes empty.
        init_fn()
        self.assertSetEqual(self.__sgmt_info.get_old_readers(), {3})
        self.assertSetEqual(self.__sgmt_info.get_readers(), set())
        if stage == 'initial-load-event':
            self.__sgmt_info.add_event(42)
            self.__sgmt_info.sync_reader(3)
            self.assertListEqual(self.__sgmt_info.get_events(), [42])
        elif stage == 'initial-load':
            self.assertIsNone(self.__sgmt_info.sync_reader(3))
        else:
            self.assertListEqual(self.__sgmt_info.get_events(), [(42,)])
            e = self.__sgmt_info.sync_reader(3)
            self.assertTupleEqual(e, (42,))
        # the ID should be moved from old readers to readers set
        self.assertSetEqual(self.__sgmt_info.get_old_readers(), set())
        self.assertSetEqual(self.__sgmt_info.get_readers(), {3})
        self.assertEqual(self.__sgmt_info.get_state(), next_state)

        # d) ID is in old readers set, but not in readers set, and
        # old_readers doesn't become empty.
        if stage == 'validation':
            self.__si_to_rvalidate_state()
            self.__sgmt_info.add_reader(3)
            self.__sgmt_info.add_event((42,))
        elif stage in ('initial-load', 'initial-load-event'):
            self.__si_to_copying_state(True)
            self.__sgmt_info.add_event((42,))
        else:
            self.__si_to_updating_state() # this also adds event of '(42,)'
        self.__sgmt_info.add_reader(4)
        if in_validate_stage:
            self.__sgmt_info.complete_validate(True)
        else:
            self.__sgmt_info.complete_update(True)
        self.assertEqual(self.__sgmt_info.get_state(), cur_state)
        self.assertSetEqual(self.__sgmt_info.get_old_readers(), {3, 4})
        self.assertSetEqual(self.__sgmt_info.get_readers(), set())
        self.assertListEqual(self.__sgmt_info.get_events(), [(42,)])
        e = self.__sgmt_info.sync_reader(3)
        self.assertIsNone(e)
        # the ID should be moved from old readers to readers set
        self.assertSetEqual(self.__sgmt_info.get_old_readers(), {4})
        self.assertSetEqual(self.__sgmt_info.get_readers(), {3})
        # we should be left in the same state
        self.assertEqual(self.__sgmt_info.get_state(), cur_state)

    def test_sync_reader(self):
        # in other states than *SYNCHRONIZING, it's no-op.
        self.__si_to_ready_state()
        self.assertIsNone(self.__sgmt_info.sync_reader(0))
        self.assertEqual(self.__sgmt_info.get_state(), SegmentInfo.READY)

        self.__si_to_updating_state()
        self.assertIsNone(self.__sgmt_info.sync_reader(0))
        self.assertEqual(self.__sgmt_info.get_state(), SegmentInfo.UPDATING)

        self.__si_to_copying_state()
        self.assertIsNone(self.__sgmt_info.sync_reader(0))
        self.assertEqual(self.__sgmt_info.get_state(), SegmentInfo.COPYING)

        # in V_SYNCHRONIZING state:
        self.__check_sync_reader_in_sync('validation')

        # in SYNCHRONIZING state:
        self.__check_sync_reader_in_sync('update')

        # in SYNCHRONIZING2 state:
        self.__check_sync_reader_in_sync('initial-load')

        # in SYNCHRONIZING2 state in the case of moving to UPDATING via READY:
        self.__check_sync_reader_in_sync('initial-load-event')

    def __check_remove_reader_in_sync(self, in_validate_stage):
        if in_validate_stage:
            init_fn = lambda: self.__si_to_vsynchronizing_state()
            cur_state = SegmentInfo.V_SYNCHRONIZING
            next_state = SegmentInfo.W_VALIDATING
        else:
            init_fn = lambda: self.__si_to_synchronizing_state()
            cur_state = SegmentInfo.SYNCHRONIZING
            next_state = SegmentInfo.COPYING

        # a) ID is not in old readers set or readers set.
        init_fn()
        self.__sgmt_info.add_reader(4)
        self.assertSetEqual(self.__sgmt_info.get_old_readers(), {3})
        self.assertSetEqual(self.__sgmt_info.get_readers(), {4})
        self.assertListEqual(self.__sgmt_info.get_events(), [(42,)])
        self.assertRaises(SegmentInfoError, self.__sgmt_info.remove_reader, (1))
        self.assertEqual(self.__sgmt_info.get_state(), cur_state)

        # b) ID is in readers set.
        init_fn()
        self.__sgmt_info.add_reader(4)
        self.assertSetEqual(self.__sgmt_info.get_old_readers(), {3})
        self.assertSetEqual(self.__sgmt_info.get_readers(), {4})
        self.assertListEqual(self.__sgmt_info.get_events(), [(42,)])
        e = self.__sgmt_info.remove_reader(4)
        self.assertIsNone(e)
        self.assertSetEqual(self.__sgmt_info.get_old_readers(), {3})
        self.assertSetEqual(self.__sgmt_info.get_readers(), set())
        self.assertListEqual(self.__sgmt_info.get_events(), [(42,)])
        # we only change state if it was removed from old_readers
        # specifically and it became empty.
        self.assertEqual(self.__sgmt_info.get_state(), cur_state)

        # c) ID is in old_readers set and it becomes empty.
        init_fn()
        self.__sgmt_info.add_reader(4)
        self.assertSetEqual(self.__sgmt_info.get_old_readers(), {3})
        self.assertSetEqual(self.__sgmt_info.get_readers(), {4})
        self.assertListEqual(self.__sgmt_info.get_events(), [(42,)])
        e = self.__sgmt_info.remove_reader(3)
        self.assertTupleEqual(e, (42,))
        self.assertSetEqual(self.__sgmt_info.get_old_readers(), set())
        self.assertSetEqual(self.__sgmt_info.get_readers(), {4})
        self.assertListEqual(self.__sgmt_info.get_events(), [])
        # we only change state if it was removed from old_readers
        # specifically and it became empty.
        self.assertEqual(self.__sgmt_info.get_state(), next_state)

        # d) ID is in old_readers set and it doesn't become empty.
        if in_validate_stage:
            self.__si_to_rvalidate_state()
            self.__sgmt_info.add_reader(3) # see __check_sync_reader_in_sync
            self.__sgmt_info.add_event((42,)) # ditto
        else:
            self.__si_to_updating_state()
        self.__sgmt_info.add_reader(4)
        if in_validate_stage:
            self.__sgmt_info.complete_validate(True)
        else:
            self.__sgmt_info.complete_update(True)
        self.__sgmt_info.add_reader(5)
        self.assertEqual(self.__sgmt_info.get_state(), cur_state)
        self.assertSetEqual(self.__sgmt_info.get_old_readers(), {3, 4})
        self.assertSetEqual(self.__sgmt_info.get_readers(), {5})
        self.assertListEqual(self.__sgmt_info.get_events(), [(42,)])
        e = self.__sgmt_info.remove_reader(3)
        self.assertIsNone(e)
        self.assertSetEqual(self.__sgmt_info.get_old_readers(), {4})
        self.assertSetEqual(self.__sgmt_info.get_readers(), {5})
        self.assertListEqual(self.__sgmt_info.get_events(), [(42,)])
        # we only change state if it was removed from old_readers
        # specifically and it became empty.
        self.assertEqual(self.__sgmt_info.get_state(), cur_state)

    def test_remove_reader(self):
        # in READY state, it should return None, unless the specified reader
        # doesn't exist.
        self.__si_to_ready_state()
        self.__sgmt_info.add_reader(4)
        self.assertRaises(SegmentInfoError, self.__sgmt_info.remove_reader, (0))
        self.assertIsNone(self.__sgmt_info.remove_reader(4))
        self.assertEqual(self.__sgmt_info.get_state(), SegmentInfo.READY)

        # Same for UPDATING state.
        self.__si_to_updating_state()
        self.__sgmt_info.add_reader(4)
        self.assertRaises(SegmentInfoError, self.__sgmt_info.remove_reader, (0))
        self.assertIsNone(self.__sgmt_info.remove_reader(4))
        self.assertEqual(self.__sgmt_info.get_state(), SegmentInfo.UPDATING)

        # Same for COPYING state.
        self.__si_to_copying_state()
        self.__sgmt_info.add_reader(4)
        self.assertRaises(SegmentInfoError, self.__sgmt_info.remove_reader, (0))
        self.assertIsNone(self.__sgmt_info.remove_reader(4))
        self.assertEqual(self.__sgmt_info.get_state(), SegmentInfo.COPYING)

        # in V_SYNCHRONIZING state:
        self.__check_remove_reader_in_sync(True)

        # in SYNCHRONIZING state:
        self.__check_remove_reader_in_sync(False)

    def test_switch_versions(self):
        self.__sgmt_info._switch_versions()
        self.__check_sgmt_reset_param(SegmentInfo.WRITER, 0)
        self.__check_sgmt_reset_param(SegmentInfo.READER, 1)

        # after switch, it should be persisted in the versions file, so a
        # newly created segment should honor that.
        sgmt_info = self.__create_sgmtinfo()
        sgmt_info.start_validate()
        sgmt_info.complete_validate(True) # to 'validate' the reader version
        self.__check_sgmt_reset_param(SegmentInfo.WRITER, 0, sgmt_info)
        self.__check_sgmt_reset_param(SegmentInfo.READER, 1, sgmt_info)

        self.__sgmt_info._switch_versions()
        self.__check_sgmt_reset_param(SegmentInfo.WRITER, 1)
        self.__check_sgmt_reset_param(SegmentInfo.READER, 0)

        sgmt_info = self.__create_sgmtinfo()
        sgmt_info.start_validate()
        sgmt_info.complete_validate(True)
        self.__check_sgmt_reset_param(SegmentInfo.WRITER, 1, sgmt_info)
        self.__check_sgmt_reset_param(SegmentInfo.READER, 0, sgmt_info)

    def test_init_others(self):
        # For local type of segment, information isn't needed and won't be
        # created.
        self.assertIsNone(SegmentInfo.create('local', 0, RRClass.IN,
                                             'sqlite3', {}))

        # Unknown type of segment will result in an exception.
        self.assertRaises(SegmentInfoError, SegmentInfo.create, 'unknown', 0,
                          RRClass.IN, 'sqlite3', {})

    def test_missing_methods(self):
        # Bad subclass of SegmentInfo that doesn't implement mandatory methods.
        class TestSegmentInfo(SegmentInfo):
            def __init__(self):
                super().__init__(0)

        self.assertRaises(SegmentInfoError,
                          TestSegmentInfo().get_reset_param,
                          SegmentInfo.WRITER)
        self.assertRaises(SegmentInfoError, TestSegmentInfo()._switch_versions)

        # remove() is not mandatory, and does nothing by default.
        TestSegmentInfo().remove() # shouldn't cause disruption

    def test_loaded(self):
        self.assertFalse(self.__sgmt_info.loaded())
        self.__si_to_rvalidate_state()
        self.assertFalse(self.__sgmt_info.loaded())
        self.__si_to_vsynchronizing_state()
        self.assertFalse(self.__sgmt_info.loaded())
        self.__si_to_updating_state(True)
        self.assertFalse(self.__sgmt_info.loaded())

        # It's considered 'loaded' on the first transition to SYNCHRONIZING2,
        # and after that it's always so.
        self.__si_to_synchronizing_state(True)
        self.assertFalse(self.__sgmt_info.loaded())
        self.__si_to_synchronizing2_state()
        self.assertTrue(self.__sgmt_info.loaded())
        self.__si_to_copying_state()
        self.assertTrue(self.__sgmt_info.loaded())

    def test_remove(self):
        # it's okay to call remove() without any files to remove
        self.__sgmt_info.remove()

        # create (empty) files that would be considered to be cleaned up on
        # remove.
        files = [self.__ver_file, '%s%d' % (self.__mapped_file_base, 0),
                 '%s%d' % (self.__mapped_file_base, 1)]
        for f in files:
            with open(f, 'w'): pass
            self.assertTrue(os.path.exists(f))

        # Failure case: shouldn't crash, and the files still exist.
        def raise_exception(arg):
            raise ValueError('test error')
        os.unlink = raise_exception
        self.__sgmt_info.remove()
        for f in files:
            self.assertTrue(os.path.exists(f))

        # Normal case: all files should be removed.
        os.unlink = self.__orig_unlink
        self.__sgmt_info.remove()
        for f in files:
            self.assertFalse(os.path.exists(f))

class MockClientList:
    """A mock ConfigurableClientList class.

    Just providing minimal shortcut interfaces needed for DataSrcInfo class.

    """
    def __init__(self, status_list):
        self.__status_list = status_list

    def get_status(self):
        return self.__status_list

class TestDataSrcInfo(unittest.TestCase):
    def setUp(self):
        self.__orig_sgmtinfo_create = SegmentInfo.create
        self.__mapped_file_dir = os.environ['TESTDATA_WRITE_PATH']
        self.__mgr_config = {'mapped_file_dir': self.__mapped_file_dir}
        self.__sqlite3_dbfile = os.environ['TESTDATA_WRITE_PATH'] + '/' + \
                                'zone.db'
        self.__clients_map = {
            # mixture of 'local' and 'mapped' and 'unused' (type =None)
            # segments
            RRClass.IN: MockClientList([('datasrc1', 'local', None),
                                        ('datasrc2', 'mapped', None),
                                        ('datasrc3', None, None)]),
            RRClass.CH: MockClientList([('datasrc2', 'mapped', None),
                                        ('datasrc1', 'local', None)]) }

    def tearDown(self):
        SegmentInfo.create = self.__orig_sgmtinfo_create
        if os.path.exists(self.__sqlite3_dbfile):
            os.unlink(self.__sqlite3_dbfile)

    def __check_sgmt_reset_param(self, sgmt_info, reader_file, writer_file):
        # Check if the initial state of (mapped) segment info object has
        # expected values.
        param = sgmt_info.get_reset_param(SegmentInfo.READER)
        self.assertEqual(reader_file, param['mapped-file'])
        param = sgmt_info.get_reset_param(SegmentInfo.WRITER)
        self.assertEqual(writer_file, param['mapped-file'])

    def test_init(self):
        """Check basic scenarios of constructing DataSrcInfo."""

        # This checks that all data sources of all RR classes are covered,
        # "local" segments are ignored, info objects for "mapped" segments
        # are created and stored in segment_info_map.
        datasrc_info = DataSrcInfo(42, self.__clients_map, self.__mgr_config)
        self.assertEqual(42, datasrc_info.gen_id)
        self.assertEqual(self.__clients_map, datasrc_info.clients_map)
        self.assertEqual(2, len(datasrc_info.segment_info_map))
        sgmt_info = datasrc_info.segment_info_map[(RRClass.IN, 'datasrc2')]

        # by default, reader mapped file isn't available yet, but writer's
        # version is 1.
        base = self.__mapped_file_dir + '/zone-IN-42-datasrc2-mapped.'
        self.__check_sgmt_reset_param(sgmt_info, None, base + '1')
        sgmt_info = datasrc_info.segment_info_map[(RRClass.CH, 'datasrc2')]
        base = self.__mapped_file_dir + '/zone-CH-42-datasrc2-mapped.'
        self.__check_sgmt_reset_param(sgmt_info, None, base + '1')

        # A case where clist.get_status() returns an empty list; shouldn't
        # cause disruption
        self.__clients_map = { RRClass.IN: MockClientList([])}
        datasrc_info = DataSrcInfo(42, self.__clients_map, self.__mgr_config)
        self.assertEqual(42, datasrc_info.gen_id)
        self.assertEqual(0, len(datasrc_info.segment_info_map))

        # A case where clients_map is empty; shouldn't cause disruption
        self.__clients_map = {}
        datasrc_info = DataSrcInfo(42, self.__clients_map, self.__mgr_config)
        self.assertEqual(42, datasrc_info.gen_id)
        self.assertEqual(0, len(datasrc_info.segment_info_map))

    # This test uses real "mmaped" segment and doesn't work without shared
    # memory support.
    @unittest.skipIf(os.environ['HAVE_SHARED_MEMORY'] != 'yes',
                     'shared memory support is not available')
    def test_production(self):
        """Check the behavior closer to a production environment.

        Instead of using mock classes, just for confirming we didn't miss
        something.

        """
        cfg_data = MockConfigData(
            {"_generation_id": 1,
             "classes":
                 {"IN": [{"type": "sqlite3", "cache-enable": True,
                          "cache-type": "mapped", "cache-zones": [],
                          "params": {"database_file": self.__sqlite3_dbfile}}]
                  }
             })
        cmgr = DataSrcClientsMgr(use_cache=True)
        cmgr.reconfigure({}, cfg_data)

        genid, clients_map = cmgr.get_clients_map()
        datasrc_info = DataSrcInfo(genid, clients_map, self.__mgr_config)

        self.assertEqual(1, datasrc_info.gen_id)
        self.assertEqual(clients_map, datasrc_info.clients_map)
        self.assertEqual(1, len(datasrc_info.segment_info_map))
        sgmt_info = datasrc_info.segment_info_map[(RRClass.IN, 'sqlite3')]
        self.assertIsNotNone(sgmt_info.get_reset_param(SegmentInfo.READER))

    def test_cancel(self):
        removed_segments = []
        # Fake segment info to be used for tests, overriding some public
        # methods for easier testing.
        class TestSegmentInfo(SegmentInfo):
            def __init__(self, *args):
                self.readers = set()
                self.old_readers = set()
            def remove(self):
                removed_segments.append(self)
            def get_readers(self):
                return self.readers
            def get_old_readers(self):
                return self.old_readers
            def remove_reader(self, reader):
                if reader in self.readers:
                    self.readers.remove(reader)
                else:
                    self.old_readers.remove(reader)
        # Fake the factory method so the faked SegmentInfo will be used.
        SegmentInfo.create = lambda type, genid, c, d, e: \
                TestSegmentInfo(genid) if type == 'mapped' else None

        def check_canceled(expected_canceled):
            if expected_canceled:
                self.assertEqual(set(), dsrc_info.cancel(None))
                self.assertEqual({}, dsrc_info.clients_map)
                self.assertEqual({}, dsrc_info.segment_info_map)
                self.assertEqual(2, len(removed_segments))
            else:
                self.assertNotEqual(set(), dsrc_info.cancel(None))
                self.assertNotEqual({}, dsrc_info.clients_map)
                self.assertNotEqual({}, dsrc_info.segment_info_map)
                self.assertEqual(0, len(removed_segments))

        # By default there's no reader for any segment.  So we can immediately
        # cancel the whole generation.
        dsrc_info = DataSrcInfo(42, self.__clients_map, self.__mgr_config)
        check_canceled(True)

        # Set up segment info with some readers.  Every time cancel() is called
        # with a reader, a set of the remaining readers will be returned (and
        # cancel isn't completed), and when all readers are removed the cancel
        # will be completed.
        del removed_segments[:]
        dsrc_info = DataSrcInfo(42, self.__clients_map, self.__mgr_config)
        dsrc_info.segment_info_map[(RRClass.IN, 'datasrc2')].readers.update(
            {'a', 'b'})
        dsrc_info.segment_info_map[(RRClass.CH, 'datasrc2')].readers.update(
            {'c'})
        dsrc_info.segment_info_map[(RRClass.CH, 'datasrc2')].old_readers.update(
            {'b'})
        self.assertEqual(set({'a', 'b', 'c'}), dsrc_info.cancel(None))
        check_canceled(False)
        self.assertEqual(set({'a', 'c'}), dsrc_info.cancel('b'))
        check_canceled(False)
        # Call cancel with a non-existent reader is no-op (no disruption)
        self.assertEqual(set({'a', 'c'}), dsrc_info.cancel('d'))
        check_canceled(False)
        self.assertEqual(set({'c'}), dsrc_info.cancel('a'))
        check_canceled(False)
        self.assertEqual(set(), dsrc_info.cancel('c'))
        check_canceled(True)

if __name__ == "__main__":
    bundy.log.init("bundy-test")
    bundy.log.resetUnitTestRootLogger()
    unittest.main()
