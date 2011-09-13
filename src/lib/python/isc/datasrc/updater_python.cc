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

// Enable this if you use s# variants with PyArg_ParseTuple(), see
// http://docs.python.org/py3k/c-api/arg.html#strings-and-buffers
//#define PY_SSIZE_T_CLEAN

// Python.h needs to be placed at the head of the program file, see:
// http://docs.python.org/py3k/extending/extending.html#a-simple-example
#include <Python.h>

#include <string>
#include <stdexcept>

#include <util/python/pycppwrapper_util.h>

#include <datasrc/client.h>
#include <datasrc/database.h>
#include <datasrc/sqlite3_accessor.h>
#include <datasrc/zone.h>

#include <dns/python/name_python.h>
#include <dns/python/rrset_python.h>

#include "datasrc.h"
#include "updater_python.h"

using namespace std;
using namespace isc::util::python;
using namespace isc::datasrc;
using namespace isc::datasrc::python;

//
// Definition of the classes
//

// For each class, we need a struct, a helper functions (init, destroy,
// and static wrappers around the methods we export), a list of methods,
// and a type description

//
// Zone Updater
//

// Trivial constructor.
s_ZoneUpdater::s_ZoneUpdater() : cppobj(ZoneUpdaterPtr()) {
}

namespace {
// Shortcut type which would be convenient for adding class variables safely.
typedef CPPPyObjectContainer<s_ZoneUpdater, ZoneUpdater> ZoneUpdaterContainer;

//
// We declare the functions here, the definitions are below
// the type definition of the object, since both can use the other
//

// General creation and destruction
int ZoneUpdater_init(s_ZoneUpdater* self, PyObject* args);
void ZoneUpdater_destroy(s_ZoneUpdater* self);

// These are the functions we export
//
PyObject* ZoneUpdater_AddRRset(PyObject* po_self, PyObject* args) {
    // TODO err handling
    s_ZoneUpdater* const self = static_cast<s_ZoneUpdater*>(po_self);
    PyObject* rrset_obj;
    if (PyArg_ParseTuple(args, "O!", &isc::dns::python::rrset_type, &rrset_obj)) {
        self->cppobj->addRRset(isc::dns::python::PyRRset_ToRRset(rrset_obj));
        Py_RETURN_NONE;
    } else {
        return (NULL);
    }
}

PyObject* ZoneUpdater_DeleteRRset(PyObject* po_self, PyObject* args) {
    // TODO err handling
    s_ZoneUpdater* const self = static_cast<s_ZoneUpdater*>(po_self);
    PyObject* rrset_obj;
    if (PyArg_ParseTuple(args, "O!", &isc::dns::python::rrset_type, &rrset_obj)) {
        self->cppobj->deleteRRset(isc::dns::python::PyRRset_ToRRset(rrset_obj));
        Py_RETURN_NONE;
    } else {
        return (NULL);
    }
}

PyObject* ZoneUpdater_Commit(PyObject* po_self, PyObject*) {
    s_ZoneUpdater* const self = static_cast<s_ZoneUpdater*>(po_self);
    self->cppobj->commit();
    Py_RETURN_NONE;
}


// These are the functions we export
// For a minimal support, we don't need them.

// This list contains the actual set of functions we have in
// python. Each entry has
// 1. Python method name
// 2. Our static function here
// 3. Argument type
// 4. Documentation
PyMethodDef ZoneUpdater_methods[] = {
/*    { "get_finder", ZoneUpdater_GetFinder, METH_NOARGS, "TODO" },*/
    { "add_rrset", ZoneUpdater_AddRRset, METH_VARARGS, "TODO" },
    { "delete_rrset", ZoneUpdater_DeleteRRset, METH_VARARGS, "TODO" },
    { "commit", ZoneUpdater_Commit, METH_NOARGS, "TODO" },
    { NULL, NULL, 0, NULL }
};

// This is a template of typical code logic of python class initialization
// with C++ backend.  You'll need to adjust it according to details of the
// actual C++ class.
int
ZoneUpdater_init(s_ZoneUpdater* self, PyObject* args) {
    // can't be called directly
    PyErr_SetString(PyExc_TypeError,
                    "ZoneUpdater cannot be constructed directly");

    return (-1);
}

// This is a template of typical code logic of python object destructor.
// In many cases you can use it without modification, but check that carefully.
void
ZoneUpdater_destroy(s_ZoneUpdater* const self) {
    //delete self->cppobj;
    //self->cppobj = NULL;
    Py_TYPE(self)->tp_free(self);
}

} // end of unnamed namespace

namespace isc {
namespace datasrc {
namespace python {
PyTypeObject zoneupdater_type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "datasrc.ZoneUpdater",
    sizeof(s_ZoneUpdater),             // tp_basicsize
    0,                                  // tp_itemsize
    reinterpret_cast<destructor>(ZoneUpdater_destroy),       // tp_dealloc
    NULL,                               // tp_print
    NULL,                               // tp_getattr
    NULL,                               // tp_setattr
    NULL,                               // tp_reserved
    NULL,                               // tp_repr
    NULL,                               // tp_as_number
    NULL,                               // tp_as_sequence
    NULL,                               // tp_as_mapping
    NULL,                               // tp_hash
    NULL,                               // tp_call
    NULL,                               // tp_str
    NULL,                               // tp_getattro
    NULL,                               // tp_setattro
    NULL,                               // tp_as_buffer
    Py_TPFLAGS_DEFAULT,                 // tp_flags
    "The ZoneUpdater class objects is...(TODO COMPLETE THIS)",
    NULL,                               // tp_traverse
    NULL,                               // tp_clear
    NULL,                               // tp_richcompare
    0,                                  // tp_weaklistoffset
    NULL,                               // tp_iter
    NULL,                               // tp_iternext
    ZoneUpdater_methods,               // tp_methods
    NULL,                               // tp_members
    NULL,                               // tp_getset
    NULL,                               // tp_base
    NULL,                               // tp_dict
    NULL,                               // tp_descr_get
    NULL,                               // tp_descr_set
    0,                                  // tp_dictoffset
    reinterpret_cast<initproc>(ZoneUpdater_init),// tp_init
    NULL,                               // tp_alloc
    PyType_GenericNew,                  // tp_new
    NULL,                               // tp_free
    NULL,                               // tp_is_gc
    NULL,                               // tp_bases
    NULL,                               // tp_mro
    NULL,                               // tp_cache
    NULL,                               // tp_subclasses
    NULL,                               // tp_weaklist
    NULL,                               // tp_del
    0                                   // tp_version_tag
};

// Module Initialization, all statics are initialized here
bool
initModulePart_ZoneUpdater(PyObject* mod) {
    // We initialize the static description object with PyType_Ready(),
    // then add it to the module. This is not just a check! (leaving
    // this out results in segmentation faults)
    if (PyType_Ready(&zoneupdater_type) < 0) {
        return (false);
    }
    void* zip = &zoneupdater_type;
    if (PyModule_AddObject(mod, "ZoneUpdater", static_cast<PyObject*>(zip)) < 0) {
        return (false);
    }
    Py_INCREF(&zoneupdater_type);

    return (true);
}

PyObject*
createZoneUpdaterObject(isc::datasrc::ZoneUpdaterPtr source) {
    s_ZoneUpdater* py_zi = static_cast<s_ZoneUpdater*>(
        zoneupdater_type.tp_alloc(&zoneupdater_type, 0));
    if (py_zi != NULL) {
        py_zi->cppobj = source;
    }
    return (py_zi);
}

} // namespace python
} // namespace datasrc
} // namespace isc

