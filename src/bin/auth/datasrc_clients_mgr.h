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

#ifndef DATASRC_CLIENTS_MGR_H
#define DATASRC_CLIENTS_MGR_H 1

#include <util/threads/thread.h>
#include <util/threads/sync.h>

#include <log/logger_support.h>
#include <log/log_dbglevels.h>

#include <dns/rrclass.h>

#include <cc/data.h>

#include <datasrc/exceptions.h>
#include <datasrc/client_list.h>
#include <datasrc/memory/zone_writer.h>

#include <asiolink/io_service.h>
#include <asiolink/local_socket.h>

#include <auth/auth_log.h>
#include <auth/datasrc_config.h>

#include <boost/array.hpp>
#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/noncopyable.hpp>
#include <boost/function.hpp>
#include <boost/foreach.hpp>

#include <exception>
#include <cassert>
#include <cerrno>
#include <list>
#include <utility>
#include <sys/types.h>
#include <sys/socket.h>

namespace bundy {
namespace auth {

/// \brief An exception that is thrown if initial checks for a command fail
///
/// This is raised *before* the command to the thread is constructed and
/// sent, so the application can still handle them (and therefore it is
/// public, as opposed to InternalCommandError).
///
/// And example of its use is currently in loadZone().
class CommandError : public bundy::Exception {
public:
    CommandError(const char* file, size_t line, const char* what) :
        bundy::Exception(file, line, what) {}
};

namespace datasrc_clientmgr_internal {
// This namespace is essentially private for DataSrcClientsMgr(Base) and
// DataSrcClientsBuilder(Base).  This is exposed in the public header
// only because these classes are templated (for testing purposes) and
// class internal has to be defined here.

/// \brief ID of commands from the DataSrcClientsMgr to DataSrcClientsBuilder.
enum CommandID {
    NOOP,         ///< Do nothing.  Only useful for tests; no argument
    RECONFIGURE,  ///< Reconfigure the datasource client lists,
                  ///  the argument to the command is the full new
                  ///  datasources configuration.
    LOADZONE,     ///< Load a new version of zone into a memory,
                  ///  the argument to the command is a map containing 'class'
                  ///  and 'origin' elements, both should have been validated.
    UPDATEZONE,   ///< Similar to LOADZONE, but is intended to be used for
                  ///  internal notification from other modules.  It takes
                  ///  specific data source name where the updated zone is
                  ///  expected to belong.  It also silently ignores the command
                  ///  if the underlying memory segment is not writable
                  ///  (implicitly assuming it's shared-memory based and is
                  ///  updated by another module).
    SEGMENT_INFO_UPDATE, ///< The memory manager sent an update about segments.
    SHUTDOWN,     ///< Shutdown the builder; no argument
    NUM_COMMANDS
};

/// \brief Callback to be called when the command is completed.
///
/// It takes an argument of \c ConstElementPtr.  Specific content of \c arg
/// varies for each callback.
typedef boost::function<void (data::ConstElementPtr arg)> FinishedCallback;

/// \brief A pair of the callback functor and its argument.
typedef std::pair<FinishedCallback, data::ConstElementPtr> FinishedCallbackPair;

/// \brief The data type passed from DataSrcClientsMgr to
///     DataSrcClientsBuilder.
///
/// This just holds the data items together, no logic or protection
/// is present here.
struct Command {
    /// \brief Constructor
    ///
    /// It just initializes the member variables of the same names
    /// as the parameters.
    Command(CommandID id, const data::ConstElementPtr& params,
            const FinishedCallback& callback) :
        id(id),
        params(params),
        callback(callback)
    {}
    /// \brief The command to execute
    CommandID id;
    /// \brief Argument of the command.
    ///
    /// If the command takes no argument, it should be null pointer.
    ///
    /// This may be a null pointer if the command takes no parameters.
    data::ConstElementPtr params;
    /// \brief A callback to be called once the command finishes.
    ///
    /// This may be an empty boost::function. In such case, no callback
    /// will be called after completion.
    FinishedCallback callback;
};

} // namespace datasrc_clientmgr_internal

/// \brief Frontend to the manager object for data source clients.
///
/// This class provides interfaces for configuring and updating a set of
/// data source clients "in the background".  The user of this class can
/// assume any operation on this class can be done effectively non-blocking,
/// not suspending any delay-sensitive operations such as DNS query
/// processing.  The only exception is the time when this class object
/// is destroyed (normally as a result of an implicit call to the destructor);
/// in the current implementation it can take time depending on what is
/// running "in the background" at the time of the call.
///
/// Internally, an object of this class invokes a separate thread to perform
/// time consuming operations such as loading large zone data into memory,
/// but such details are completely hidden from the user of this class.
///
/// This class is templated only so that we can test the class without
/// involving actual threads or mutex.  Normal applications will only
/// need one specific specialization that has a typedef of
/// \c DataSrcClientsMgr.
template <typename ThreadType, typename BuilderType, typename MutexType,
          typename CondVarType>
class DataSrcClientsMgrBase : boost::noncopyable {
private:
    typedef std::map<dns::RRClass,
                     boost::shared_ptr<datasrc::ConfigurableClientList> >
    ClientListsMap;

    class FDGuard : boost::noncopyable {
    public:
        FDGuard(DataSrcClientsMgrBase *mgr) :
            mgr_(mgr)
        {}
        ~FDGuard() {
            if (mgr_->read_fd_ != -1) {
                close(mgr_->read_fd_);
            }
            if (mgr_->write_fd_ != -1) {
                close(mgr_->write_fd_);
            }
        }
    private:
        DataSrcClientsMgrBase* mgr_;
    };
    friend class FDGuard;

public:
    /// \brief Thread-safe accessor to the data source client lists.
    ///
    /// This class provides a simple wrapper for searching the client lists
    /// stored in the DataSrcClientsMgr in a thread-safe manner.
    /// It ensures the result of \c getClientList() can be used without
    /// causing a race condition with other threads that can possibly use
    /// the same manager throughout the lifetime of the holder object.
    ///
    /// This also means the holder object is expected to have a short lifetime.
    /// The application shouldn't try to keep it unnecessarily long.
    /// It's normally expected to create the holder object on the stack
    /// of a small scope and automatically let it be destroyed at the end
    /// of the scope.
    class Holder {
    public:
        Holder(DataSrcClientsMgrBase& mgr) :
            mgr_(mgr), locker_(mgr_.map_mutex_)
        {}

        /// \brief Find a data source client list of a specified RR class.
        ///
        /// It returns a pointer to the list stored in the manager if found,
        /// otherwise it returns NULL.  The manager keeps the ownership of
        /// the pointed object.  Also, it's not safe to get access to the
        /// object beyond the scope of the holder object.
        ///
        /// \note Since the ownership isn't transferred the return value
        /// could be a bare pointer (and it's probably better in several
        /// points).  Unfortunately, some unit tests currently don't work
        /// unless this method effectively shares the ownership with the
        /// tests.  That's the only reason why we return a shared pointer
        /// for now.  We should eventually fix it and change the return value
        /// type (see Trac ticket #2395).  Other applications must not
        /// assume the ownership is actually shared.
        boost::shared_ptr<datasrc::ConfigurableClientList> findClientList(
            const dns::RRClass& rrclass)
        {
            const ClientListsMap::const_iterator
                it = mgr_.clients_map_->find(rrclass);
            if (it == mgr_.clients_map_->end()) {
                return (boost::shared_ptr<datasrc::ConfigurableClientList>());
            } else {
                return (it->second);
            }
        }
        /// \brief Return list of classes that are present.
        ///
        /// Get the list of classes for which there's a client list. It is
        /// returned in form of a vector, copied from the internals. As the
        /// number of classes in there is expected to be small, it is not
        /// a performance issue.
        ///
        /// \return The list of classes.
        /// \throw std::bad_alloc for problems allocating the result.
        std::vector<dns::RRClass> getClasses() const {
            std::vector<dns::RRClass> result;
            for (ClientListsMap::const_iterator it =
                 mgr_.clients_map_->begin(); it != mgr_.clients_map_->end();
                 ++it) {
                result.push_back(it->first);
            }
            return (result);
        }
    private:
        DataSrcClientsMgrBase& mgr_;
        typename MutexType::Locker locker_;
    };

    /// \brief Constructor.
    ///
    /// It internally invokes a separate thread and waits for further
    /// operations from the user application.
    ///
    /// This method is basically exception free except in case of really
    /// rare system-level errors.  When that happens the only reasonable
    /// action that the application can take would be to terminate the program
    /// in practice.
    ///
    /// \throw std::bad_alloc internal memory allocation failure.
    /// \throw bundy::Unexpected general unexpected system errors.
    DataSrcClientsMgrBase(asiolink::IOService& service) :
        clients_map_(new ClientListsMap),
        fd_guard_(new FDGuard(this)),
        read_fd_(-1), write_fd_(-1),
        builder_(&command_queue_, &callback_queue_, &cond_, &queue_mutex_,
                 &clients_map_, &map_mutex_, createFds()),
        builder_thread_(boost::bind(&BuilderType::run, &builder_)),
        wakeup_socket_(service, read_fd_)
    {
        // Schedule wakeups when callbacks are pushed.
        wakeup_socket_.asyncRead(
            boost::bind(&DataSrcClientsMgrBase::processCallbacks, this, _1),
            buffer, 1);
    }

    /// \brief The destructor.
    ///
    /// It tells the internal thread to stop and waits for it completion.
    /// In the current implementation, it can block for some unpredictably
    /// long period depending on what the thread is doing at that time
    /// (in future we may want to implement a rapid way of killing the thread
    /// and/or provide a separate interface for waiting so that the application
    /// can choose the timing).
    ///
    /// The waiting operation can result in an exception, but this method
    /// catches any of them so this method itself is exception free.
    ~DataSrcClientsMgrBase() {
        // We share class member variables with the builder, which will be
        // invalidated after the call to the destructor, so we need to make
        // sure the builder thread is terminated.  Depending on the timing
        // this could take a long time; if we don't want that to happen in
        // this context, we may want to introduce a separate 'shutdown()'
        // method.
        // Also, since we don't want to propagate exceptions from a destructor,
        // we catch any possible ones.  In fact the only really expected one
        // is Thread::UncaughtException when the builder thread died due to
        // an exception.  We specifically log it and just ignore others.
        try {
            sendCommand(datasrc_clientmgr_internal::SHUTDOWN,
                        data::ConstElementPtr());
            builder_thread_.wait();
        } catch (const util::thread::Thread::UncaughtException& ex) {
            // technically, logging this could throw, which will be propagated.
            // But such an exception would be a fatal one anyway, so we
            // simply let it go through.
            LOG_ERROR(auth_logger, AUTH_DATASRC_CLIENTS_SHUTDOWN_ERROR).
                arg(ex.what());
        } catch (...) {
            LOG_ERROR(auth_logger,
                      AUTH_DATASRC_CLIENTS_SHUTDOWN_UNEXPECTED_ERROR);
        }

        processCallbacks(); // Any leftover callbacks
        cleanup();              // see below
    }

    /// \brief Handle new full configuration for data source clients.
    ///
    /// This method simply passes the new configuration to the builder
    /// and immediately returns.  This method is basically exception free
    /// as long as the caller passes a non NULL value for \c config_arg;
    /// it doesn't validate the argument further.
    ///
    /// \brief bundy::InvalidParameter config_arg is NULL.
    /// \brief std::bad_alloc
    ///
    /// \param config_arg The new data source configuration.  Must not be NULL.
    /// \param callback Called once the reconfigure command completes. It is
    ///     called in the main thread (not in the work one). It should be
    ///     exceptionless.
    void reconfigure(const data::ConstElementPtr& config_arg,
                     const datasrc_clientmgr_internal::FinishedCallback&
                     callback = datasrc_clientmgr_internal::FinishedCallback())
    {
        if (!config_arg) {
            bundy_throw(InvalidParameter, "Invalid null config argument");
        }
        sendCommand(datasrc_clientmgr_internal::RECONFIGURE, config_arg,
                    callback);
        reconfigureHook();      // for test's customization
    }

    /// \brief Set the underlying data source client lists to new lists.
    ///
    /// This is provided only for some existing tests until we support a
    /// cleaner way to use faked data source clients.  Non test code or
    /// newer tests must not use this.
    void setDataSrcClientLists(datasrc::ClientListMapPtr new_lists) {
        typename MutexType::Locker locker(map_mutex_);
        clients_map_ = new_lists;
    }

    /// \brief Instruct internal thread to (re)load a zone
    ///
    /// \param args Element argument that should be a map of the form
    /// { "class": "IN", "origin": "example.com" }
    /// (but class is optional and will default to IN)
    /// \param callback Called once the loadZone command completes. It
    ///     is called in the main thread, not in the work thread. It should
    ///     be exceptionless.
    ///
    /// \exception CommandError if the args value is null, or not in
    ///                                 the expected format, or contains
    ///                                 a bad origin or class string
    void
    loadZone(const data::ConstElementPtr& args,
             const datasrc_clientmgr_internal::FinishedCallback& callback =
             datasrc_clientmgr_internal::FinishedCallback())
    {
        updateZoneInternal(datasrc_clientmgr_internal::LOADZONE, args,
                           callback);
    }

    void updateZone(const data::ConstElementPtr& args) {
        updateZoneInternal(datasrc_clientmgr_internal::UPDATEZONE, args,
                           datasrc_clientmgr_internal::FinishedCallback());
    }

    void segmentInfoUpdate(const data::ConstElementPtr& args,
                           const datasrc_clientmgr_internal::FinishedCallback&
                           callback =
                           datasrc_clientmgr_internal::FinishedCallback()) {
        // Some minimal validation
        if (!args) {
            bundy_throw(CommandError, "segmentInfoUpdate argument empty");
        }
        if (args->getType() != bundy::data::Element::map) {
            bundy_throw(CommandError, "segmentInfoUpdate argument not a map");
        }
        const char* params[] = {
            "data-source-name",
            "data-source-class",
            "segment-params",
            "generation-id",
            NULL
        };
        for (const char** param = params; *param; ++param) {
            if (!args->contains(*param)) {
                bundy_throw(CommandError,
                          "segmentInfoUpdate argument has no '" << param <<
                          "' value");
            }
        }

        sendCommand(datasrc_clientmgr_internal::SEGMENT_INFO_UPDATE, args,
                    callback);
    }

private:
    // This is expected to be called at the end of the destructor.  It
    // actually does nothing, but provides a customization point for
    // specialized class for tests so that the tests can inspect the last
    // state of the class.
    void cleanup() {}

    // Common handler for LOADZONE and UPDATEZONE.
    void updateZoneInternal(datasrc_clientmgr_internal::CommandID command,
                            const data::ConstElementPtr& args,
                            const datasrc_clientmgr_internal::FinishedCallback&
                            callback)
    {
        const std::string& command_str =
            (command == datasrc_clientmgr_internal::LOADZONE) ?
            "loadZone" : "updateZone";

        if (!args) {
            bundy_throw(CommandError, command_str + " argument empty");
        }

        if (args->getType() != bundy::data::Element::map) {
            bundy_throw(CommandError, command_str + " argument not a map");
        }
        if (!args->contains("origin")) {
            bundy_throw(CommandError,
                      command_str + " argument has no 'origin' value");
        }
        // Also check if it really is a valid name
        try {
            dns::Name(args->get("origin")->stringValue());
        } catch (const bundy::Exception& exc) {
            bundy_throw(CommandError, "bad origin: " << exc.what());
        }

        if (args->get("origin")->getType() != data::Element::string) {
            bundy_throw(CommandError,
                      "loadZone argument 'origin' value not a string");
        }
        if (args->contains("class")) {
            if (args->get("class")->getType() != data::Element::string) {
                bundy_throw(CommandError,
                          "loadZone argument 'class' value not a string");
            }
            // Also check if it is a valid class
            try {
                dns::RRClass(args->get("class")->stringValue());
            } catch (const bundy::Exception& exc) {
                bundy_throw(CommandError, "bad class: " << exc.what());
            }
        }
        // If "datasource" is provided as a parameter, it must be a string.
        // For UPDATEZONE, datasource must be specified.
        if (args->contains("datasource")) {
            if (args->get("datasource")->getType() !=
                bundy::data::Element::string)
            {
                bundy_throw(CommandError,
                          "invalid type for datasource (must be string)");
            }
        } else if (command == datasrc_clientmgr_internal::UPDATEZONE) {
                bundy_throw(CommandError, "missing datasource for UPDATEZONE");
        }

        // Note: we could do some more advanced checks here,
        // e.g. check if the zone is known at all in the configuration.
        // For now these are skipped, but one obvious way to
        // implement it would be to factor out the code from
        // the start of doUpdateZone(), and call it here too

        sendCommand(command, args, callback);
    }

    // same as cleanup(), for reconfigure().
    void reconfigureHook() {}

    void sendCommand(datasrc_clientmgr_internal::CommandID command,
                     const data::ConstElementPtr& arg,
                     const datasrc_clientmgr_internal::FinishedCallback&
                     callback = datasrc_clientmgr_internal::FinishedCallback())
    {
        // The lock will be held until the end of this method.  Only
        // push_back has to be protected, but we can avoid having an extra
        // block this way.
        typename MutexType::Locker locker(queue_mutex_);
        command_queue_.push_back(
            datasrc_clientmgr_internal::Command(command, arg, callback));
        cond_.signal();
    }

    int createFds() {
        int fds[2];
        int result = socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
        if (result != 0) {
            bundy_throw(Unexpected, "Can't create socket pair: " <<
                      strerror(errno));
        }
        read_fd_ = fds[0];
        write_fd_ = fds[1];
        return write_fd_;
    }

    void processCallbacks(const std::string& error = std::string()) {
        // Schedule the next read.
        wakeup_socket_.asyncRead(
            boost::bind(&DataSrcClientsMgrBase::processCallbacks, this, _1),
            buffer, 1);
        if (!error.empty()) {
            // Generally, there should be no errors (as we are the other end
            // as well), but check just in case.
            bundy_throw(Unexpected, error);
        }

        // Steal the callbacks into local copy.
        std::list<datasrc_clientmgr_internal::FinishedCallbackPair> queue;
        {
            typename MutexType::Locker locker(queue_mutex_);
            queue.swap(callback_queue_);
        }

        // Execute the callbacks
        BOOST_FOREACH(const datasrc_clientmgr_internal::FinishedCallbackPair&
                      cbpair, queue) {
            cbpair.first(cbpair.second);
        }
    }

    //
    // The following are shared with the builder.
    //
    // The list is used as a one-way queue: back-in, front-out
    std::list<datasrc_clientmgr_internal::Command> command_queue_;
    // Similar to above, for the callbacks that are ready to be called.
    // While the command queue is for sending commands from the main thread
    // to the work thread, this one is for the other direction. Protected
    // by the same mutex (queue_mutex_).
    std::list<datasrc_clientmgr_internal::FinishedCallbackPair> callback_queue_;
    CondVarType cond_;          // condition variable for queue operations
    MutexType queue_mutex_;     // mutex to protect the queue
    datasrc::ClientListMapPtr clients_map_;
                                // map of actual data source client objects
    boost::scoped_ptr<FDGuard> fd_guard_; // A guard to close the fds.
    int read_fd_, write_fd_;    // Descriptors for wakeup
    MutexType map_mutex_;       // mutex to protect the clients map

    BuilderType builder_;
    ThreadType builder_thread_; // for safety this should be placed last
    bundy::asiolink::LocalSocket wakeup_socket_; // For integration of read_fd_
                                               // to the asio loop
    char buffer[1];   // Buffer for the wakeup socket.
};

namespace datasrc_clientmgr_internal {

/// \brief A class that maintains a set of data source clients.
///
/// An object of this class is supposed to run on a dedicated thread, whose
/// main function is a call to its \c run() method.  It runs in a loop
/// waiting for commands from the manager and handles each command (including
/// reloading a new version of zone data into memory or fully reconfiguration
/// of specific set of data source clients).  When it receives a SHUTDOWN
/// command, it exits from the loop, which will terminate the thread.
///
/// While this class is defined in a publicly visible namespace, it's
/// essentially private to \c DataSrcClientsMgr.  Except for tests,
/// applications should not directly access this class.
///
/// This class is templated so that we can test it without involving actual
/// threads or locks.
template <typename MutexType, typename CondVarType>
class DataSrcClientsBuilderBase : boost::noncopyable {
private:
    typedef std::map<dns::RRClass,
                     boost::shared_ptr<datasrc::ConfigurableClientList> >
    ClientListsMap;

public:
    /// \brief Internal errors in handling commands.
    ///
    /// This exception is expected to be caught within the
    /// \c DataSrcClientsBuilder implementation, but is defined as public
    /// so tests can be checked it.
    class InternalCommandError : public bundy::Exception {
    public:
        InternalCommandError(const char* file, size_t line, const char* what) :
            bundy::Exception(file, line, what) {}
    };

    /// \brief Constructor.
    ///
    /// It simply sets up a local copy of shared data with the manager.
    ///
    /// \throw None
    DataSrcClientsBuilderBase(std::list<Command>* command_queue,
                              std::list<FinishedCallbackPair>* callback_queue,
                              CondVarType* cond, MutexType* queue_mutex,
                              datasrc::ClientListMapPtr* clients_map,
                              MutexType* map_mutex,
                              int wake_fd
        ) :
        command_queue_(command_queue), callback_queue_(callback_queue),
        cond_(cond), queue_mutex_(queue_mutex),
        clients_map_(clients_map), map_mutex_(map_mutex), wake_fd_(wake_fd),
        gen_id_(-1)
    {}

    /// \brief The main loop.
    void run();

    /// \brief Handle one command from the manager.
    ///
    /// This is a dedicated subroutine of run() and is essentially private,
    /// but is defined as a separate public method so we can test each
    /// command test individually.  In any case, this class itself is
    /// generally considered private.
    ///
    /// \return Pair of bool and ConstElementPtr: the first element is true if
    /// the builder should keep running; false otherwise.  The second element
    /// is the callback argument if the command is expected to call a callback
    /// (if the callback is not expected this element will be ignored).
    std::pair<bool, data::ConstElementPtr>
    handleCommand(const Command& command);

private:
    // NOOP command handler.  We use this so tests can override it; the default
    // implementation really does nothing.
    data::ConstElementPtr doNoop() { return (data::ConstElementPtr()); }

    // The following three methods are helper to determine whether a new
    // generation of data source clients are ready for use: they are considered
    // ready iff all memory segments are in a state other than WAITING.
    static bool segmentWaiting(const datasrc::DataSourceStatus& status) {
        return (status.getSegmentState() == datasrc::SEGMENT_WAITING);
    }

    static bool
    isClientListWaiting(const std::pair<dns::RRClass,
                        boost::shared_ptr<datasrc::ConfigurableClientList> >&
                        listpair)
    {
        const std::vector<datasrc::DataSourceStatus>& statuses =
            listpair.second->getStatus();
        return (std::find_if(statuses.begin(), statuses.end(), segmentWaiting)
                != statuses.end());
    }

    static bool isClientsReady(const ClientListsMap& clients_map) {
        return (std::find_if(clients_map.begin(), clients_map.end(),
                             isClientListWaiting) == clients_map.end());
    }

    // Swap pending clients map with the current when all waiting memory
    // segments are ready.
    void installClientsMap() {
        // Define new_clients_map outside of the block that has the lock scope;
        // this way, after the swap, the lock is guaranteed to be released
        // before the old data is destroyed, minimizing the lock duration.
        {
            typename MutexType::Locker locker(*map_mutex_);
            pending_map_->clients_map_.swap(*clients_map_);
        } // lock is released by leaving scope
          // old clients_map_ data is released by leaving scope

        gen_id_ = pending_map_->gen_id_;
        pending_map_.reset();
        LOG_INFO(auth_logger, AUTH_DATASRC_CLIENTS_BUILDER_RECONFIGURE_SUCCESS).
            arg(gen_id_);
    }

    // This method returns a bool element, whose value is true iff shared-type
    // memory segment is going to be used.  It will be used as a callback
    // argument so it can be used in the callback to determine whether to
    // start listening to segment info updates.
    data::ConstElementPtr
    doReconfigure(const data::ConstElementPtr& mod_config) {
        if (mod_config) {
            LOG_INFO(auth_logger,
                     AUTH_DATASRC_CLIENTS_BUILDER_RECONFIGURE_STARTED);
            try {
                // Perform the rest of argument validation:
                if (!mod_config->contains("classes")) {
                    bundy_throw(InvalidParameter, "invalid data source "
                                "configuration: must have 'classes'");
                }
                if (!mod_config->contains("_generation_id")) {
                    bundy_throw(InvalidParameter, "invalid data source "
                                "configuration: must have '_generation_id'");
                }
                const int64_t genid =
                    mod_config->get("_generation_id")->intValue();
                // make sure it's non-negative and always increasing (the
                // initial value of gen_id_ is -1, so this condition is enough)
                if (genid <= gen_id_) {
                    bundy_throw(InvalidParameter, "invalid data source "
                                "configuration: bad generation: " << genid);
                }

                // Consider any new configuration to be "pending" first.  Note
                // that we override any existing pending generation; it does
                // not make sense to complete such an intermediate version, and
                // even memmgr may have stopped completing it.
                pending_map_.reset(
                    new PendingClientListMap(
                        configureDataSource(mod_config->get("classes")),
                        genid));

                // Check if all memory segments are ready: if not, we are done
                // for now, waiting for segment info updates; if so, apply the
                // new config now.
                if (!isClientsReady(*pending_map_->clients_map_)) {
                    LOG_INFO(auth_logger,
                             AUTH_DATASRC_CLIENTS_BUILDER_RECONFIGURE_PENDING).
                        arg(genid);

                    // We use shared-type memory segments iff we are here:
                    // if we use a shared segment, it should always begin with
                    // the WAITING state, so we should be here; if we don't use
                    // a shared segment, all segments should be immediately
                    // INUSE, and so we shouldn't be here.  Also, in the latter
                    // case we immediately switch to the new generation below,
                    // so it doesn't matter whether or not we use a shared
                    // segment in the current generation.
                    return (data::Element::create(true));
                }
                installClientsMap();
            } catch (const datasrc::ConfigurableClientList::ConfigurationError&
                     config_error) {
                LOG_ERROR(auth_logger,
                    AUTH_DATASRC_CLIENTS_BUILDER_RECONFIGURE_CONFIG_ERROR).
                    arg(config_error.what());
            } catch (const datasrc::DataSourceError& ds_error) {
                LOG_ERROR(auth_logger,
                    AUTH_DATASRC_CLIENTS_BUILDER_RECONFIGURE_DATASRC_ERROR).
                    arg(ds_error.what());
            } catch (const bundy::Exception& bundy_error) {
                LOG_ERROR(auth_logger,
                    AUTH_DATASRC_CLIENTS_BUILDER_RECONFIGURE_ERROR).
                    arg(bundy_error.what());
            }
            // other exceptions are propagated, see
            // http://bundy.bundy.org/ticket/2210#comment:13
        }
        return (data::Element::create(false));
    }

    void resetSegment(ClientListsMap& clients_map, const dns::RRClass& rrclass,
                      const std::string& dsrc_name,
                      const data::ConstElementPtr& segment_params,
                      bool inuse_only)
    {
        const boost::shared_ptr<bundy::datasrc::ConfigurableClientList>&
            list = (clients_map)[rrclass];
        if (!list) {
            LOG_FATAL(auth_logger,
                      AUTH_DATASRC_CLIENTS_BUILDER_SEGMENT_UNKNOWN_CLASS)
                .arg(rrclass);
            std::terminate();
        }
        if (inuse_only) {
            BOOST_FOREACH(const datasrc::DataSourceStatus& st,
                          list->getStatus()) {
                if (st.getName() != dsrc_name) {
                    continue;
                }
                if (st.getSegmentState() != bundy::datasrc::SEGMENT_INUSE) {
                    LOG_DEBUG(auth_logger, DBGLVL_TRACE_BASIC,
                              AUTH_DATASRC_CLIENTS_SKIP_SEGMENT_RESET).
                        arg(dsrc_name).arg(rrclass);
                    return;
                }
            }
        }

        typename MutexType::Locker locker(*map_mutex_);
        if (!list->resetMemorySegment(
                dsrc_name, bundy::datasrc::memory::ZoneTableSegment::READ_ONLY,
                segment_params)) {
            LOG_FATAL(auth_logger,
                      AUTH_DATASRC_CLIENTS_BUILDER_SEGMENT_NO_DATASRC)
                .arg(rrclass).arg(dsrc_name);
            std::terminate();
        }
    }

    void doSegmentUpdate(const bundy::data::ConstElementPtr& arg) {
        try {
            const bundy::dns::RRClass
                rrclass(arg->get("data-source-class")->stringValue());
            const std::string&
                name(arg->get("data-source-name")->stringValue());
            const bundy::data::ConstElementPtr& segment_params =
                arg->get("segment-params");
            const int64_t genid = arg->get("generation-id")->intValue();
            const bool inuse_only = (arg->contains("inuse-only") &&
                                     arg->get("inuse-only")->boolValue());

            if (gen_id_ == genid) {
                // normal case: update on the current generation; just apply it.
                resetSegment(**clients_map_, rrclass, name, segment_params,
                             inuse_only);
            } else if (pending_map_ && pending_map_->gen_id_ == genid) {
                // update for a pending generation: apply it, and see if it's
                // now ready, and if so, perform swap now.
                resetSegment(*pending_map_->clients_map_, rrclass, name,
                             segment_params, inuse_only);
                if (isClientsReady(*pending_map_->clients_map_)) {
                    installClientsMap();
                }
            } else {
                // We should be able to ignore all other cases: We shouldn't
                // get an update for a future generation (even newer one than
                // pending generation) since the update must follow a data
                // source reconfiguration, which should have been broadcasted
                // to all modules at the same time.  Getting an older generation
                // should also be impossible, but even if that happens we can
                // just ignore it since we'll never need it.  Getting an
                // intermediate generation between the current and pending
                // might be possible if multiple generations of reconfiguration
                // happen very rapidly, but we can ignore it, too since we'll
                // never need that generation.  We'll still send an ack to the
                // memmgr just in case it really waits for it.
                LOG_INFO(auth_logger,
                         AUTH_DATASRC_CLIENTS_BUILDER_SEGMENT_UNKNOWNGEN).
                    arg(genid).arg(gen_id_);
            }
        } catch (const bundy::dns::InvalidRRClass& irce) {
            LOG_FATAL(auth_logger,
                      AUTH_DATASRC_CLIENTS_BUILDER_SEGMENT_BAD_CLASS)
                .arg(arg->get("data-source-class"));
            std::terminate();
        } catch (const bundy::Exception& e) {
            LOG_FATAL(auth_logger,
                      AUTH_DATASRC_CLIENTS_BUILDER_SEGMENT_ERROR)
                .arg(e.what());
            std::terminate();
        }
    }

    void doUpdateZone(datasrc_clientmgr_internal::CommandID command,
                      const bundy::data::ConstElementPtr& arg);
    boost::shared_ptr<datasrc::memory::ZoneWriter> getZoneWriter(
        datasrc_clientmgr_internal::CommandID command,
        datasrc::ConfigurableClientList& client_list,
        const std::string& datasrc_name, const dns::RRClass& rrclass,
        const dns::Name& origin);

    // The following are shared with the manager
    std::list<Command>* command_queue_;
    std::list<FinishedCallbackPair> *callback_queue_;
    CondVarType* cond_;
    MutexType* queue_mutex_;
    datasrc::ClientListMapPtr* clients_map_;
    MutexType* map_mutex_;
    int wake_fd_;

    // These are local to the builder thread:
    // Placeholder for pending new generation of data source clients.  Defined
    // as a struct just for handling the members as a tuple.
    struct PendingClientListMap {
        PendingClientListMap(datasrc::ClientListMapPtr clients_map,
                             int64_t gen_id) :
            clients_map_(clients_map), gen_id_(gen_id)
        {}
        datasrc::ClientListMapPtr clients_map_;
        const int64_t gen_id_;
    };
    boost::scoped_ptr<PendingClientListMap> pending_map_;
    int64_t gen_id_;    // effective generation ID of the current clients_map_
                        // begin with -1, and >= 0 once configured.
};

// Shortcut typedef for normal use
typedef DataSrcClientsBuilderBase<util::thread::Mutex, util::thread::CondVar>
DataSrcClientsBuilder;

template <typename MutexType, typename CondVarType>
void
DataSrcClientsBuilderBase<MutexType, CondVarType>::run() {
    LOG_INFO(auth_logger, AUTH_DATASRC_CLIENTS_BUILDER_STARTED);

    try {
        bool keep_running = true;
        while (keep_running) {
            std::list<Command> current_commands;
            {
                // Move all new commands to local queue under the protection of
                // queue_mutex_.
                typename MutexType::Locker locker(*queue_mutex_);
                while (command_queue_->empty()) {
                    cond_->wait(*queue_mutex_);
                }
                current_commands.swap(*command_queue_);
            } // the lock is released here.

            while (keep_running && !current_commands.empty()) {
                data::ConstElementPtr cbarg;
                try {
                    const std::pair<bool, data::ConstElementPtr> result =
                        handleCommand(current_commands.front());
                    keep_running = result.first;
                    cbarg = result.second;
                } catch (const InternalCommandError& e) {
                    LOG_ERROR(auth_logger,
                              AUTH_DATASRC_CLIENTS_BUILDER_COMMAND_ERROR).
                        arg(e.what());
                }
                if (current_commands.front().callback) {
                    // Lock the queue
                    typename MutexType::Locker locker(*queue_mutex_);
                    callback_queue_->push_back(
                        FinishedCallbackPair(current_commands.front().callback,
                                             cbarg));
                    // Wake up the other end. If it would block, there are data
                    // and it'll wake anyway.
                    const int result = send(wake_fd_, "w", 1, MSG_DONTWAIT);
                    if (result == -1 &&
                        (errno != EWOULDBLOCK && errno != EAGAIN)) {
                        // Note: the strerror might not be thread safe, as
                        // subsequent call to it might change the returned
                        // string. But that is unlikely and strerror_r is
                        // not portable and we are going to terminate anyway,
                        // so that's better than nothing.
                        //
                        // Also, this error handler is not tested. It should
                        // be generally impossible to happen, so it is hard
                        // to trigger in controlled way.
                        LOG_FATAL(auth_logger,
                                  AUTH_DATASRC_CLIENTS_BUILDER_WAKE_ERR).
                            arg(strerror(errno));
                        std::terminate();
                    }
                }
                current_commands.pop_front();
            }
        }

        LOG_INFO(auth_logger, AUTH_DATASRC_CLIENTS_BUILDER_STOPPED);
    } catch (const std::exception& ex) {
        // We explicitly catch exceptions so we can log it as soon as possible.
        LOG_FATAL(auth_logger, AUTH_DATASRC_CLIENTS_BUILDER_FAILED).
            arg(ex.what());
        std::terminate();
    } catch (...) {
        LOG_FATAL(auth_logger, AUTH_DATASRC_CLIENTS_BUILDER_FAILED_UNEXPECTED);
        std::terminate();
    }
}

template <typename MutexType, typename CondVarType>
std::pair<bool, data::ConstElementPtr>
DataSrcClientsBuilderBase<MutexType, CondVarType>::handleCommand(
    const Command& command)
{
    const CommandID cid = command.id;
    if (cid >= NUM_COMMANDS) {
        // This shouldn't happen except for a bug within this file.
        bundy_throw(Unexpected, "internal bug: invalid command, ID: " << cid);
    }

    const boost::array<const char*, NUM_COMMANDS> command_desc = {
        {"NOOP", "RECONFIGURE", "LOADZONE", "UPDATEZONE", "SEGMENT_INFO_UPDATE",
         "SHUTDOWN"}
    };
    LOG_DEBUG(auth_logger, DBGLVL_TRACE_BASIC,
              AUTH_DATASRC_CLIENTS_BUILDER_COMMAND).arg(command_desc.at(cid));
    data::ConstElementPtr cbarg;
    switch (command.id) {
    case RECONFIGURE:
        cbarg = doReconfigure(command.params);
        break;
    case LOADZONE:
    case UPDATEZONE:
        doUpdateZone(command.id, command.params);
        break;
    case SEGMENT_INFO_UPDATE:
        doSegmentUpdate(command.params);
        break;
    case SHUTDOWN:
        return (std::pair<bool, data::ConstElementPtr>(false, cbarg));
    case NOOP:
        cbarg = doNoop();
        break;
    case NUM_COMMANDS:
        assert(false);          // we rejected this case above
    }
    return (std::pair<bool, data::ConstElementPtr>(true, cbarg));
}

template <typename MutexType, typename CondVarType>
void
DataSrcClientsBuilderBase<MutexType, CondVarType>::doUpdateZone(
    datasrc_clientmgr_internal::CommandID command,
    const bundy::data::ConstElementPtr& arg)
{
    // We assume some basic level validation as this method can only be
    // called via the manager in practice.  manager is expected to do the
    // minimal validation.
    assert(arg);
    assert(arg->get("origin"));

    // TODO: currently, we hardcode IN as the default for the optional
    // 'class' argument. We should really derive this from the specification,
    // but at the moment the config/command API does not allow that to be
    // done easily. Once that is in place (tickets have yet to be created,
    // as we need to do a tiny bit of design work for that), this
    // code can be replaced with the original part:
    // assert(arg->get("class"));
    // const dns::RRClass(arg->get("class")->stringValue());
    bundy::data::ConstElementPtr class_elem = arg->get("class");
    const dns::RRClass rrclass(class_elem ?
                                dns::RRClass(class_elem->stringValue()) :
                                dns::RRClass::IN());
    const dns::Name origin(arg->get("origin")->stringValue());
    ClientListsMap::iterator found = (*clients_map_)->find(rrclass);
    if (found == (*clients_map_)->end()) {
        bundy_throw(InternalCommandError, "failed to load a zone " << origin <<
                  "/" << rrclass << ": not configured for the class");
    }

    const bundy::data::ConstElementPtr datasrc_name_elem =
        arg->get("datasource");
    const std::string& datasrc_name = datasrc_name_elem ?
        datasrc_name_elem->stringValue() : "";

    boost::shared_ptr<datasrc::ConfigurableClientList> client_list =
        found->second;
    assert(client_list);

    try {
        boost::shared_ptr<datasrc::memory::ZoneWriter> zwriter =
            getZoneWriter(command, *client_list, datasrc_name, rrclass, origin);
        if (!zwriter) {
            return;
        }

        zwriter->load(); // this can take time but doesn't cause a race
        {   // install() can cause a race and must be in a critical section
            typename MutexType::Locker locker(*map_mutex_);
            zwriter->install();
        }
        LOG_DEBUG(auth_logger, DBG_AUTH_OPS,
                  AUTH_DATASRC_CLIENTS_BUILDER_LOAD_ZONE)
            .arg(origin).arg(rrclass);

        // same as load(). We could let the destructor do it, but do it
        // ourselves explicitly just in case.
        zwriter->cleanup();
    } catch (const InternalCommandError& ex) {
        throw;     // this comes from getZoneWriter.  just let it go through.
    } catch (const bundy::Exception& ex) {
        // We catch our internal exceptions (which will be just ignored) and
        // propagated others (which should generally be considered fatal and
        // will make the thread terminate)
        bundy_throw(InternalCommandError, "failed to load a zone " << origin <<
                  "/" << rrclass << ": error occurred in reload: " <<
                  ex.what());
    }
}

// A dedicated subroutine of doUpdateZone().  Separated just for keeping the
// main method concise.
template <typename MutexType, typename CondVarType>
boost::shared_ptr<datasrc::memory::ZoneWriter>
DataSrcClientsBuilderBase<MutexType, CondVarType>::getZoneWriter(
    datasrc_clientmgr_internal::CommandID command,
    datasrc::ConfigurableClientList& client_list,
    const std::string& datasrc_name, const dns::RRClass& rrclass,
    const dns::Name& origin)
{
    // getCachedZoneWriter() could get access to an underlying data source
    // that can cause a race condition with the main thread using that data
    // source for lookup.  So we need to protect the access here.
    datasrc::ConfigurableClientList::ZoneWriterPair writerpair;
    {
        typename MutexType::Locker locker(*map_mutex_);
        writerpair = client_list.getCachedZoneWriter(origin, false,
                                                     datasrc_name);
    }

    switch (writerpair.first) {
    case datasrc::ConfigurableClientList::ZONE_SUCCESS:
        assert(writerpair.second);
        return (writerpair.second);
    case datasrc::ConfigurableClientList::ZONE_NOT_FOUND:
        bundy_throw(InternalCommandError, "failed to load zone " << origin
                  << "/" << rrclass << ": not found in any configured "
                  "data source.");
    case datasrc::ConfigurableClientList::ZONE_NOT_CACHED:
        LOG_DEBUG(auth_logger, DBG_AUTH_OPS,
                  AUTH_DATASRC_CLIENTS_BUILDER_LOAD_ZONE_NOCACHE)
            .arg(origin).arg(rrclass);
        break;                  // return NULL below
    case datasrc::ConfigurableClientList::CACHE_NOT_WRITABLE:
        if (command == UPDATEZONE) {
            break;
        }
        // This is an internal error. Auth server should skip reloading zones
        // on non writable caches.
        bundy_throw(InternalCommandError, "failed to load zone " << origin
                  << "/" << rrclass << ": internal failure, in-memory cache "
                  "is not writable");
    case datasrc::ConfigurableClientList::CACHE_DISABLED:
        // This is an internal error. Auth server must have the cache
        // enabled.
        bundy_throw(InternalCommandError, "failed to load zone " << origin
                  << "/" << rrclass << ": internal failure, in-memory cache "
                  "is somehow disabled");
    default:                    // other cases can really never happen
        bundy_throw(Unexpected, "Impossible result in getting data source "
                  "ZoneWriter: " << writerpair.first);
    }

    return (boost::shared_ptr<datasrc::memory::ZoneWriter>());
}
} // namespace datasrc_clientmgr_internal

/// \brief Shortcut type for normal data source clients manager.
///
/// In fact, for non test applications this is the only type of this kind
/// to be considered.
typedef DataSrcClientsMgrBase<
    util::thread::Thread,
    datasrc_clientmgr_internal::DataSrcClientsBuilder,
    util::thread::Mutex, util::thread::CondVar> DataSrcClientsMgr;
} // namespace auth
} // namespace bundy

#endif  // DATASRC_CLIENTS_MGR_H

// Local Variables:
// mode: c++
// End:
