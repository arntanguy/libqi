/*
 * Copyright (c) 2013 Aldebaran Robotics. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the COPYING file.
 */

#include <boost/lexical_cast.hpp>
#include <boost/thread.hpp>
#include <boost/enable_shared_from_this.hpp>

#include <qi/log.hpp>
#include <qi/periodictask.hpp>


qiLogCategory("qi.PeriodicTask");

// WARNING: if you add a state, review trigger() so that it stays lockfree
enum TaskState
{
  Task_Stopped = 0,
  Task_Scheduled = 1, //< scheduled in an async()
  Task_Running = 2,   //< being executed
  Task_Rescheduling = 3, //< being rescheduled (protects _task)
  Task_Starting = 4, //< being started
  Task_Stopping = 5, //< stop requested
  Task_Triggering = 6, //< force trigger
  Task_TriggerReady = 7, //< force trigger (step 2)
};

/* Transition matrix:
 Stopped      -> Starting [start()]
 Starting     -> Rescheduling [start()]
 Rescheduling -> Scheduled [start(), _wrap()]
 Scheduled    -> Running   [start()]
 Running      -> Rescheduling [ _wrap() ]
 Stopping     -> Stopped   [stop(), _wrap(), trigger()]
 Running      -> Stopping [stop()]
 Scheduled    -> Stopping [stop()]
 Scheduled    -> Triggering [trigger()]
 Triggering   -> Running [_wrap()]
 Triggering   -> Rescheduling [_trigger()]

 - State Rescheduling is a lock on _state and on _task
*/

// Persist trying to transition state, log if it takes too long, but never abort
inline void setState(qi::Atomic<int>& state, TaskState from, TaskState to)
{
  for (unsigned i=0; i<1000; ++i)
    if (state.setIfEquals(from, to))
      return;
  while (true)
  {
    for (unsigned i=0; i<1000; ++i)
    {
      if (state.setIfEquals(from, to))
        return;
      qi::os::msleep(1); // TODO: 1ms is probably too long
    }
    qiLogWarning() << "PeriodicTask is stuck " << from << ' ' << to << ' ' << *state;
  }
}

inline void setState(qi::Atomic<int>& state, TaskState from, TaskState to, TaskState from2, TaskState to2)
{
  for (unsigned i=0; i<1000; ++i)
    if (state.setIfEquals(from, to) || state.setIfEquals(from2, to2))
      return;
  while (true)
  {
    for (unsigned i=0; i<1000; ++i)
    {
      if (state.setIfEquals(from, to) || state.setIfEquals(from2, to2))
        return;
      qi::os::msleep(1); // TODO: 1ms is probably too long
    }
    qiLogWarning() << "PeriodicTask is stuck " << from << ' ' << to << ' '  << from2 << ' ' << to2 << ' '<< *state;
  }
}

namespace qi
{

  struct PeriodicTaskPrivate :
    boost::enable_shared_from_this<PeriodicTaskPrivate>
  {
    MethodStatistics        _callStats;
    qi::SteadyClockTimePoint _statsDisplayTime;
    PeriodicTask::Callback  _callback;
    PeriodicTask::ScheduleCallback _scheduleCallback;
    qi::Duration            _period;
    qi::Atomic<int>         _state;
    qi::Future<void>        _task;
    std::string             _name;
    bool                    _compensateCallTime;
    int                     _tid;

    void _reschedule(qi::Duration delay = qi::Duration(0));
    void _wrap();
    void _trigger(qi::Future<void> future);
  };
  static const int invalidThreadId = -1;
  PeriodicTask::PeriodicTask() :
    _p(new PeriodicTaskPrivate)
  {
    _p->_period = qi::Duration(-1);
    _p->_tid = invalidThreadId;
    _p->_compensateCallTime =false;
    _p->_statsDisplayTime = qi::steadyClockNow();
    _p->_name = "PeriodicTask_" + boost::lexical_cast<std::string>(this);
  }


  PeriodicTask::~PeriodicTask()
  {
    stop();
  }

  void PeriodicTask::setName(const std::string& n)
  {
    _p->_name = n;
  }

  void PeriodicTask::setCallback(const Callback& cb)
  {
    if (_p->_callback)
      throw std::runtime_error("Callback already set");
    _p->_callback = cb;
  }

  void PeriodicTask::setStrand(qi::Strand* strand)
  {
    if (strand)
      _p->_scheduleCallback = boost::bind<qi::Future<void> >(
              static_cast<qi::Future<void>(qi::Strand::*)(const Callback&,
                qi::Duration)>(
                  &qi::Strand::async),
              strand, _1, _2);
    else
      _p->_scheduleCallback = ScheduleCallback();
  }

  void PeriodicTask::setUsPeriod(qi::int64_t usp)
  {
    if (usp<0)
      throw std::runtime_error("Period cannot be negative");
    _p->_period = qi::MicroSeconds(usp);
  }

  void PeriodicTask::setPeriod(qi::Duration period)
  {
    if (period < qi::Duration(0))
      throw std::runtime_error("Period cannot be negative");
    _p->_period = period;
  }

  void PeriodicTask::start(bool immediate)
  {
    if (!_p->_callback)
      throw std::runtime_error("Periodic task cannot start without a setCallback() call first");
    if (_p->_period < qi::Duration(0))
      throw std::runtime_error("Periodic task cannot start without a setPeriod() call first");
    // we are called from the callback
    if (os::gettid() == _p->_tid)
      return;

    qiLogDebug() << *_p->_state << " start";
    //Stopping is not handled by start, stop will handle it for us.
    stop();
    if (!_p->_state.setIfEquals(Task_Stopped, Task_Starting))
    {
      qiLogDebug() << *_p->_state << " task was not stopped";
      return; // Already running or being started.
    }
    if (!_p->_state.setIfEquals(Task_Starting, Task_Rescheduling))
      qiLogError() << "Periodic task internal error while starting";
    _p->_reschedule(immediate ? qi::Duration(0) : _p->_period);
  }

  void PeriodicTask::trigger()
  {
    qiLogDebug() << *_p->_state << " trigger";
    while (true)
    {
      if (_p->_state.setIfEquals(Task_Stopped, Task_Stopped) ||
          _p->_state.setIfEquals(Task_Stopping, Task_Stopping) ||
          _p->_state.setIfEquals(Task_Starting, Task_Starting) ||
          _p->_state.setIfEquals(Task_Running, Task_Running) ||
          _p->_state.setIfEquals(Task_Rescheduling, Task_Rescheduling) ||
          _p->_state.setIfEquals(Task_Triggering, Task_Triggering) ||
          _p->_state.setIfEquals(Task_TriggerReady, Task_TriggerReady))
      {
        qiLogDebug() << *_p->_state << " nothing to do";
        return;
      }
      if (_p->_state.setIfEquals(Task_Scheduled, Task_Triggering))
      {
        qiLogDebug() << *_p->_state << " scheduled to triggerring";
        _p->_task.cancel();
        qiLogDebug() << *_p->_state << " cancel done";
        _p->_task.connect(&PeriodicTaskPrivate::_trigger, _p, _1,
            FutureCallbackType_Sync);
        qiLogDebug() << *_p->_state << " connected callback";
        _p->_state.setIfEquals(Task_Triggering, Task_TriggerReady);
        qiLogDebug() << *_p->_state << " ready";
        return;
      }
    }
  }

  void PeriodicTaskPrivate::_trigger(qi::Future<void> future)
  {
    qiLogDebug() << *_state << " future finished";
    // if future was not canceled, the task already ran, don't retrigger
    if (!future.isCanceled())
    {
      qiLogDebug() << *_state << " task successfully ran";
      return;
    }

    // else, start the task now if we are still triggering
    if (_state.setIfEquals(Task_Triggering, Task_Rescheduling) ||
        _state.setIfEquals(Task_TriggerReady, Task_Rescheduling))
    {
      qiLogDebug() << *_state << " rescheduling";
      _reschedule();
    }
    else
      qiLogDebug() << *_state << " not rescheduling anymore";
  }

  void PeriodicTaskPrivate::_wrap()
  {
    qiLogDebug() << *_state << " callback start";
    if (*_state == Task_Stopped)
      qiLogError()  << "PeriodicTask inconsistency: stopped from callback";
    /* To avoid being stuck because of unhandled transition, the rule is
    * that any other thread playing with our state can only do so
    * to stop us, and must eventualy reach the Stopping state
    */
    if (_state.setIfEquals(Task_Stopping, Task_Stopped))
    {
      qiLogDebug() << *_state << " stopped before callback";
      return;
    }
    /* reschedule() needs to call async() before reseting state from rescheduling
    *  to scheduled, to protect the _task object. So we might still be
    * in rescheduling state here.
    */
    while (*_state == Task_Rescheduling)
      boost::this_thread::yield();
    // order matters! check scheduled state first as the state cannot change
    // from triggering to scheduled but can change in the other way
    if (!_state.setIfEquals(Task_Scheduled, Task_Running) &&
        !_state.setIfEquals(Task_Triggering, Task_Triggering) &&
        !_state.setIfEquals(Task_TriggerReady, Task_TriggerReady))
    {
      qiLogDebug() << *_state << " not scheduled nor triggering, waiting for stop";
      setState(_state, Task_Stopping, Task_Stopped);
      return;
    }
    bool shouldAbort = false;
    qi::SteadyClockTimePoint now;
    qi::Duration delta;
    qi::int64_t usr, sys;
    bool compensate = _compensateCallTime; // we don't want that bool to change in the middle
    try
    {
      qi::SteadyClockTimePoint start = qi::steadyClockNow();
      std::pair<qi::int64_t, qi::int64_t> cpu = qi::os::cputime();
      _tid = os::gettid();
      _callback();
      _tid = invalidThreadId;
      now = qi::steadyClockNow();
      delta = now - start;
      std::pair<qi::int64_t, qi::int64_t> cpu2 = qi::os::cputime();
      usr = cpu2.first - cpu.first;
      sys = cpu2.second - cpu.second;
    }
    catch (const std::exception& e)
    {
      qiLogInfo() << "Exception in task " << _name << ": " << e.what();
      shouldAbort = true;
    }
    catch(...)
    {
      qiLogInfo() << "Unknown exception in task callback.";
      shouldAbort = true;
    }
    if (shouldAbort)
    {
      qiLogDebug() << *_state << " should abort, bye";
      setState(_state, Task_Stopping, Task_Stopped,
                       Task_Running, Task_Stopped);
      return;
    }
    else
    {
      _callStats.push(
          (float)boost::chrono::duration_cast<qi::MicroSeconds>(delta).count() / 1e6f,
          (float)usr / 1e6f,
          (float)sys / 1e6f);

      if (now - _statsDisplayTime >= qi::Seconds(20))
      {
        float secTime = float(boost::chrono::duration_cast<qi::MicroSeconds>(now - _statsDisplayTime).count()) / 1e6f;
        _statsDisplayTime = now;
        unsigned int count = _callStats.count();
        std::string catName = "stats." + _name;
        qiLogVerbose(catName.c_str())
          << (_callStats.user().cumulatedValue() * 100.0 / secTime)
          << "%  "
          << count
          << "  " << _callStats.wall().asString(count)
          << "  " << _callStats.user().asString(count)
          << "  " << _callStats.system().asString(count)
          ;
        _callStats.reset();
      }

      while (*_state == Task_Triggering)
        boost::this_thread::yield();

      if (!_state.setIfEquals(Task_Running, Task_Rescheduling) &&
          !_state.setIfEquals(Task_TriggerReady, Task_Rescheduling))
      { // If we are not in running state anymore, someone switched us
        // to stopping
        qiLogDebug() << *_state << " not running anymore, waiting for stop";
        setState(_state, Task_Stopping, Task_Stopped);
        return;
      }
      _reschedule(std::max(qi::Duration(0), _period - (compensate ? delta : qi::Duration(0))));
    }
  }

  void PeriodicTaskPrivate::_reschedule(qi::Duration delay)
  {
    qiLogDebug() << *_state << " rescheduling in " << delay;
    if (_scheduleCallback)
      _task = _scheduleCallback(boost::bind(&PeriodicTaskPrivate::_wrap, shared_from_this()), delay);
    else
      _task = getEventLoop()->async(boost::bind(&PeriodicTaskPrivate::_wrap, shared_from_this()), delay);
    if (!_state.setIfEquals(Task_Rescheduling, Task_Scheduled))
      qiLogError() << "PeriodicTask forbidden state change while rescheduling " << *_state;
  }

  void PeriodicTask::asyncStop()
  {
    qiLogDebug() << *_p->_state << " async stop";
    if (_p->_state.setIfEquals(Task_Stopped, Task_Stopped))
      return;
    // we are allowed to go from Scheduled and Running to Stopping
    // also handle multiple stop() calls
    while (!_p->_state.setIfEquals(Task_Scheduled , Task_Stopping) &&
           !_p->_state.setIfEquals(Task_Running, Task_Stopping) &&
           !_p->_state.setIfEquals(Task_Stopped, Task_Stopped) &&
           !_p->_state.setIfEquals(Task_Stopping, Task_Stopping))
      boost::this_thread::yield();
    // We do not want to wait for callback to trigger. Since at this point
    // the callback (_wrap)  is not allowed to touch _task, we can just cancel/wait it
    try
    {
      qiLogDebug() << *_p->_state << " canceling";
      _p->_task.cancel();
    }
    catch(...)
    {}
  }

  void PeriodicTask::stop()
  {
    qiLogDebug() << *_p->_state << " stop";
    asyncStop();
    if (os::gettid() == _p->_tid)
      return;
    try
    {
      qiLogDebug() << *_p->_state << " waiting";
      _p->_task.wait();
    }
    catch (...) {}

    // So here state can be stopping (callback was aborted) or stopped
    // We set to stopped either way to be ready for restart.
    qiLogDebug() << *_p->_state << " going to stopped state";
    if (!_p->_state.setIfEquals(Task_Stopping , Task_Stopped) &&
        !_p->_state.setIfEquals(Task_Stopped, Task_Stopped))
      qiLogError() << "PeriodicTask inconsistency, expected Stopped, got " << *_p->_state;
  }

  void PeriodicTask::compensateCallbackTime(bool enable)
  {
    _p->_compensateCallTime = enable;
  }

  bool PeriodicTask::isRunning() const
  {
    int s = *_p->_state;
    return s != Task_Stopped && s!= Task_Stopping;
  }

  bool PeriodicTask::isStopping() const
  {
    int s = *_p->_state;
    return s == Task_Stopped || s == Task_Stopping;
  }
}
