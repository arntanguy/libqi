##
## Author(s):
##  - Cedric GESTES <gestes@aldebaran-robotics.com>
##  - Pierre ROULLON <proullon@aldebaran-robotics.com>
##
## Copyright (C) 2010 - 2013 Aldebaran Robotics
##

""" QiMessaging Python bindings

Provided features are very close to C++, Python style.
"""

import os
import sys

def load_lib_qipyessaging():
    """ Load _qipyessaging.so and its dependencies.

    This makes _qipyessaging usable from a relocatable
    SDK without having to set LD_LIBRARY_PATH
    """
    import ctypes
    deps = [
            "libqi.so",
            "libqitype.so",
            "libqimessaging.so",
    ]
    this_dir = os.path.abspath(os.path.dirname(__file__))
    for dep in deps:
        full_path = os.path.join(this_dir, "..", dep)
        ctypes.cdll.LoadLibrary(full_path)


if sys.platform.startswith("linux"):
    try:
        load_lib_qipyessaging()
    except Exception:
        pass


#######

from _qi import Application, FutureState, FutureTimeout, Object, \
                Promise, Property, ServiceDirectory, Session, Signal, \
                createObject, registerObjectFactory

from _type import Void, Int, Float, String, List, Map, Struct, Object, Dynamic, Buffer, AnyArguments
from _binder import bind, nobind

_app = Application()


#we want to stop all thread before python start destroying
#module and the like. (this avoid callback calling python while
#it's destroying)
def _stopApplication():
    global _app
    _app.stop()
    del _app
    _app = None

import atexit
atexit.register(_stopApplication)

#application is a singleton, it should live till the end of the program
#because it own eventloops
def Application():
    global _app
    return _app

__all__ = ["FutureState",
           "FutureTimeout",
           "Object",
           "Promise",
           "Property",
           "ServiceDirectory",
           "Session",
           "Signal",
           "createObject",
           "registerObjectFactory",

           "Void", "Int", "Float", "String", "List", "Map", "Struct", "Object", "Dynamic", "Buffer", "AnyArguments"
           "bind", "nobind"

]
