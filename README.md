# Android Demystification Toolbox

## Purpose

ADT is a [Miasm](https://github.com/cea-sec/miasm)-based symbolic execution toolset designed to help model application behavior, research and test security vulnerabilities, and facilitate reversing hostile code.

## Features

* The ability to save/restore all threads & processes contexts
* A centralized (json encoded) config file to mimick an Android environment
* A scheduler to handle mutexes, multi-threading and multi-processing
    * fork()
    * pthread_create()
    * pthread_mutex_lock/unlock()
    * Blocking file reads / writes
* Java JNI (java native bridge) implementation which handles
    * Strings
    * Files & directories
    * Arrays
    * Function calls
    * Class fields
* A number of miscallenous implementations
    * sscanf()
    * mktime()
    * crc32, mimicking the c version
    * c++ streams
    * pipes
    * fstat() and android's custom struct w/ padding for aarch64
    * android libc's _system_property_get()
    * varargs (general case scenario working only)
    * prcrl

## HOWTO

### Setup

* Install Miasm from this [Miasm fork](https://github.com/nguigo/miasm/tree/experimental). The patches from the `experimental` branch implement aaarch64 instructions, and provide the corresponding jitter and sandboxing components.
  * `git clone https://github.com/nguigo/miasm.git && cd miasm && git checkout experimental`
  * `pip install .`
* `git clone https://github.com/nccgroup/android_demystification_toolbox.git`
* `pip install ./android_demystification_toolbox`

### General usage

* From the template
  * Fill out the necessary memory requirements in the `one_time_setup()` function
  * Enter your custom breakpoints in the `breakpoints_setup()` function
  * Let the main loop take care of handling the multiple contexts
  * Use adt.config to store Android environment information (see samples for more details)
* The NDK sample can be run as a demo with `python3 sample.py libhello-jnicallback.so`

### Saving / Restoring contexts

## !! WARNING !!

The contexts are saved and restored using the [pickle](https://docs.python.org/3/library/pickle.html) module,
which is not safe with untrusted data. Ensure only trusted contexts are restored.

## Usage

* The sample function `save_context_and_dump()` can be used as a jitter callback:
```
jitter.add_breakpoint(<my_address>, save_context_and_dump)
```
* The code automatically looks for a `context.pkl` to restore, so the following command line can be used:
```
ln -s context_myaddress.pkl context.pkl
```
* Upon starting the script, the context will be restored automatically
