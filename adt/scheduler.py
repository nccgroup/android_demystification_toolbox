import os, itertools, threading, asyncio
from collections import namedtuple
from itertools import chain
# Miasm
from miasm.os_dep.linux import syscall
from miasm.os_dep.linux.environment import FileDescriptorRegularFile
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE
# Android toolbox
from adt.context import Context, log

FInfo = namedtuple("FInfo", ["path", "fdesc"])
NOPROC = 'NOPROC'
NOTHREAD = 'NOTHREAD'

def locked(func):
  async def wrapper(self, *args, **kwargs):
    async with self.lock:
      func(self, *args, **kwargs)
    #self.lock.release()
  return wrapper

class Scheduler(object):
  class Threadpool(dict):
    def __init__(self, *args, **kwargs):
      dict.__init__(self, args)
      self.update(*args, **kwargs)
      self.runnable = threading.Event()

    def __setitem__(self, key, val):
      # Only recompile the generator if we are adding a new element
      generator_reset_required = False if key in self else True
      dict.__setitem__(self, key, val)
      if generator_reset_required:
        self.next_element_gen = itertools.cycle(self)
        self.runnable.set()
        print('Threadpool RUNNABLE SET')

    def __delitem__(self, *args, **kwargs):
      dict.__delitem__(self, *args, **kwargs)
      self.next_element_gen = itertools.cycle(self)
      if not len(self):
        self.runnable.clear()
        print('Threadpool RUNNABLE CLEARED')

    def update(self, *args, **kwargs):
      dict.update(self, *args, **kwargs)
      self.next_element_gen = itertools.cycle(self)

    # This transparently allows for pickling
    def __copy__(self):
      newself = self.__copy__()
      newself.next_element_gen = None

  def __init__(self, jitter, linuxenv, ret=None):
    self.lock = asyncio.Lock() # asyncio acquiring is fair, as opposed to threading module
    self.jitter = jitter
    self.procs = {linuxenv.process_pid : self.jitter.vm.get_all_memory()}
    self.threads = self.Threadpool()
    self.thread_done = {}
    self.return_values = {}
    #self.threads[linuxenv.process_tid] = self.save_state()
    self.t2p = {linuxenv.process_tid:linuxenv.process_pid, NOTHREAD:NOPROC}
    self.genealogy = {}
    self.cond = {}
    self.sync = {linuxenv.process_pid: linuxenv.process_tid} # held mutexes
    self.waiters = {}
    self.current_stack = jitter.stack_base
    self.files = {}
    self.my_FILE_ptr = 0x11223344
    self.FILE_to_info = {}
    self.pipes = []
    self.pthread_keys = {}
    self.max_tid = 0x800
    self.max_pid = 0x1000
    self.CALL_FINISH_ADDR = ret # This is only to propagate miasm's internal canonical ret address

  def reinitialize(self, jitter):
    self.jitter = jitter
    # Rebuild the real filesystem underneath
    for fd, fdesc in Context.current.linuxenv.file_descriptors.items():
      if type(fdesc) is FileDescriptorRegularFile and not fdesc.is_closed:
        path = self.files[fdesc]
        fdesc.real_fd = os.open(path, os.O_RDONLY)
    # Get last running thread at time of snaphost and apply it
    self.restore_state(self.current_tid, force=True)

  def update(self):
    # Save current state for thread and process
    self.threads[self.current_tid] = self.save_state()
    self.procs[self.current_pid] = self.jitter.vm.get_all_memory()
    self.files = { fdesc: os.readlink(f'/proc/self/fd/{fdesc.real_fd}') \
            for fdesc in Context.current.linuxenv.file_descriptors.values() \
            if type(fdesc) is FileDescriptorRegularFile and not fdesc.is_closed
            }

  @property
  def current_tid(self):
    return Context.current.linuxenv.process_tid

  @current_tid.setter
  def current_tid(self, value):
    Context.current.linuxenv.process_tid = value

  @property
  def current_pid(self):
    return Context.current.linuxenv.process_pid

  @current_pid.setter
  def current_pid(self, value):
    Context.current.linuxenv.process_pid = value

  @property
  def next_runnable_thread(self):
    if not self.threads:
      return None
    assert self.runnable_threads
    print(f'BLOCKED: {self.blocked}')
    while t := next(self.threads.next_element_gen):
      if t not in self.blocked:
        return t

  @property
  def blocked(self):
    return set(chain(*self.waiters.values()))

  @property
  def runnable_threads(self):
    runnable_threads_counts = len([t for t in self.threads if t not in self.blocked])
    return runnable_threads_counts

  def get_new_pid(self):
    self.max_pid += 1
    return self.max_pid

  def get_new_tid(self):
    self.max_tid += 1
    return self.max_tid

  def get_new_stack(self):
    self.current_stack += self.jitter.stack_size
    return self.current_stack

  def save_state(self):
    out = {}
    regs = self.jitter.lifter.arch.regs.attrib_to_regs[self.jitter.lifter.attrib]
    for reg in regs:
      if hasattr(self.jitter.cpu, reg.name):
        out[reg.name] = getattr(self.jitter.cpu, reg.name)
    return out

  def restore_state(self, tid, force=False):
    pid = self.t2p[tid]
    # Restore registers
    self.jitter.pc = self.threads[tid][self.jitter.lifter.pc.name]
    for reg, value in self.threads[tid].items():
      setattr(self.jitter.cpu, reg, value)
    # Reset intern elements
    self.jitter.vm.set_exception(0)
    self.jitter.cpu.set_exception(0)
    self.jitter.bs._atomic_mode = False
    # Restore memory if necessary
    if force or pid != self.current_pid:
      log.warning(f'({pid}.{tid}) RESTORING PROCESS MEMORY at {self.jitter.pc:08X}')
      self.jitter.vm.reset_memory_page_pool()
      self.jitter.vm.reset_code_bloc_pool()
      for addr, metadata in self.procs[pid].items():
          self.jitter.vm.add_memory_page(
              addr,
              metadata["access"],
              metadata["data"]
          )
    # Restore pid & tid
    self.current_pid = pid
    self.current_tid = tid

  def context_switch(self, tid=None, pc=None, save_context=True):
    # FIXME!!!! DIRTY HACK: FIX CONTEXT TO REPLAY READ() CALL UPON SCHEDULING
    if pc:
      self.jitter.pc = pc
      self.jitter.cpu.PC = pc
      #self.jitter.cpu.RSP = self.jitter.cpu.RSP+0x8
    # Save current state, unless it's a dead thread
    if save_context:
      self.threads[self.current_tid] = self.save_state()
    # If no thread specified, get one not waiting on anything
    if not tid:
      tid = self.next_runnable_thread
    if tid:
      if self.t2p[tid] != self.current_pid:
        log.warning(f'({self.current_pid}.{self.current_tid}) SAVING PROCESS MEMORY at {self.jitter.pc:08X}')
        self.procs[self.current_pid] = self.jitter.vm.get_all_memory()
      self.restore_state(tid)
      log.warning(f'CONTEXT SWITCH to {self.t2p[tid]}, {tid}: {self.jitter.pc:08X}')
      return True
    else:
      # Terminate if all threads have terminated
      log.warning(f'NO OTHER THREAD CONTEXT TO RUN')
      self.jitter.running = False
      return False

  def new_process(self, pc):
    # Get a new pid
    newpid = self.get_new_pid()
    # Create a new thread in this new process to-be
    tid = self.new_thread(pc, pid=newpid, keep_sp=True)
    # Save current mem into new proc
    self.procs[newpid] = self.jitter.vm.get_all_memory()
    # Set new process as not signalled so waitpid can wait on it
    self.sync[newpid] = tid
    log.warning(f'NEW PROC {newpid},{tid}')
    return newpid

  def new_thread(self, routine, *args, pid=None, keep_sp=False, **kwargs):
    # Save current thread state
    oldtid = self.current_tid
    if oldtid:
      self.threads[oldtid] = self.save_state()
    # Get a new tid
    tid = self.get_new_tid()
    # Record which process context this thread lives
    self.t2p[tid] = pid if pid else self.current_pid
    # Set arg and pc
    self.jitter.init_run(routine)
    # Allow the caller to specify another calling convention
    prepare_cb = kwargs.pop('prepare_cb', self.jitter.func_prepare_systemv)
    prepare_cb(self.CALL_FINISH_ADDR, *args)
    # Create new stack
    if not keep_sp:
      stack_top = self.get_new_stack()
      self.jitter.vm.add_memory_page(
          stack_top,
          PAGE_READ | PAGE_WRITE,
          b"\x00" * self.jitter.stack_size,
          "Stack")
      sp = self.jitter.arch.getsp(self.jitter.attrib)
      setattr(self.jitter.cpu, sp.name, stack_top + int(self.jitter.stack_size/2))
    # Save new thread context
    self.threads[tid] = self.save_state()
    self.thread_done[tid] = threading.Event()
    log.warning(f'NEW THREAD {tid}: {routine:08X}')
    # Restore old thread if it exists
    if oldtid:
      self.restore_state(oldtid)
    return tid

  def acquire(self, waitable, tid=None, rewait=False):
    tid = tid if tid else self.current_tid
    # TODO: HACK HACK HERE
    if waitable == 0xFFFFFFFF:
      log.warning(f'({self.t2p[tid]}.{tid}) ACQUIRED (THEN RELEASED) {waitable:08X}')
      #enable_log(self.jitter)
      return False
    owner = self.sync.get(waitable)
    # Check for double acquires
    assert owner != tid
    # No owner, just claim it
    if not owner:
      log.warning(f'({self.t2p[tid]}.{tid}) CLAIMING OWNERSHIP of {waitable:08X}')
      self.sync[waitable] = tid
      if rewait:
       self.waiters[waitable].append(self.current_tid)
      return True
    else:
      log.warning(f'({self.t2p[tid]}.{tid}) WAITING ON {waitable:08X}')
      # Add current thread to the list of waiters
      self.waiters.setdefault(waitable, []).append(tid)
      if rewait:
       self.waiters[waitable].append(self.current_tid)
      # Do not perform context switch if we are acquiring on behalf of another thread
      #if tid == self.current_tid:
      raise ContextSwitchException()

  def release(self, waitable, reacquire=False):
    # Wait for the right thread to release this resource
    if self.sync.get(waitable) not in (self.current_tid, NOTHREAD):
      print(f'({self.current_pid}.{self.current_tid}) holder:{self.sync.get(waitable)} != current:{self.current_tid}')
      assert False
    # Pass ownership to the first waiter and unblock it
    waiters = self.waiters.get(waitable)
    tid = waiters.pop(0) if waiters else None
    self.sync[waitable] = tid
    log.warning(f'({self.current_pid}.{self.current_tid}) RELEASED {waitable:08X} -> NEW OWNER {tid}')
    if reacquire:
      self.waiters.setdefault(waitable, []).append(self.current_tid)
      raise ContextSwitchException()

# TODO: Include context to allow sync functions to set return value since they cannot via normal func_ret_systemv
class ContextSwitchException(Exception):
  def __init__(self, pc=None):
    super(Exception, self).__init__()
    self.pc = pc
