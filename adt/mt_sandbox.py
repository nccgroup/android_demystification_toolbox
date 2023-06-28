import threading, asyncio
from miasm.analysis.sandbox import Sandbox, Arch_aarch64l, OS_Linux
from miasm.os_dep.linux import syscall
# Android toolbox
from adt import adt
from adt.context import Context, log
from adt.scheduler import ContextSwitchException
from adt.misc import parse_libc
from adt.jitter_callbacks import *

class MTSandbox(Sandbox, Arch_aarch64l, OS_Linux):

  def loop_runner(self):
    self.loop.run_forever()

  def __init__(self, loc_db, *args, **kwargs):
    Sandbox.__init__(self, loc_db, *args, **kwargs)
    self.loop = None

    # Pre-stack some arguments
    if self.options.mimic_env:
      env_ptrs = []
      for env in self.envp:
        env = force_bytes(env)
        env += b"\x00"
        self.jitter.cpu.SP -= len(env)
        ptr = self.jitter.cpu.SP
        self.jitter.vm.set_mem(ptr, env)
        env_ptrs.append(ptr)
      argv_ptrs = []
      for arg in self.argv:
        arg = force_bytes(arg)
        arg += b"\x00"
        self.jitter.cpu.SP -= len(arg)
        ptr = self.jitter.cpu.SP
        self.jitter.vm.set_mem(ptr, arg)
        argv_ptrs.append(ptr)

        self.jitter.push_uint64_t(0)
        for ptr in reversed(env_ptrs):
          self.jitter.push_uint64_t(ptr)
        self.jitter.push_uint64_t(0)
        for ptr in reversed(argv_ptrs):
          self.jitter.push_uint64_t(ptr)
        self.jitter.push_uint64_t(len(self.argv))

    self.jitter.cpu.LR = self.CALL_FINISH_ADDR

    # Set the runtime guard
    self.jitter.add_breakpoint(self.CALL_FINISH_ADDR, self.__class__.code_sentinelle)

    # Load the context
    self.newrun = True
    if self.options.context:
      if context := Context.import_from_file(self.options.context):
        context.apply(self.jitter)
        self.newrun = False
    if not Context.current:
      context = adt.create_new_context(self.jitter, ret=self.CALL_FINISH_ADDR)
      Context.set_current(context)

    # Always enable syscall handling (bc why not?)
    syscall.enable_syscall_handling(self.jitter, context.linuxenv, syscall.syscall_callbacks_aarch64)

    # Use the real libc offsets
    if self.options.libc:
      parse_libc(self.jitter, self.options.libc, globals())

    # Use the jitter callbackback to mimic quantum
    self.jitter.exec_cb = self.__class__.runiter_cb

    # Get the async loop going
    self.loop = asyncio.new_event_loop()
    #print(f'STARTING JITTER LOOP')
    self.loop.create_task(self.jitter_loop(self.jitter, Context.current.sched))
    #print(f'RETURNED JITTER LOOP')
    threading.Thread(target=self.loop_runner).start()
    #print(f'LOOP {self.loop}: {self.loop.is_running()}')

  @classmethod
  def parser(cls, *args, **kwargs):
    parser = super().parser(args, kwargs)
    parser.add_argument('-C', '--context', help='Load existing context', default=None)
    parser.add_argument('-l', '--libc', help='Parse real libc', default=None)
    return parser

  async def jitter_loop(self, jitter, sched):
    while sched.threads.runnable.wait():
      while jitter.running:
        try:
          jitter.continue_run()
        except ContextSwitchException as e:
          sched.context_switch(tid=None, pc=e.pc)
        except RuntimeError as e:
          print('Caught manually raised StopIteration')
          pass

  def run(self, addr=None, *args, **kwargs):
    sync = kwargs.pop('sync', True)
    pid, tid = self.run_async(addr, *args, **kwargs)
    if sync:
      Context.current.sched.thread_done[tid].wait()
      return Context.current.sched.return_values[tid]
    return pid, tid

  def run_async(self, addr=None, *args, **kwargs):
    sched = Context.current.sched
    pid, tid = sched.current_pid, sched.current_tid
    # Get run address
    if addr is None and self.options.address is None:
      addr = self.entry_point
    # Handle processes and threads
    newthread = kwargs.pop('newthread', False)
    if kwargs.pop('newproc', False):
      # This also creates a thread
      sched.current_pid = pid = sched.new_process(addr)
    elif not sched.current_tid or newthread:
      tid = Context.current.sched.new_thread(addr, *args, *kwargs)
      # If no threads are currently running, schedule us
      if not sched.current_tid:
        sched.current_tid = tid
    # Run callack if any (useful to attach DSE)
    if cb := kwargs.pop('cb', None):
      cb(self)
    return pid, tid

  @staticmethod
  def code_sentinelle(jitter):
    # Get the scheduler
    sched = Context.current.sched
    # Store the thread's return value
    sched.return_values[sched.current_tid] = jitter.cpu.X0
    # Set the thread done event
    sched.thread_done[sched.current_tid].set()
    # Remove thread from runnable list
    del sched.threads[sched.current_tid]
    print(f'THREAD {Context.current.sched.current_tid} RETURNED')
    sched.current_tid = None
    # Switch out of this thread and bail
    Context.current.sched.context_switch(save_context=False)
    raise StopIteration

  # Only running within jitter as a transparent syncing mechanism
  @staticmethod
  def runiter_cb(jitter):
    #print(f'nb runnable threads: {Context.current.sched.runnable_threads}')
    if Context.current.sched.runnable_threads > 1:
      Context.current.sched.context_switch()
    return True

  def get_exit_code(self, tid):
    sched = Context.current.sched
    if sched.thread_done[tid]:
      return sched.return_values[tid]
    return None
