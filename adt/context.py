import logging, pickle, copy
from miasm.os_dep.linux_stdlib import c_linobjs

#logging
#logging.basicConfig(format='[%(filename)s:%(lineno)s] %(message)s')
log = logging.getLogger()

class Context(object):

  current = None

  def __init__(self, linuxenv, scheduler, javaenv, *args):
    self.linuxenv = linuxenv
    self.linuxenv.process_tid = None # Clear the current running thread
    self.sched = scheduler
    self.javaenv = javaenv
    self.linobjs = c_linobjs()
    for arg in args:
      self.additions = args

  @classmethod
  def set_current(cls, context):
    # Make ourselves the current context
    cls.current = context

  @classmethod
  def import_from_file(cls, filename='./context.pkl'):
    try:
      context = pickle.load(open(filename, 'rb'))
      log.warning(f'CONTEXT IMPORTED')
    except Exception as e:
      log.warning(f'CONTEXT IMPORT FAILED: {str(e)}')
      context = None
    # Make ourselves the current context
    cls.current = context
    return context

  def apply(self, jitter):
    # Setup the jitter with the current TID/PID and re-open the linuxenv files
    self.sched.reinitialize(jitter)
    # The memory pages are alreay present, only add the breakpoint callbacks
    self.javaenv.setup_jitter(jitter, add_mems=False)
    # Initialize to pick-up where we left off
    jitter.init_run(jitter.pc)
    log.warning(f'CONTEXT APPLIED')
    return

  def save_to_file(self):
    # Update current thread/proc from jitter
    self.sched.update()
    #  Get the current pc
    pc = self.sched.jitter.pc
    # Clear the jitter
    jitter= self.sched.jitter
    self.sched.jitter = None
    # And dump self to file
    pickle.dump(self, open(f'context_{pc:08X}.pkl', 'wb')) # overwrites
    # Restore
    self.sched.jitter = jitter
    log.warning(f'[{pc:08X}] CONTEXT SAVED')
