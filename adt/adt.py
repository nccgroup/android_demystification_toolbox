from miasm.os_dep.linux import environment
from adt.context import Context
from adt.scheduler import Scheduler
from adt.javavm import JavaEnv

def create_new_context(jitter, ret):
  linuxenv = environment.LinuxEnvironment_aarch64()
  sched =  Scheduler(jitter, linuxenv, ret)
  javaenv = JavaEnv(jitter)
  return Context(linuxenv, sched, javaenv)
