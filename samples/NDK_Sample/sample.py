import pickle, itertools, time
# Miasm stuff
from miasm.core.locationdb import LocationDB
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE
from miasm.core.utils import pck64
from miasm.os_dep.linux import syscall, environment
# Android toolbox
from adt.mt_sandbox import MTSandbox as Sandbox
from adt.scheduler import ContextSwitchException
from adt.context import Context, log
from adt.misc import THREAD_PTR, libc_base, parse_libc
from adt.javavm import *
from adt.jitter_callbacks import *

### KNOWN ADDRESSES
# binary: 0x0-0x1000000 (100 Mb)
# Stacks: 0x1100000-0x10000000
# THREAD: 0x1000000
# java: 0x10000000-0x20000000
# heap: 0x20000000+

def xxx_gettimeofday(jitter):
  ret_ad, args = jitter.func_args_systemv(['tv', 'tz'])
  assert args.tz == 0x0
  jitter.vm.set_u64(args.tv, int(time.time()))
  jitter.vm.set_u64(args.tv+0x8, 0)
  jitter.func_ret_systemv(ret_ad, 0x0) # success
  return True

def xxx_nanosleep(jitter):
  ret_ad, args = jitter.func_args_systemv(['reg', 'rem'])
  time.sleep(1) # Ignore actual values, just sleep 1 sec
  print(f'[{Context.current.sched.current_tid}]: quick nanosleep')
  jitter.func_ret_systemv(ret_ad, 0x0) # success
  return True

class com_example_hellojnicallback_JniHandler(JavaObj):

  def jinit(self):
    return self.address

  def updateStatus(self, msg):
    string = Context.current.javaenv.GetStringUTFChars(msg)
    if 'error' in string.lower():
      print('JniHandler Native Err: ' + string)
    else:
      print('JniHandler Native Msg: ' + string)

  def getBuildVersion(self):
    return UTFString('30').address

  def getRuntimeMemorySize(self):
    return 40000

def one_time_setup(sb):
  # Stack canary
  sb.jitter.vm.add_memory_page(libc_base+0xA4, PAGE_READ|PAGE_WRITE, pck64(THREAD_PTR+0x28), 'stack_canary_ptr')
  sb.jitter.vm.add_memory_page(THREAD_PTR+0x28, PAGE_READ|PAGE_WRITE, b'ABABABABCDCDCDCD', 'stack canary')

def main():
  global sb
  # Setup sandbox
  parser = Sandbox.parser(description='ELF sandboxer')
  parser.add_argument('filename', help='ELF Filename')
  options = parser.parse_args()
  options.jitter = 'llvm'
  sb = Sandbox(LocationDB(), options.filename, options, globals())
  one_time_setup(sb)

  # Register the custom class
  Context.current.javaenv.register_class('com/example/hellojnicallback/JniHandler',
    com_example_hellojnicallback_JniHandler)

  print('-- CALLING JNI_OnLoad')
  ret = sb.run(sb.loc_db.get_name_offset('JNI_OnLoad'), Context.current.javaenv.javavm_ptr)
  print(f'RETURN: {ret:08X}')
  print('--'*40)

  # Instantiate a MainActivity object (just a YesClass)
  print(f'Instantiating a MainActivity object')
  clazz = Context.current.javaenv.FindClass('com/example/hellojnicallback/MainActivity')
  ctor = Context.current.javaenv.GetMethodID(clazz, '<init>')
  mainActivityObj = Context.current.javaenv.CallMethod(clazz, ctor, []) # Call the constructor
  print('--'*40)

  log.warning('-- CALLING stringFromJNI')
  ret = sb.run(sb.loc_db.get_name_offset('Java_com_example_hellojnicallback_MainActivity_stringFromJNI'),
    Context.current.javaenv.javaenv_ptr, mainActivityObj)
  stringUTF = Context.current.javaenv.objects[ret].string
  print(f'RETURN: {stringUTF} ({ret:08X})')
  log.warning('--'*40)

  log.warning('-- CALLING startTicks')
  pid, tid = sb.run(sb.loc_db.get_name_offset('Java_com_example_hellojnicallback_MainActivity_startTicks'), \
    Context.current.javaenv.javaenv_ptr, mainActivityObj, sync=False) # async call
  print(f'NEW PROC: {pid} & NEW THREAD {tid}')

  # Run after 3 seconds
  time.sleep(3)

  print('-- CALLING StopTicks')
  # Create new thread in sandbox
  ret = sb.run(sb.loc_db.get_name_offset('Java_com_example_hellojnicallback_MainActivity_StopTicks'),
    Context.current.javaenv.javaenv_ptr, mainActivityObj, newthread=True)
  print(f'RETURN: {ret:08X}')
  print(f'[{pid}:{tid}]: {sb.get_exit_code(tid):08X}')
  print('--'*40)

if __name__ == '__main__':
  main()
