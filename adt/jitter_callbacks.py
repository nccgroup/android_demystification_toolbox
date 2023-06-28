import re, uuid, os, struct, time, zlib, functools
from ctypes import *
from errno import ENOENT
# miasm
from miasm.os_dep.linux import syscall
from miasm.os_dep.linux_stdlib import get_fmt_args
from miasm.os_dep.common import get_fmt_args as printf
from miasm.os_dep.linux.environment import FileDescriptorDirectory, FileDescriptorRegularFile
# adt
from adt.scanf_py3k import sscanf
from adt.misc import log, set_last_error, LAST_ERROR_PTR, varargs_to_list_aarch64, \
_dump_struct_stat_android_aarch64, pipe, SEEK_SET, SEEK_END
from adt.scheduler import FInfo, ContextSwitchException, NOTHREAD
from adt.context import Context
from adt.config import system_properties, auxvec, env, program_headers, shared_objects, auxtype
from adt.misc import get_file_access, faccess_convert, get_file_stats

# Convenience function to ignore call
def skip_fn_ret0(jitter):
  #import pdb; pdb.set_trace()
  ret_addr, _ = jitter.func_args_systemv([])
  jitter.func_ret_systemv(ret_addr, 0x0)
  return True

# Linker API

def xxx_dlsym(jitter):
  ret_addr, args = jitter.func_args_systemv(['handle', 'symbol'])
  # If we need to match the actual libc
  symbol = jitter.get_c_str(args.symbol)
  fname = f'xxx_{symbol}'
  addr = jitter.libs.cname2addr.get(fname, 0x0)
  if not addr and fname in globals():
    # symbol not found but implementation exists
    addr = max(jitter.libs.fad2cname)+0x10
    jitter.libs.cname2addr[fname] = addr
    jitter.libs.fad2cname[addr] = fname
    jitter.handle_function(addr)
  log.warning(f'dlsym: "{symbol}" <- {addr:08X}')
  jitter.func_ret_systemv(ret_addr, addr)
  return True

def xxx_dladdr(jitter):
  ret_addr, args = jitter.func_args_systemv(['addr', 'info'])
  log.warning(f'dladdr: {args.addr:08X}')
  jitter.func_ret_systemv(ret_addr, 0x0)
  return True

# memory operations

def xxx_malloc(jitter):
  ret_ad, args = jitter.func_args_systemv(["msize"])
  addr = Context.current.linobjs.heap.alloc(jitter, args.msize)
  log.warning(f'malloc({args.msize:04X}) <- {addr:08X})')
  jitter.func_ret_systemv(ret_ad, addr)
  return True

def xxx_calloc(jitter):
  ret_ad, args = jitter.func_args_systemv(['nmemb', 'size'])
  addr = Context.current.linobjs.heap.alloc(jitter, args.nmemb*args.size)
  log.warning(f'calloc({args.nmemb*args.size:04X}) <- {addr:08X})')
  jitter.func_ret_systemv(ret_ad, addr)
  return True

# int posix_memalign(void **memptr, size_t alignment, size_t size);
def xxx_posix_memalign(jitter):
  ret_ad, args = jitter.func_args_systemv(['memptr', 'alignment', 'size'])
  addr = Context.current.linobjs.heap.alloc(jitter, args.size)
  log.warning(f'xxx_posix_memalign({args.size:04X}) <- {addr:08X})')
  jitter.vm.set_u64(args.memptr, addr)
  jitter.func_ret_systemv(ret_ad, 0x0)
  return True

def xxx_realloc(jitter):
  ret_ad, args = jitter.func_args_systemv(['ptr', 'size'])
  addr = Context.current.linobjs.heap.alloc(jitter, args.size)
  # If given an alloc, copy its contents over
  if args.ptr:
    cur_size = Context.current.linobjs.heap.get_size(jitter.vm, args.ptr)
    oldbuf = jitter.vm.get_mem(args.ptr, cur_size)
    jitter.vm.set_mem(addr, oldbuf)
  jitter.func_ret_systemv(ret_ad, addr)
  return True

def xxx_free(jitter):
  ret_ad, args = jitter.func_args_systemv(["ptr"])
  jitter.func_ret_systemv(ret_ad, 0)
  return True

def xxx_memmove(jitter):
  ret_addr, args = jitter.func_args_systemv(['dest', 'src', 'n'])
  jitter.vm.set_mem(args.dest, jitter.vm.get_mem(args.src, args.n))
  jitter.func_ret_systemv(ret_addr, args.dest)
  return True

def xxx___memset_chk(jitter):
  ret_addr, args = jitter.func_args_systemv(['dest', 'c', 'n', 'dest_len'])
  jitter.vm.set_mem(args.dest, struct.pack('B', args.c&0xFF)*args.n)
  jitter.func_ret_systemv(ret_addr, args.dest)
  return True

# fd operations

xxx_open64  = lambda j: xxx_open(j)
xxx___open_2  = lambda j: xxx_open(j)
def xxx_open(jitter):
  ret_addr, args = jitter.func_args_systemv(['pathname', 'flags'])
  fname = jitter.get_c_str(args.pathname)
  mode = faccess_convert(args.flags)
  # Check if access explicitely restricted
  err = get_file_access(fname, mode, explicit=True)
  if err:
    fp = -1
    set_last_error(jitter, err)
  else:
    fp = Context.current.linuxenv.open_(fname, args.flags)
    if fp == -1:
      set_last_error(jitter, ENOENT) # Defaults to not found
  log.warning(f'open({fname}, {args.flags:08X}) <- {fp} (error= {err})')
  jitter.func_ret_systemv(ret_addr, fp)
  return True

def xxx_opendir(jitter):
  ret_addr, args = jitter.func_args_systemv(['name'])
  fname = jitter.get_c_str(args.name)
  err = get_file_access(fname, 0, explicit=True)
  if err:
    fp = 0
    set_last_error(jitter, err)
  else:
    fp = Context.current.linuxenv.open_(fname, Context.current.linuxenv.O_DIRECTORY)
    if fp == -1:
      fp = 0
      set_last_error(jitter, ENOENT) # Defaults to not found
  log.warning(f'open({fname}) <- {fp} (error= {err})')
  jitter.func_ret_systemv(ret_addr, fp)
  return True

def xxx_read(jitter):
  ret_addr, args = jitter.func_args_systemv(['fd', 'buf', 'count'])
  data = Context.current.linuxenv.read(args.fd, args.count)
  jitter.vm.set_mem(args.buf, data)
  jitter.func_ret_systemv(ret_addr, len(data))
  return True

def xxx___read_chk(jitter):
  #xxx_read(jitter)
  ret_addr , args = jitter.func_args_systemv(['fd', 'buf', 'count', 'bufsize'])
  assert args.count <= args.bufsize
  size = Context.current.linuxenv.file_descriptors[args.fd].size
  cur = Context.current.linuxenv.file_descriptors[args.fd].tell()
  available = size - cur
  fdesc = Context.current.linuxenv.file_descriptors[args.fd]
  log.warning(f'Reading {type(fdesc).__name__} at offset: {fdesc.tell():08X}')
  if args.count > available:
    log.warning(f'NOT ENOUGH DATA AVAILABLE TO READ (only {available} available)')
    # Dirty hack to replay the call instruction once data has been written to the pipe/file
    #raise ContextSwitchException(ret_addr-0x4)
    raise ContextSwitchException()
    # TODO: SWITCH TO JUST acquire()
  data = Context.current.linuxenv.read(args.fd, args.count)
  jitter.vm.set_mem(args.buf, data)
  jitter.func_ret_systemv(ret_addr, len(data))
  return True

dirents={}
def xxx_readdir(jitter):
  global dirents
  # define the struct
  class dirent (LittleEndianStructure):
    _fields_ = [
      ('d_ino', c_uint64),  #  Inode number
      ('d_off', c_uint64), # Not an offset
      ('d_reclen', c_ushort),  # Length of this record
      ('d_type', c_char),  # Type of file
      ('d_name', c_char*256)  # Type of file
    ]
  ret_addr, args = jitter.func_args_systemv(['dirp'])
  desc = Context.current.linuxenv.file_descriptors[args.dirp]
  try:
    filename = next(desc.listdir())
  except StopIteration:
    filename = None
    ret = 0x0
  if filename:
    # TODO: real inode, why not?
    # DT_UNKNOWN file type 0
    d = dirent(0x11223344, 0x55667788, sizeof(dirent), 0, filename.encode())
    # Get the structure pointer
    ret = dirents.setdefault(args.dirp, Context.current.linobjs.heap.alloc(jitter, sizeof(dirent)))
    jitter.vm.set_mem(ret, bytes(d))
  jitter.func_ret_systemv(ret_addr, ret)
  return True

xxx_lseek64  = lambda j: xxx_lseek(j)
def xxx_lseek(jitter):
  ret_addr, args = jitter.func_args_systemv(['fd', 'offset', 'whence'])
  offset = Context.current.linuxenv.file_descriptors[args.fd].lseek(args.offset, args.whence)
  jitter.func_ret_systemv(ret_addr, offset) # Return file offset!
  return True

xxx_closedir = lambda j: xxx_close(j)
def xxx_close(jitter):
  ret_addr, args = jitter.func_args_systemv(['fd'])
  ret = Context.current.linuxenv.close(args.fd)
  jitter.func_ret_systemv(ret_addr, ret)
  return True

def xxx_stat64(jitter):
  ret_addr, args = jitter.func_args_systemv(['pathname', 'statbuf'])
  fname = jitter.get_c_str(args.pathname)
  flags = Context.current.linuxenv.O_RDONLY
  if os.path.isdir(Context.current.linuxenv.filesystem.resolve_path(fname)):
    flags |= Context.current.linuxenv.O_DIRECTORY
  info = get_file_stats(fname, flags)
  if info:
    data = _dump_struct_stat_android_aarch64(info)
    jitter.vm.set_mem(args.statbuf, data)
    ret= 0
  else:
    ret= -1
    set_last_error(jitter, ENOENT)
  log.warning(f'fname= {fname} <= {ret}')
  jitter.func_ret_systemv(ret_addr, ret)
  return True

def xxx_pipe(jitter):
  ret_addr, args = jitter.func_args_systemv(['pipefd', 'flags'])
  assert args.flags==0
  # Create the pipe
  p = pipe()
  jitter.vm.set_u32(args.pipefd, p.fd1)
  jitter.vm.set_u32(args.pipefd+4, p.fd2)
  jitter.func_ret_systemv(ret_addr, 0)
  return True

def xxx_poll(jitter):
  ret_addr, args = jitter.func_args_systemv(['fds', 'nfds', 'timeout'])
  # This is a no-op in our current greedy execution design
  assert args.nfds==1
  waitable = jitter.vm.get_u16(args.fds)
  Context.current.sched.acquire(waitable)
  #raise ContextSwitchException(ret_addr-0x4)
  return True

# c string operations

# TODO: This is just strcpy, upgrade implementation
def xxx_strncpy(jitter):
  ret_ad, args = jitter.func_args_systemv(['dst', 'src', 'n'])
  str_src = jitter.get_c_str(args.src, args.n) + '\x00'
  jitter.vm.set_mem(args.dst, bytes(str_src))
  jitter.func_ret_systemv(ret_ad, args.dst)
  return True

def xxx_strstr(jitter):
  ret_ad, args = jitter.func_args_systemv(['haystack', 'needle'])
  h = jitter.get_c_str(args.haystack)
  n = jitter.get_c_str(args.needle)
  log.warning(f'haystack: "{h}", needle: "{n}"')
  index = h.find(n)
  log.warning('FOUND' if index!=-1 else 'NOT FOUND')
  jitter.func_ret_systemv(ret_ad, args.haystack+index if index!=-1 else 0x0)
  return True

def xxx_strchr(jitter):
  ret_ad, args = jitter.func_args_systemv(['s', 'c'])
  s = jitter.get_c_str(args.s)
  index = s.find(chr(args.c))
  jitter.func_ret_systemv(ret_ad, args.s+index if index!=-1 else 0x0)
  return True

def xxx_strncmp(jitter):
  ret_ad, args = jitter.func_args_systemv(['str1', 'str2', 'num'])
  s1 = jitter.get_c_str(args.str1, args.num)
  s2 = jitter.get_c_str(args.str2, args.num)
  log.warning(f'strncmp("{jitter.get_c_str(args.str1)}", "{jitter.get_c_str(args.str2)}")')
  jitter.func_ret_systemv(ret_ad, 0 if s1==s2 else 1)
  return True

def xxx_strcmp(jitter):
  ret_ad, args = jitter.func_args_systemv(['s1', 's2'])
  log.warning(f'strcmp("{jitter.get_c_str(args.s1)}", "{jitter.get_c_str(args.s2)}")')
  return linux_stdlib_xxx_strcmp(jitter)

def xxx_strtol(jitter):
  ret_addr, args = jitter.func_args_systemv(['nptr', 'endptr', 'base'])
  val = int(jitter.get_c_str(args.nptr), args.base)
  log.warning(f'val= {val}')
  jitter.func_ret_systemv(ret_addr, val)
  return True

def xxx_strtoul(jitter):
  ret_addr, args = jitter.func_args_systemv(['nptr', 'endptr', 'base'])
  val = int(jitter.get_c_str(args.nptr), args.base)
  log.warning(f'val= {val}')
  jitter.func_ret_systemv(ret_addr, val)
  return True

def xxx_atoi(jitter):
  ret_addr, args = jitter.func_args_systemv(['nptr'])
  val = int(jitter.get_c_str(args.nptr), 10)
  log.warning(f'val= {val}')
  jitter.func_ret_systemv(ret_addr, val)
  return True

def xxx_vfprintf(jitter):
  ret_addr, args = jitter.func_args_systemv(['stream', 'format', 'ap'])
  # Guess the number of params
  fstring = jitter.get_c_str(args.format)
  nbparams = fstring.count('%')
  fargs = varargs_to_list_aarch64(jitter, args.ap, max_args=nbparams)
  # Perform the format print
  get_str = lambda p,j=jitter: j.get_c_str(p)
  feeder = lambda i,t=fargs: t[i]
  output = printf(args.format, 0, get_str, feeder)
  # Get the stream
  info = Context.current.sched.FILE_to_info[args.stream]
  Context.current.linuxenv.file_descriptors[info.fdesc].write(output)
  jitter.func_ret_systemv(ret_addr, len(output))
  return True

def xxx_vsnprintf(jitter):
  ret_addr, args = jitter.func_args_systemv(['str', 'size', 'format', 'ap'])
  # Guess the number of params
  fstring = jitter.get_c_str(args.format)
  nbparams = fstring.count('%')
  fargs = varargs_to_list_aarch64(jitter, args.ap, max_args=nbparams)
  # Perform the format print
  get_str = lambda p,j=jitter: j.get_c_str(p)
  feeder = lambda i,t=fargs: t[i]
  output = printf(args.format, 0, get_str, feeder)
  jitter.set_c_str(args.str, output) # And let's hope it fits
  # Write it to dest
  log.warning(f'str({args.str:08X}) <- {output}')
  jitter.func_ret_systemv(ret_addr, len(output))
  return True

def xxx___vsnprintf_chk(jitter):
  ret_addr, args = jitter.func_args_systemv(['s', 'maxlen', 'flags', 'slen', 'format', 'ap'])
  # Guess the number of params
  fstring = jitter.get_c_str(args.format)
  # hack: replace format string
  fstring = re.sub(r'%ll(.)', r'%\1', fstring )
  fstring = re.sub(r'.*', r'', fstring ) # also ignore precision
  jitter.set_c_str(args.format, fstring)
  nbparams = fstring.count('%')
  fargs = varargs_to_list_aarch64(jitter, args.ap, max_args=nbparams)
  # Perform the format print
  get_str = lambda p,j=jitter: j.get_c_str(p)
  feeder = lambda i,t=fargs: t[i]
  output = printf(args.format, 0, get_str, feeder)
  jitter.set_c_str(args.s, output) # And let's hope it fits
  # Write it to dest
  log.warning(f'str({args.s:08X}) <- {output}')
  jitter.func_ret_systemv(ret_addr, len(output))
  return True

def xxx_asprintf(jitter):
  # Capture args
  ret_addr, args = jitter.func_args_systemv(['strp', 'fmt'])
  cur_arg = 2
  fmt = args.fmt
  # Perform sprintf
  output = get_fmt_args(jitter, args.fmt, cur_arg)
  # Allocate mem
  addr = Context.current.linobjs.heap.alloc(jitter, len(output)+1) # string len + null terminator
  # Write output
  jitter.vm.set_u64(args.strp, addr)
  jitter.set_c_str(addr, output)
  log.warning(f'asprintf: {jitter.get_c_str(args.fmt)} - > {jitter.get_c_str(addr)}')
  jitter.func_ret_systemv(ret_addr, len(output))
  return True

def xxx_isspace(jitter):
  ret_addr, args = jitter.func_args_systemv(['c'])
  ret = 1 if chr(args.c).isspace() else 0
  log.warning(f'isspace({chr(args.c)}) {ret}')
  jitter.func_ret_systemv(ret_addr, ret)
  return True

def xxx_isblank(jitter):
  ret_addr, args = jitter.func_args_systemv(['c'])
  ret = 1 if chr(args.c) in [' ', '\t'] else 0
  log.warning(f'isspace({chr(args.c)}) {ret}')
  jitter.func_ret_systemv(ret_addr, ret)
  return True

## Thread creation, sync and TLS

def xxx_pthread_create(jitter):
  ret_addr, args = jitter.func_args_systemv(['newthread', 'attr', 'start_routine', 'arg'])
  new_tid = Context.current.sched.new_thread(args.start_routine, args.arg)
  jitter.vm.set_u32(args.newthread, new_tid) # 64 ?
  jitter.func_ret_systemv(ret_addr, 0x0)
  return True

def xxx_pthread_key_create(jitter):
  ret_addr, args = jitter.func_args_systemv(['key', 'destructor'])
  keyid = uuid.uuid4().int & (1<<32)-1
  Context.current.sched.pthread_keys.setdefault(Context.current.sched.current_tid, {})[keyid] = 0x0
  jitter.vm.set_u32(args.key, keyid)
  log.warning(f'Key created: {keyid:08X}')
  jitter.func_ret_systemv(ret_addr, 0x0)
  return True

def xxx_pthread_getspecific(jitter):
  ret_addr, args = jitter.func_args_systemv(['key'])
  try:
    value = Context.current.sched.pthread_keys[Context.current.sched.current_tid][args.key]
    log.warning(f'KEY: {args.key:08X}\n VAL: {value:08X}')
  except KeyError:
    value = 0x0
    log.warning(f'KEY: {args.key:08X}\n VAL: {value:08X} (NOT FOUND)')
  jitter.func_ret_systemv(ret_addr, value)
  return True

def xxx_pthread_setspecific(jitter):
  ret_addr, args = jitter.func_args_systemv(['key', 'value'])
  if args.key in Context.current.sched.pthread_keys[Context.current.sched.current_tid]:
    Context.current.sched.pthread_keys[Context.current.sched.current_tid][args.key] = args.value
    log.warning(f'KEY: {args.key:08X}= {args.value}')
    ret = 0
  else:
    log.warning(f'KEY: {args.key:08X} NOT FOUND')
    ret = 2 # NOT FOUND ?
  jitter.func_ret_systemv(ret_addr, ret)
  return True

def xxx_pthread_mutex_init(jitter):
  ret_addr, args = jitter.func_args_systemv(['mutex'])
  jitter.func_ret_systemv(ret_addr, 0) # Return 0 SUCCESS
  return True

def xxx_pthread_mutex_lock(jitter):
  ret_addr, args = jitter.func_args_systemv(['mutex'])
  jitter.func_ret_systemv(ret_addr, 0) # Return 0 SUCCESS
  # Handle the sync
  Context.current.sched.acquire(args.mutex)
  return True

def xxx_pthread_mutex_unlock(jitter):
  ret_addr, args = jitter.func_args_systemv(['mutex'])
  Context.current.sched.release(args.mutex) # Always works
  jitter.func_ret_systemv(ret_addr, 0) # Return 0 SUCCESS
  return True

# typedef struct priority_queue_node {
#   struct priority_queue_node *next;
#   uint32_t priority;
#   unsigned int data;
# } priority_queue_node_t;

def xxx_pthread_cond_wait(jitter):
  sched = Context.current.sched
  ret_addr, args = jitter.func_args_systemv(['cond', 'mutex'])
  c = jitter.vm.get_u32(args.cond+0x0C)
  #c = sched.cond.setdefault(args.cond, False)
  # Check whether the condition is ready
  print(f'({sched.current_pid}:{sched.current_tid}) cond: {c}')
  if c == 0:
    # Associate the condition with the mutex
    #sched.cond[args.cond] = (args.mutex, sched.current_tid)
    # Release the mutex to give another thread a chance to set the condition
    sched.release(args.mutex, reacquire=True)
    # Wait on the condition (this will trigger a context switch)
    #sched.acquire(args.cond, tid=NOTHREAD, rewait=True)
  jitter.func_ret_systemv(ret_addr, 0x0)
  return True

def xxx_pthread_cond_signal(jitter):
  sched = Context.current.sched
  ret_addr, args = jitter.func_args_systemv(['cond'])
  # Set the condition to True
  c = jitter.vm.set_u32(args.cond+0x0C, 0x1)
  # Reacquire the corresponding mutex on behalf of the condition-waiting thread
  #mutex, tid = Context.current.sched.cond[args.cond]
  #sched.acquire(mutex, tid=tid)
  # Release the condition to unlock the condition-waiting thread
  #sched.release(args.cond)
  jitter.func_ret_systemv(ret_addr, 0x0)
  return True

def xxx_pthread_cond_broadcast(jitter):
  assert False
  ret_addr, args = jitter.func_args_systemv(['cond'])
  c = Context.current.sched.cond[args.cond] = True
  jitter.func_ret_systemv(ret_addr, 0x0)
  return True

def xxx_pthread_mutexattr_settype(jitter):
  log.warning('SKIPPING pthread_mutexattr_settype')
  return skip_fn_ret0(jitter)

def xxx_pthread_attr_init(jitter):
  log.warning('SKIPPING pthread_attr_init')
  return skip_fn_ret0(jitter)

def xxx_pthread_mutexattr_init(jitter):
  log.warning('SKIPPING pthread_mutexattr_init')
  return skip_fn_ret0(jitter)

def xxx_pthread_mutex_destroy(jitter):
  log.warning('SKIPPING pthread_mutexattr_init')
  return skip_fn_ret0(jitter)

def xxx_pthread_attr_setdetachstate(jitter):
  log.warning('SKIPPING pthread_attr_setdetachstate')
  return skip_fn_ret0(jitter)

def xxx_pthread_attr_destroy(jitter):
  log.warning('SKIPPING pthread_attr_destroy')
  return skip_fn_ret0(jitter)

# process stuff

def xxx_fork(jitter):
  ret_ad, _ = jitter.func_args_systemv([])
  jitter.func_ret_systemv(ret_ad, 0x0)
  # Save the child's state
  pid = Context.current.sched.new_process(ret_ad)
  Context.current.sched.genealogy.setdefault(Context.current.sched.current_pid, set()).add(pid)
  #tid = Context.current.sched.save_state(new_thread=True, new_proc=True) # Save child context
  jitter.cpu.X0 = pid # Keep running the parent
  return True

def xxx_waitpid(jitter):
  ret_addr, args = jitter.func_args_systemv(['pid', 'wstatus', 'options'])
  jitter.func_ret_systemv(ret_addr, 0x0)
  # Handle the sync
  # TODO: WHEN WAITING ON SIGNALS, INSTRUCT THE SCHEDULER TO NOT HOLD THE LOCK
  Context.current.sched.acquire(args.pid)
  return True

dumpable = {}
def xxx_prctl(jitter):
  ret_addr, args = jitter.func_args_systemv(['option', 'arg2', 'arg3', 'arg4', 'arg5'])
  if args.option==4 and args.arg2==1:
    log.warning('prctl setting DUMPABLE to ALLOW PTRACE')
    dumpable[Context.current.sched.current_pid] = True
  elif args.option==4 and args.arg2==0:
    log.warning('prctl setting DUMPABLE to DISALLOW PTRACE')
    dumpable[Context.current.sched.current_pid] = False
  elif args.option==15:
    thread_name = jitter.get_c_str(args.arg2, 16)
    log.warning(f'prctl PR_SET_NAME: "{thread_name}"')
  elif args.option==0x59616d61:
    log.warning(f'prctl setting ALLOWED PTRACER to {args.arg2}')
  else:
    log.warning(f' !!! prctl UNIMPLEMENTED SETTING {args.option:08X} !!!!')
    import pdb; pdb.set_trace()
  jitter.func_ret_systemv(ret_addr, 0x0)
  return True

def xxx_getpid(jitter):
  ret_addr, _ = jitter.func_args_systemv([])
  ret = Context.current.sched.current_pid
  jitter.func_ret_systemv(ret_addr, ret)
  return True

def xxx_getppid(jitter):
  ret_addr, _ = jitter.func_args_systemv([])
  ppid = [parent for parent, children in Context.current.sched.genealogy.items() if Context.current.linuxenv.process_pid in children][0]
  jitter.func_ret_systemv(ret_addr, ppid)
  return True

def xxx___cxa_atexit(jitter):
  ret_ad, args = jitter.func_args_systemv(['func', 'arg', 'dso_handle'])
  log.warning('REGISTERING SO-unload callback: ' + hex(args.func))
  jitter.func_ret_systemv(ret_ad, 0x0) # Return sucess
  return True

## File streams

xxx_fopen64  = lambda j: xxx_fopen(j)
def xxx_fopen(jitter):
  global my_FILE_ptr
  ret_addr, args = jitter.func_args_systemv(['filename', 'mode'])
  fname = jitter.get_c_str(args.filename)
  mode = jitter.get_c_str(args.mode)
  assert mode=='r'
  log.warning('fopen: ' + fname + ' ' + mode)
  fp = Context.current.linuxenv.open_(fname, Context.current.linuxenv.O_RDONLY)
  log.warning('fp: ' + str(fp))
  if fp != -1:
    Context.current.sched.FILE_to_info[Context.current.sched.my_FILE_ptr] = FInfo(fname, fp)
    jitter.func_ret_systemv(ret_addr, Context.current.sched.my_FILE_ptr)
    log.warning('returning ' + hex(Context.current.sched.my_FILE_ptr))
    Context.current.sched.my_FILE_ptr += 1
  else:
    jitter.func_ret_systemv(ret_addr, 0x0)
  return True

def xxx_fseeko(jitter):
  return xxx_fseek(jitter)

def xxx_fseek(jitter):
  ret_addr, args = jitter.func_args_systemv(['stream', 'offset', 'origin'])
  info = Context.current.sched.FILE_to_info[args.stream]
  Context.current.linuxenv.file_descriptors[info.fdesc].lseek(args.offset, args.origin)
  jitter.func_ret_systemv(ret_addr, 0x0) # Return success
  return True

def xxx_fread(jitter):
    ret_addr, args = jitter.func_args_systemv(['ptr', 'size', 'nmemb', 'stream'])
    info = Context.current.sched.FILE_to_info[args.stream]
    #data = info.fdesc.read(args.size * args.nmemb)
    data = Context.current.linuxenv.read(info.fdesc, args.size * args.nmemb)
    jitter.vm.set_mem(args.ptr, data)
    jitter.func_ret_stdcall(ret_addr, len(data))
    return True

def xxx_fgets(jitter):
  ret_addr, args = jitter.func_args_systemv(['str', 'num', 'stream'])
  # Get file descriptor
  info = Context.current.sched.FILE_to_info[args.stream]
  cur = Context.current.linuxenv.file_descriptors[info.fdesc].tell()
  # Get file pointer
  data = Context.current.linuxenv.read(info.fdesc, args.num)
  # Only get the first line
  if data:
    string = data.splitlines()[0]
    # Ajust the file pointer
    Context.current.linuxenv.file_descriptors[info.fdesc].seek(cur+len(string)+1)
    log.warning(f'fgets: {string}')
    # Write result out
    jitter.vm.set_mem(args.str, string+b'\x00')
    jitter.func_ret_systemv(ret_addr, args.str)
  else:
    jitter.func_ret_systemv(ret_addr, 0x0)
  return True

def xxx_fclose(jitter):
  ret_addr, args = jitter.func_args_systemv(['stream'])
  del Context.current.sched.FILE_to_info[args.stream]
  jitter.func_ret_systemv(ret_addr, 0)
  return True

# scanf

def xxx_sscanf(jitter):
  ret_ad, args = jitter.func_args_systemv(['str', 'format'])
  s = jitter.get_c_str(args.str)
  f = jitter.get_c_str(args.format)
  log.warning(f'format string: {f}\nstr: {s}')
  # Handle lib implementation limitations
  f = re.sub(r'%l(.)', r'%\1', f)
  f = re.sub(r'%\d+s', r'%s', f)
  f = re.sub(r'%li', r'%i', f)
  log.warning(f'fixed format string: {f}')
  try:
    parsed = sscanf(s, f)
  except:
    parsed = False
  if parsed:
    for i, v in enumerate(parsed):
      dest = jitter.get_arg_n_systemv(i+2)
      if type(v) is int:
        # TODO THIS IS BAD: SUPER DIRTY HACK
        if v > 0xFFFFFFFF:
          jitter.vm.set_u64(dest, v)
        else:
          jitter.vm.set_u32(dest, v)
        #jitter.vm.set_u64(dest, v)
        log.warning(f'[{dest:08X}] <- {v:08X}')
        jitter.func_ret_systemv(ret_ad, len(parsed))
      elif type(v) is str:
        jitter.vm.set_mem(dest, v.encode('ascii')+b'\x00')
        log.warning(f'[{dest:08X}] <- {v}')
        jitter.func_ret_systemv(ret_ad, len(parsed))
    return True
  # PARSING FAILED
  log.warning('sscanf FAIL')
  jitter.func_ret_systemv(ret_ad, 0x0) # Failed parse
  return True

# gzip decompression

def xxx_inflateInit2_(jitter):
  ret_addr, args = jitter.func_args_systemv(['strm', 'windowBits', 'version', 'stream_size'])
  next_in, avail_in, _, total_in, next_out, avail_out, _,  total_out, msg, state, zalloc, zfree, opaque, data_type, _, adler, reserved \
  = struct.unpack('QIIQQIIQQQQQQiIQQ', jitter.vm.get_mem(args.strm, 112))
  log.warning(f'strm: {next_in:08X}, {avail_in:08X}, {total_in:08X}, {next_out:08X}, {avail_out:08X}, {total_out:08X}, {msg:08X}, {state:08X}, {zalloc:08X}, {zfree:08X}, {opaque:08X}, {data_type:08X}, {adler:08X}, {reserved}')
  jitter.func_ret_systemv(ret_addr, 0x0) # Z_OK
  return True

def xxx_inflate(jitter):
  ret_addr, args = jitter.func_args_systemv(['stream', 'flush'])
  next_in, avail_in, _, total_in, next_out, avail_out, _,  total_out, msg, state, zalloc, zfree, opaque, data_type, _, adler, reserved \
  = struct.unpack('QIIQQIIQQQQQQiIQQ', jitter.vm.get_mem(args.stream, 112))
  buf = jitter.vm.get_mem(next_in, avail_in)
  # Decompress into output buffer
  decomp = zlib.decompress(buf, -15)
  jitter.vm.set_mem(next_out, decomp)
  # Update stream structure's in fields
  jitter.vm.set_u64(args.stream+0, next_in+len(buf)) # next_in increase
  jitter.vm.set_u32(args.stream+8, avail_in-len(buf)) # avail_in decrease
  jitter.vm.set_u64(args.stream+16, total_in+len(buf)) # total_in increase
  # Update stream structure's out fields
  jitter.vm.set_u64(args.stream+24, next_out+len(decomp)) # next_out increase
  jitter.vm.set_u32(args.stream+32, avail_out-len(decomp)) # avail_out decrease
  jitter.vm.set_u64(args.stream+40, total_out+len(decomp)) # total_out increase
  # TODO ? Update adler32 field
  #adler = zlib.adler32(data[, value])
  jitter.func_ret_systemv(ret_addr, 0x1) # Z_STREAM_END
  return True

def xxx_inflateEnd(jitter):
  ret_addr, args = jitter.func_args_systemv(['stream'])
  jitter.func_ret_systemv(ret_addr, 0x0) # Z_OK
  return True

# time handling

def xxx_time(jitter):
  ret_ad, args = jitter.func_args_systemv(['tloc'])
  assert args.tloc == 0x0
  jitter.func_ret_systemv(ret_ad, int(time.time()))

def xxx_mktime(jitter):
  ret_ad, args = jitter.func_args_systemv(['tm'])
  # Capture the tm data
  tm_data = jitter.vm.get_mem(args.tm, 0x24)
  tm_sec, tm_min, tm_hour, tm_mday, tm_mon, tm_year, tm_wday, tm_yday, tm_isdst = struct.unpack('iiiiiiiii', tm_data)
  log.warning(f'sec: {tm_sec}, min: {tm_min}, hour: {tm_hour}, day: {tm_mday}, month: {tm_mon}, year: {tm_year}, wday: {tm_wday}, yday: {tm_yday}, isdst: {tm_isdst}')
  try:
    # Careful here, the year starts at 1900 and the month is 1-12
    dt = time.mktime((1900+tm_year, tm_mon+1, tm_mday, tm_hour, tm_min, tm_sec, tm_wday, tm_yday, tm_isdst))
    ret = int(dt)
    log.warning(f'{str(dt)} -> {ret:08X}')
  except ValueError as e:
    log.warning(str(e))
    ret = -1
    pass
  if tm_year==80:
    ret = 0
  jitter.func_ret_systemv(ret_ad, ret)
  return True

def xxx_crc32(jitter):
  ret_ad, args = jitter.func_args_systemv(["crc", "buf", "len"])
  databuf = jitter.vm.get_mem(args.buf, args.len) if args.len else b''
  retval = zlib.crc32(databuf, args.crc)
  log.warning(f'CRC32: {retval:08X}')
  jitter.func_ret_systemv(ret_ad, retval)
  return True

# mimic android

def xxx_uname(jitter):
  ret_addr, args = jitter.func_args_systemv(['name'])
  # System
  system = 'linux'
  jitter.set_c_str(args.name+65*0, system)
  # Node
  node = 'localhost'
  jitter.set_c_str(args.name+65*1, node)
  # Release
  release = '2.2147483648' # Not sure why, but this gets me through
  jitter.set_c_str(args.name+65*2, release)
  # Version
  version = 'Wed Jan 30 07:13:09 UTC 2021'
  jitter.set_c_str(args.name+65*3, version)
  # Machine
  machine = 'armv8l'
  jitter.set_c_str(args.name+65*4, machine)
  # Done
  jitter.func_ret_systemv(ret_addr, 0x0)
  return True

# Error handling

def xxx___errno(jitter):
  ret_addr, args = jitter.func_args_systemv([])
  err = jitter.vm.get_u32(LAST_ERROR_PTR)
  log.warning(f'last error: ({err:08X})')
  jitter.func_ret_systemv(ret_addr, LAST_ERROR_PTR) # NB: This function returns a pointer
  return True

# Android properties

def xxx___system_property_get(jitter):
  ret_ad, args = jitter.func_args_systemv(['name', 'value'])
  key = jitter.get_c_str(args.name)
  val = system_properties.get(key)
  if val:
    log.warning(f'__system_property_get({key}, {args.value:08X}) <- {val}')
    jitter.vm.set_mem(args.value, val.encode('ascii')+b'\x00')
  else:
    jitter.vm.set_mem(args.value, b'\x00')
    log.warning(f'__system_property_get({key}, {args.value:08X}) <- NOT FOUND')
  jitter.func_ret_systemv(ret_ad, len(val) if val else 0x0)
  return True

# signals

#sig_handlers = {}
def xxx_sigaction(jitter):
  ret_addr, args = jitter.func_args_systemv(['signum', 'act', 'oldact'])
  handler = jitter.vm.get_u64(args.act+0x8)
  jitter.exceptions_handler.set_callback(args.signum, handler)
  #sig_handlers[args.signum] = handler
  log.warning(f'sa_handler: {handler:08X}\nsa_mask: {jitter.vm.get_u64(args.act+0x10):08X}')
  jitter.func_ret_systemv(ret_addr, 0x0)
  return True

contexts = {}
def xxx_sigsetjmp(jitter):
  ret_addr, args = jitter.func_args_systemv(['env', 'savesigs'])
  contexts[args.env] = Context.current.sched.save_state()
  jitter.func_ret_systemv(ret_addr, 0x0)
  return True

def xxx_siglongjmp(jitter):
  ret_addr, args = jitter.func_args_systemv(['env', 'val'])
  Context.current.sched.restore_state(contexts[args.env])
  jitter.func_ret_systemv(ret_addr, val)
  return True

def xxx_kill(jitter):
  ret_addr, args = jitter.func_args_systemv(['pid', 'sig'])
  #del Context.current.sched.procs[args.pid]
  # TODO: ALSO DELETE THREADS
  log.warning('TODO: IMPLEMENT THIS NOOP')
  #import pdb; pdb.set_trace()
  jitter.func_ret_systemv(ret_addr, 0)
  return True

# misc

MAX_STRING_LEN = 0x1000000
def xxx___ctype_get_mb_cur_max(jitter):
  ret_addr, args = jitter.func_args_systemv([])
  jitter.func_ret_systemv(ret_addr, MAX_STRING_LEN)
  return True

def xxx_mbtowc(jitter):
  ret_addr, args = jitter.func_args_systemv(['pwc', 's', 'n'])
  ret = 0x0
  if args.pwc:
    cstr = jitter.get_c_str(args.s, args.n)
    ustr = cstr.encode('utf-8')
    print(f'{args.pwc:08X} <- {ustr}')
    jitter.vm.set_mem(args.pwc, ustr)
    ret = len(cstr)
  jitter.func_ret_systemv(ret_addr, ret)
  return True

def xxx_mprotect(jitter):
  # Just ignore
  ret_addr, args = jitter.func_args_systemv(['addr', 'size', 'prot'])
  # Break here to catch self-modifying code
  #if args.prot == 0x5:
  #  import pdb; pdb.set_trace()
  jitter.func_ret_systemv(ret_addr, 0x0)
  return True

def xxx_access(jitter):
  ret_addr, args = jitter.func_args_systemv(['pathname', 'mode'])
  filename = jitter.get_c_str(args.pathname)
  requested_mode = args.mode
  error = get_file_access(filename, requested_mode)
  ret = -1 if error else 0
  if ret:
    set_last_error(jitter, error)
  log.warning(f'filename: {filename} <- {ret}')
  jitter.func_ret_systemv(ret_addr, ret)
  return True

def xxx_dlopen(jitter):
  ret_addr, args = jitter.func_args_systemv(['filename', 'flags'])
  filename = jitter.get_c_str(args.filename) if args.filename else 'null'
  ret = shared_objects.get(filename, 0x0)
  log.warning(f'filename: {filename} <- {ret:08X}')
  jitter.func_ret_systemv(ret_addr, ret)
  return True

def xxx_dl_iterate_phdr(jitter):
  # Utils to break on callback return
  BOGUS_ADDRESS = 0xFEFEFEFE
  class EndcallbackException(Exception):
    pass
  def callback_end(jitter):
    raise EndcallbackException()
    return True
  # Define the callback's expected struture
  class dl_phdr_info(LittleEndianStructure):
    j = jitter
    _fields_ = [
       ('dlpi_addr', c_uint64),  #  Base address of object
       ('dlpi_name', POINTER(c_char)), # null-terminated name of object
       ('dlpi_phdr', c_void_p),  # Pointer to array of ELF program headers for this object
       ('dlpi_phnum', c_uint32)  # Numer of items in dlpi_phdr
    ]
       # The following fields were added in glibc 2.4, after the first
       # version of this structure was available.  Check the size
       # argument passed to the dl_iterate_phdr callback to determine
       # whether or not each later member is available.

       # unsigned long long int dlpi_adds; // Incremented when a new object may have been added
       # unsigned long long int dlpi_subs; // Incremented when an object may have been removed
       # size_t dlpi_tls_modid; // If there is a PT_TLS segment, its module ID as used in TLS relocations,
       # else zero
       # void  *dlpi_tls_data; // The address of the calling thread's instance of this module's PT_TLS segment,        # if it has one and it has been allocated in the calling thread, otherwise a null pointer

    # Constructor also maps in jtter's VM
    def __init__(self, addr, name, phdr, phnum):
      pname = Context.current.linobjs.heap.alloc(self.j, len(name)+1)
      self.j.vm.set_mem(pname, name.encode()+b'\x00')
      super().__init__(addr, cast(pname, POINTER(c_char)), phdr, phnum)
      self.ptr = Context.current.linobjs.heap.alloc(self.j, sizeof(self))
      self.j.vm.set_mem(self.ptr, bytes(self))

  shared_objects = [dl_phdr_info(*ph) for ph in program_headers]
  ret_addr, args = jitter.func_args_systemv(['callback', 'data'])
  # Allocate memory for phdr info structure
  jitter.add_breakpoint(BOGUS_ADDRESS, callback_end)
  for so in shared_objects:
    jitter.init_run(args.callback)
    jitter.func_prepare_systemv(BOGUS_ADDRESS , so.ptr, sizeof(so))
    try:
      jitter.continue_run()
    except EndcallbackException:
      pass
  jitter.remove_breakpoints_by_address(BOGUS_ADDRESS)
  # Returns the last function's return code
  ret = jitter.cpu.X0
  jitter.func_ret_systemv(ret_addr, ret)
  return True

def xxx_getauxval(jitter):
  ret_addr, args = jitter.func_args_systemv(['type'])
  ret = auxvec.get(auxtype[args.type], 0)
  log.warning(f'Requesting: {args.type} <- {ret}')
  #TODO when returning zero here (base address for example), ensure they don't interpret that as failure
  jitter.func_ret_systemv(ret_addr, ret)
  return True

watch = None
def xxx_inotify_init(jitter):
  global watch
  ret_addr, args = jitter.func_args_systemv([])
  # Returning inode to empty file so calls to read() just hang
  watch = Context.current.linuxenv.open_('/dev/watch0', 0)
  jitter.func_ret_systemv(ret_addr, watch)
  return True

def xxx_inotify_add_watch(jitter):
  ret_addr, args = jitter.func_args_systemv(['fd', 'pathname', 'mask'])
  log.warning(f'inotify_add_watch("{jitter.get_c_str(pathnamename)}") <- 0x11223344')
  assert args.fd == watch
  jitter.func_ret_systemv(ret_addr, 0x11223344) # watch descripor is unused
  return True

def xxx_strerror(jitter):
  ret_addr, args = jitter.func_args_systemv(['errnum'])
  error_string = os.strerror(args.errnum)
  addr = Context.current.linobjs.heap.alloc(jitter, len(error_string)+1)
  jitter.set_c_str(addr, error_string)
  jitter.func_ret_systemv(ret_addr, addr)
  return True

def xxx_getenv(jitter):
  ret_addr, args = jitter.func_args_systemv(['name'])
  name = jitter.get_c_str(args.name)
  value = env[name]
  addr = Context.current.linobjs.heap.alloc(jitter, len(value)+1) # string len + null terminator
  jitter.set_c_str(addr, value)
  log.warning(f'getenv("{name}") <- "{value}"')
  jitter.func_ret_systemv(ret_addr, addr)
  return True

locale_ptr = 0x34534646
def xxx_newlocale(jitter):
  ret_addr, args = jitter.func_args_systemv(['category_mask', 'locale', 'base'])
  jitter.func_ret_systemv(ret_addr, locale_ptr)
  return True

def xxx_uselocale(jitter):
  ret_addr, args = jitter.func_args_systemv(['newloc'])
  jitter.func_ret_systemv(ret_addr, locale_ptr)
  return True

def xxx_exit(jitter):
  ret_addr, args = jitter.func_args_systemv(['status'])
  jitter.func_ret_systemv(ret_addr, 0x0)
  return False

def xxx_usleep(jitter):
  ret_addr, args = jitter.func_args_systemv(['usec'])
  # NOP
  jitter.func_ret_systemv(ret_addr, 0)
  return True

def xxx___android_log_print(jitter):
  ret_addr, args = jitter.func_args_systemv(['prio', 'tag', 'fmt', 'arg0', 'arg1', 'arg2', 'arg3', 'arg4', 'arg5'])
  get_str = lambda p,j=jitter: j.get_c_str(p)
  feeder = lambda i,t=args[3:]: t[i]
  output = printf(args.fmt, 0, get_str, feeder)
  print(f'android_log: {output}')
  jitter.func_ret_systemv(ret_addr, 0)
  return True

# syscalls

def xxx_syscall(jitter):
  ret_addr, args = jitter.func_args_systemv(['number'])
  # Dispatch to SYSCALL stub
  ret_addr, args = jitter.func_args_systemv(['number', 'arg0', 'arg1', 'arg2', 'arg3', 'arg4', 'arg5'])
  fn = syscalls.get(args.number, None)
  if fn:
    ret = fn(jitter, Context.current.linuxenv, args[1:])
  else:
    assert False
  if ret < 0:
    set_last_error(-ret)
    ret = -1
  jitter.func_ret_systemv(ret_addr, ret)
  return True

def get_syscall_ret(jitter):
  return jitter.cpu.LR

def sys_arm64_faccessat(jitter, linuxenv, args):
  dirfd, pathname, mode, flags = args[:4]
  filename = jitter.get_c_str(pathname)
  assert filename[0] == '/' # we only handle absolute path case
  ret = -get_file_access(filename, mode)
  log.warning(f'[{get_syscall_ret(jitter):08X}] sys_arm64_faccessat(dirfd={dirfd:08X}, filename="{filename}", mode={mode:08X}, flags={flags:08X}) <- {ret}')
  return ret

def sys_arm64_readlinkat(jitter, linuxenv, args):
  dirfd, pathname, buf, bufsiz = args[:4]
  pathname = jitter.get_c_str(pathname)
  assert pathname[0] == '/' # we only handle absolute path case
  ret = get_file_access(pathname, 0, explicit=True)
  if ret == 0:
    filename = pathname.split('/')[-1]
    # Pretend the our backend regular file is a link and read its content
    target = f't_{filename}'
    jitter.set_c_str(buf, target)
    ret = len(target)+1
  else:
    ret = -ret
  log.warning(f'[{get_syscall_ret(jitter):08X}] sys_arm64_readlinkat(dirfd={dirfd:08X}, pathname="{pathname}", buf={buf:08X}, bufsiz={bufsiz:08X}) <- {ret}')
  return ret

def sys_arm64_arch_read(jitter, linuxenv, args):
  # Parse arguments
  fd, buf, count = args[:3]
  data = linuxenv.read(fd, count)
  log.warning(f'[{get_syscall_ret(jitter):08X}] sys_read({fd}, {buf:08X}, {count})')
  jitter.vm.set_mem(buf, data)
  return len(data)

def sys_arm64_arch_write(jitter, linuxenv, args):
  # Parse arguments
  fd, buf, count = args[:3]
  data = jitter.vm.get_mem(buf, count)
  log.warning(f'[{get_syscall_ret(jitter):08X}] sys_write({fd}, {buf:08X}, {count}) <- {data}')
  ret = linuxenv.write(fd, data)
  return ret

def sys_arm64_arch_exit_group(jitter, linuxenv, args):
  assert False # ERROR PATH
  status, = args[:1]
  log.warning(f'[{get_syscall_ret(jitter):08X}] sys_exit_group({status:08X})')
  del scheduler.procs[Context.current.sched.current_pid]
  for t, p in scheduler.t2p.items():
    if p == Context.current.sched.current_pid:
      del scheduler.threads[t]

def sys_arm64_arch_gettid(jitter, linuxenv, args):
  log.warning(f'[{get_syscall_ret(jitter):08X}] sys_gettid() <- {Context.current.sched.current_tid}')
  return Context.current.sched.current_tid

def sys_arm64_arch_getpid(jitter, linuxenv, args):
  log.warning(f'[{get_syscall_ret(jitter):08X}] sys_getpid() <- {Context.current.sched.current_pid}')
  return Context.current.sched.current_pid

# NOT ALLOWED
def sys_arm64_arch_socket(jitter, linuxenv, args):
  log.warning(f'[{get_syscall_ret(jitter):08X}] socket() <- NOT ALLOWED')
  return -1

def sys_arm64_arch_setsockopt(jitter, linuxenv, args):
  sockfd, level, optname, optval, optlen, = args[:5]
  log.warning(f'[{get_syscall_ret(jitter):08X}] setsockopt(...) <- NOT ALLOWED')
  return -1

def sys_arm64_fstatat(jitter, linuxenv, args):
  dirfd, pathname, statbuf, flags = args[:4]
  fname = jitter.get_c_str(pathname)
  assert fname[0] == '/' # we only handle absolute path case
  log.warning(f'[{get_syscall_ret(jitter):08X}] sys_arm64_fstatat(dirfd={dirfd:08X}, pathname={fname}, statbuf={statbuf:08X}, flags={flags:08X})')
  if os.path.isdir(Context.current.linuxenv.filesystem.resolve_path(fname)):
    flags |= Context.current.linuxenv.O_DIRECTORY
  info = get_file_stats(fname, flags)
  if info:
    log.warning(f'fstat info: {info}')
    data = _dump_struct_stat_android_aarch64(info)
    jitter.vm.set_mem(statbuf, data)
    retval = 0x0
  else:
    retval = -2 #ENOENT
  return retval

def sys_arm64_openat(jitter, linuxenv, args):
  dirfd, pathname, flags = args[:3]
  path = jitter.get_c_str(pathname)
  assert dirfd == 0xFFFFFF9C
  ret = linuxenv.open_(path, flags)
  log.warning(f'[{get_syscall_ret(jitter):08X}] sys_arm64_openat(dirfd={dirfd:08X}, pathname={path}, flags={flags:08X}) <- {ret}')
  return ret

def sys_arm64_arch_kill(jitter, linuxenv, args):
  pid, sig = args[:2]
  log.warning(f'[{get_syscall_ret(jitter):08X}] sys_kill(pid={pid:04X}, sig={sig:04X})')
  #scheduler.release(pid)
  return 0

def sys_arm64_arch_ptrace(jitter, linuxenv, args):
  request, pid, addr, data = args[:4]
  if dumpable.get(pid, True):
    ret = 0
  else:
    ret = -1
  log.warning(f'[{jitter.pc:08X}] sys_ptrace(request={request:X}, pid={pid}, addr={addr:08X}, data={data}): ' + ('DENIED' if ret else 'ALLOWED'))
  return ret

def sys_arm64_arch_getppid(jitter, linuxenv, args):
  ppid = [parent for parent, children in Context.current.sched.genealogy.items() if linuxenv.process_pid in children][0]
  log.warning(f'[{get_syscall_ret(jitter):08X}] sys_getppid() <- {ppid}')
  return ppid

def sys_arm64_close(jitter, linuxenv, args):
  fd, = jitter.syscall_args_systemv(1)
  log.warning(f'[{get_syscall_ret(jitter):08X}] sys_arm64_close({fd})')
  linuxenv.close(fd)
  return 0

def sys_arm64_lseek(jitter, linuxenv, args):
  fd, offset, whence = args[:3]
  offset = c_long(offset).value
  log.warning(f'[{get_syscall_ret(jitter):08X}] sys_arm64_lseek({fd:08X}, {offset:08X}, {whence:08X})')
  if type(linuxenv.file_descriptors[fd]) == FileDescriptorDirectory:
    if whence == SEEK_SET:
      ret = 0x0
    elif whence == SEEK_END:
      ret = 0x7fffffffffffffff
    else:
      log.error(f'Pretend there are no files in directory {fd}')
      assert False
  else:
    log.warning(f'SEEKING TO {offset:08X}')
    ret = linuxenv.file_descriptors[fd].lseek(offset, whence)
  return ret

def sys_arm64_arch_pipe2(jitter, linuxenv, args):
  # Parse arguments
  pipefd, flags = args[:2]
  assert flags==0
  # Create the pipe
  p = pipe()
  jitter.vm.set_u32(pipefd, p.fd1)
  jitter.vm.set_u32(pipefd+4, p.fd2)
  log.warning(f'[{get_syscall_ret(jitter):08X}] sys_pipe2({pipefd:08X})[{p.fd1}, {p.fd2}]')
  return 0

sig_handlers = {}
def sys_arm64_rt_sigaction(jitter, linuxenv, args):
  sig, act, oact, sigsetsize = args[:4]
  log.warning(f'[{get_syscall_ret(jitter):08X}] rt_sigaction(sig={sig}, act={act:08X}, oact={oact:08X}, sigsetsize={sigsetsize})')
  handler = jitter.vm.get_u64(act)
  log.warning(f'sa_handler: {handler:08X}\nsig_action: {jitter.vm.get_u64(act+0x8):08X}\nsa_mask: {jitter.vm.get_u64(act+0x10):08X}')
  log.warning(f'sa_flags: {jitter.vm.get_u64(act+0x18):08X}\nsa_restorer: {jitter.vm.get_u64(act+0x20):08X}')
  sig_handlers[sig] = handler
  return 0

def sys_arm64_arch_getdents64(jitter, linuxenv, args):
  fd, dirp, count = args[:3]
  log.warning(f'[{get_syscall_ret(jitter):08X}] sys_getdents64(fd={fd}, dirp={dirp:08X}, count={count:08X})')

  def packing_callback(cur_len, d_ino, d_type, name):
    # struct linux_dirent64 {
    #   ino64_t        d_ino;    /* 64-bit inode number */
    #   off64_t        d_off;    /* 64-bit offset to next structure */
    #   unsigned short d_reclen; /* Size of this dirent */
    #   unsigned char  d_type;   /* File type */
    #   char           d_name[]; /* Filename (null-terminated) */
    # };
    d_reclen = 8 * 2 + 2 + 1 + len(name) + 1
    d_off = cur_len + d_reclen
    entry = struct.pack('QqHB', d_ino, d_off, d_reclen, d_type) + name.encode() + b'\x00'
    assert len(entry) == d_reclen
    return entry

  out = linuxenv.getdents(fd, count, packing_callback)
  jitter.vm.set_mem(dirp, out)
  return len(out)

def sys_arm64_arch_mmap(jitter, linuxenv, args):
  addr, length, prot, flags, fd, pgoff = args[:6]
  argstr = ', '.join([f'{a:08X}' for a in args[:6]])
  log.warning(f'[{get_syscall_ret(jitter):08X}] sys_mmap ({argstr})')
  ret = linuxenv.mmap(addr, length, prot, flags, fd, pgoff, jitter.vm)
  return ret

def sys_arm64_arch_munmap(jitter, linuxenv, args):
  addr, length = args[:2]
  argstr = ', '.join([f'{a:08X}' for a in args[:6]])
  log.warning(f'[{get_syscall_ret(jitter):08X}] sys_mmap ({argstr})')
  return 0

def syscallit(fn):
  @functools.wraps(fn)
  def wrapper(jitter, linuxenv):
      args = jitter.syscall_args_systemv(6) # X0-X5
      ret = fn(jitter, linuxenv, args)
      jitter.syscall_ret_systemv(ret)
  return wrapper

syscalls = { \
  48: sys_arm64_faccessat, \
  63 : sys_arm64_arch_read, \
  64 : sys_arm64_arch_write, \
  57 : sys_arm64_close, \
  62 : sys_arm64_lseek, \
  78 : sys_arm64_readlinkat, \
  134 : sys_arm64_rt_sigaction, \
  172 : sys_arm64_arch_getpid, \
  129 : sys_arm64_arch_kill, \
  117 : sys_arm64_arch_ptrace, \
  173 : sys_arm64_arch_getppid, \
  178 : sys_arm64_arch_gettid, \
  198 : sys_arm64_arch_socket, \
  208 : sys_arm64_arch_setsockopt, \
  61 :  sys_arm64_arch_getdents64, \
  94 : sys_arm64_arch_exit_group, \
  56: sys_arm64_openat, \
  79: sys_arm64_fstatat, \
  59 : sys_arm64_arch_pipe2, \
  222 : sys_arm64_arch_mmap, \
  215 : sys_arm64_arch_munmap, \
}

syscall.syscall_callbacks_aarch64 = {k:syscallit(f) for k,f in syscalls.items()}
