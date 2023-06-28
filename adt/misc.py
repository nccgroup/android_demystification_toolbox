import os, struct, ctypes, pickle
from errno import EACCES, ENOENT
from collections import namedtuple
# Miasm
from miasm.analysis.sandbox import Arch_aarch64l as Arch
from miasm.os_dep.linux import environment
from miasm.loader.elf_init import ELF
# Android toolbox
from adt.context import Context, log
from adt.config import file_accesses, file_stats

# lseek stuff
SEEK_SET = 0
SEEK_CUR = 1
SEEK_END = 2

# Fixed addresses
THREAD_PTR = 0x1000000
libc_base = 0x71111000
Arch.STACK_BASE = 0x1100000 # Fix the stack base to avoid conflict with exec pages
LAST_ERROR_PTR = 0x99000000

def faccess_convert(flags):
  faccess = {
      os.O_RDONLY : os.F_OK|os.R_OK, \
      os.O_WRONLY : os.F_OK|os.W_OK, \
      os.O_RDWR : os.F_OK|os.R_OK|os.W_OK, \
  }
  for flag in faccess:
    if flags&flag==flag:
      return faccess[flag]
  assert False
  return None

def get_file_access(filename, requested_mode, explicit=False):
  if filename in file_accesses:
    access = int(file_accesses[filename], 0)
    # If all requested flags are present in access
    if requested_mode & access == access:
      ret = 0
    else:
      ret = EACCES
  elif explicit:
    ret = 0
  else:
    ret = ENOENT
  return ret

def get_file_stats(filename, flags):
  fd = Context.current.linuxenv.open_(filename, flags)
  if fd > 0:
    fdesc = Context.current.linuxenv.file_descriptors[fd]
    # Fix the access
    mode_str = file_accesses.get(filename)
    if mode_str:
      mode = int(mode_str, 0) if mode_str else None
      fdesc.file_mode = mode
    # Fix the creation time
    ctime_str, mtime_str = file_stats.get(filename, (None, None))
    if ctime_str:
      fdesc.ctime = int(ctime_str, 0)
    # Fix the modification time
    if ctime_str:
      fdesc.mtime = int(mtime_str, 0)
    # Only then can we query
    info = Context.current.linuxenv.fstat(fd)
    log.warning(f'stat64 info: {info}')
  else:
    info = None
  return info

# TODO: This version only handles aligned 64bit gp arguments passsed by reference
def varargs_to_list_aarch64(jitter, valist, max_args=5):
  # gp regs list only
  args = []
  # Capture va_list struct
  stack = jitter.vm.get_u64(valist)
  gr_top = jitter.vm.get_u64(valist+0x8)
  vr_top = jitter.vm.get_u64(valist+0x10)
  gr_offs = ctypes.c_int(jitter.vm.get_u32(valist+0x18)).value
  vr_offs = jitter.vm.get_u32(valist+0x1C)
  # Parse gp args
  # args storage area first
  while gr_offs<ctypes.c_int(0x0).value and len(args)<max_args:
    args.append(jitter.vm.get_u64(gr_top+gr_offs))
    gr_offs+=8
  while len(args)<max_args:
    # then just from stack
    args.append(jitter.vm.get_u64(stack))
    stack+=8
  return args

def set_last_error(jitter, err):
  log.warning(f'LAST_ERROR <- {err:08X}')
  jitter.vm.set_u32(LAST_ERROR_PTR, err)
  return True

def _dump_struct_stat_android_aarch64(info):
    log.warning('Packing for android arm64')
    data = struct.pack(
        "QQIIIIQQQIIQQQQQQQII",
        info.st_dev, # Q
        info.st_ino, # Q
        info.st_mode, # I
        info.st_nlink, # I
        info.st_uid, # I
        info.st_gid, # I
        info.st_rdev, # Q
        0, # 64 bit padding
        info.st_size,
        info.st_blksize, # I
        0, # 32 bit padding
        info.st_blocks,
        info.st_atime,
        info.st_atimensec,
        info.st_mtime,
        info.st_mtimensec,
        info.st_ctime,
        info.st_ctimensec,
        0, # unused
        0, # unused
    )
    return data

# pipes

class pipe(environment.FileDescriptor):

  def __init__(self):
    # Create 2 "fake" fds
    self.fd1 = Context.current.linuxenv.next_fd()
    Context.current.linuxenv.file_descriptors[self.fd1] = self
    self.fd2 = Context.current.linuxenv.next_fd()
    Context.current.linuxenv.file_descriptors[self.fd2] = self
    # And allocate a buffer for it
    self.buffer = bytearray()

  @property
  def size(self):
    return len(self.buffer)

  def tell(self):
    return 0

  def read(self, size):
    ret = bytes(self.buffer[:size])
    self.buffer = self.buffer[size:]
    log.warning(f'PIPE[{self.fd1}] READ: {ret}')
    return ret

  def write(self, data):
    self.buffer += bytearray(data)
    log.warning(f'PIPE[{self.fd2}] WRITE: {data} -> {self.buffer}')
    return len(data)

# Real libc handling

SHN_UNDEF=0
def parse_libc(jitter, path, globals):
  # auto libc callbacks
  with open(path, 'rb') as f:
    libc = ELF(f.read())
  symbsection = [sec for sec in libc.sh if sec.sh.name==b'.dynsym'][0]
  for bname, info in symbsection.symbols.items():
    fname = f'xxx_{bname.decode()}'
    if info.shndx != SHN_UNDEF:
      if fname in globals:
        newaddr = libc_base+info.value
        jitter.libs.cname2addr[fname] = newaddr
        jitter.libs.fad2cname[newaddr] = fname
        jitter.handle_function(newaddr)
