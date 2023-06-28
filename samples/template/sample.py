# Miasm stuff
from miasm.core.locationdb import LocationDB
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE
from miasm.core.utils import pck64
from miasm.os_dep.linux import syscall
from miasm.loader.elf_init import ELF
from miasm.analysis.dse import DSEPathConstraint as DSEPC
# Android toolbox
from adt.mt_sandbox import MTSandbox as Sandbox
from adt.context import Context, log
from adt.scheduler import ContextSwitchException
from adt.misc import THREAD_PTR
from adt.jitter_callbacks import *

### KNOWN ADDRESSES
# binary: 0x0-0x1000000 (100 Mb)
# Stacks: 0x1100000-0x10000000
# THREAD: 0x1000000
# java: 0x10000000-0x20000000
# heap: 0x20000000+

def save_context_and_dump(jitter):
  Context.current.save_to_file()
  return True

def just_break(jitter):
  log.warning(f'[PC: {jitter.pc:08X}]')
  import pdb; pdb.set_trace()
  return True

def one_time_setup(sb):
  sb.jitter.vm.add_memory_page(THREAD_PTR+0x28, PAGE_READ|PAGE_WRITE, b'ABABABABCDCDCDCD', 'stack canary')
  sb.jitter.vm.add_memory_page(LAST_ERROR_PTR, PAGE_READ|PAGE_WRITE, pck64(0), 'last error')

def main():
  # Setup sandbox
  parser = Sandbox.parser(description="Android aarch64 sandbox")
  parser.add_argument("filename", help="ELF Filename")
  options = parser.parse_args()
  options.jitter = 'llvm'
  sb = Sandbox(LocationDB(), options.filename, options, globals())
  # Add custom breakpoints here is necessary
  if sb.newrun:
    one_time_setup(sb)
    sb.run(sb.loc_db.get_name_offset('JNI_OnLoad'), Context.current.javaenv.javavm_ptr)
  else:
    sb.continue_run()
  print(f'RETURN: {sb.jitter.cpu.X0:08X}')

if __name__ == '__main__':
  main()
