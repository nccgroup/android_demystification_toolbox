import os, json
from collections import namedtuple
from errno import *

config = json.load(open('./adt.config'))

system_properties = config['system_properties']

env = config['env']

auxtype = { 0 : 'AT_NULL', 1 : 'AT_IGNORE', 2 : 'AT_EXECFD', 3 : 'AT_PHDR', 4 : 'AT_PHENT', 5 : 'AT_PHNUM', \
    6 : 'AT_PAGESZ', 7 : 'AT_BASE', 8 : 'AT_FLAGS', 9 : 'AT_ENTRY', 10: 'AT_NOTELF', 11: 'AT_UID', \
    12: 'AT_EUID', 14: 'AT_GID', 15: 'AT_EGID', 16: 'AT_PLATFORM', 17: 'AT_HWCAP', 18: 'AT_CLKTCK', \
    23: 'AT_SECURE', 44: 'AT_VECTOR_SIZE', \
}
auxvec = config['auxvec']

file_accesses = config['file_accesses']

file_stats = config['file_stats']

program_headers = [(0x0, 'some.so', 0x40, 7)]

shared_objects = {k:int(v, 0) for k,v in config['shared_objects'].items()}

android_config = config['android']
