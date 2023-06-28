import os
from inspect import signature
from collections.abc import Iterable
# Miasm
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE
from miasm.core.utils import hexdump, pck64, pck32
# Android toolbox
from adt.context import Context, log
from adt.misc import varargs_to_list_aarch64
from adt.config import android_config

JAVAENV_PTR = 0x11600000
JNI_OK = 0x00

jni_funcs = [ \
'reserved0','reserved1','reserved2','reserved3','GetVersion', 'DefineClass','FindClass','FromReflectedMethod','FromReflectedField',\
'ToReflectedMethod','GetSuperclass','IsAssignableFrom','ToReflectedField','Throw','ThrowNew','ExceptionOccurred','ExceptionDescribe','ExceptionClear',\
'FatalError','PushLocalFrame','PopLocalFrame','NewGlobalRef','DeleteGlobalRef','DeleteLocalRef','IsSameObject','NewLocalRef','EnsureLocalCapacity',\
'AllocObject','NewObject','NewObjectV','NewObjectA','GetObjectClass','IsInstanceOf','GetMethodID','CallObjectMethod','CallObjectMethodV',\
'CallObjectMethodA','CallBooleanMethod','CallBooleanMethodV','CallBooleanMethodA','CallByteMethod','CallByteMethodV','CallByteMethodA','CallCharMethod',\
'CallCharMethodV','CallCharMethodA','CallShortMethod','CallShortMethodV','CallShortMethodA','CallIntMethod','CallIntMethodV','CallIntMethodA',\
'CallLongMethod','CallLongMethodV','CallLongMethodA','CallFloatMethod','CallFloatMethodV','CallFloatMethodA','CallDoubleMethod','CallDoubleMethodV',\
'CallDoubleMethodA','CallVoidMethod','CallVoidMethodV','CallVoidMethodA','CallNonvirtualObjectMethod','CallNonvirtualObjectMethodV','CallNonvirtualObjectMethodA',\
'CallNonvirtualBooleanMethod','CallNonvirtualBooleanMethodV','CallNonvirtualBooleanMethodA','CallNonvirtualByteMethod','CallNonvirtualByteMethodV',\
'CallNonvirtualByteMethodA','CallNonvirtualCharMethod','CallNonvirtualCharMethodV','CallNonvirtualCharMethodA','CallNonvirtualShortMethod',\
'CallNonvirtualShortMethodV','CallNonvirtualShortMethodA','CallNonvirtualIntMethod','CallNonvirtualIntMethodV','CallNonvirtualIntMethodA',\
'CallNonvirtualLongMethod','CallNonvirtualLongMethodV','CallNonvirtualLongMethodA','CallNonvirtualFloatMethod','CallNonvirtualFloatMethodV',\
'CallNonvirtualFloatMethodA','CallNonvirtualDoubleMethod','CallNonvirtualDoubleMethodV','CallNonvirtualDoubleMethodA','CallNonvirtualVoidMethod',\
'CallNonvirtualVoidMethodV','CallNonvirtualVoidMethodA','GetFieldID','GetObjectField','GetBooleanField','GetByteField','GetCharField','GetShortField',\
'GetIntField','GetLongField','GetFloatField','GetDoubleField','SetObjectField','SetBooleanField','SetByteField','SetCharField','SetShortField',\
'SetIntField','SetLongField','SetFloatField','SetDoubleField','GetStaticMethodID','CallStaticObjectMethod','CallStaticObjectMethodV','CallStaticObjectMethodA',\
'CallStaticBooleanMethod','CallStaticBooleanMethodV','CallStaticBooleanMethodA','CallStaticByteMethod','CallStaticByteMethodV','CallStaticByteMethodA',\
'CallStaticCharMethod','CallStaticCharMethodV','CallStaticCharMethodA','CallStaticShortMethod','CallStaticShortMethodV','CallStaticShortMethodA',\
'CallStaticIntMethod','CallStaticIntMethodV','CallStaticIntMethodA','CallStaticLongMethod','CallStaticLongMethodV','CallStaticLongMethodA',\
'CallStaticFloatMethod','CallStaticFloatMethodV','CallStaticFloatMethodA','CallStaticDoubleMethod','CallStaticDoubleMethodV','CallStaticDoubleMethodA',\
'CallStaticVoidMethod','CallStaticVoidMethodV','CallStaticVoidMethodA','GetStaticFieldID','GetStaticObjectField','GetStaticBooleanField',\
'GetStaticByteField','GetStaticCharField','GetStaticShortField','GetStaticIntField','GetStaticLongField','GetStaticFloatField','GetStaticDoubleField',\
'SetStaticObjectField','SetStaticBooleanField','SetStaticByteField','SetStaticCharField','SetStaticShortField','SetStaticIntField','SetStaticLongField',\
'SetStaticFloatField','SetStaticDoubleField','NewString','GetStringLength','GetStringChars','ReleaseStringChars','NewStringUTF','GetStringUTFLength',\
'GetStringUTFChars','ReleaseStringUTFChars','GetArrayLength','NewObjectArray','GetObjectArrayElement','SetObjectArrayElement','NewBooleanArray','NewByteArray',\
'NewCharArray','NewShortArray','NewIntArray','NewLongArray','NewFloatArray','NewDoubleArray','GetBooleanArrayElements','GetByteArrayElements',\
'GetCharArrayElements','GetShortArrayElements','GetIntArrayElements','GetLongArrayElements','GetFloatArrayElements','GetDoubleArrayElements',\
'ReleaseBooleanArrayElements','ReleaseByteArrayElements','ReleaseCharArrayElements','ReleaseShortArrayElements','ReleaseIntArrayElements',\
'ReleaseLongArrayElements','ReleaseFloatArrayElements','ReleaseDoubleArrayElements','GetBooleanArrayRegion','GetByteArrayRegion','GetCharArrayRegion',\
'GetShortArrayRegion','GetIntArrayRegion','GetLongArrayRegion','GetFloatArrayRegion','GetDoubleArrayRegion','SetBooleanArrayRegion','SetByteArrayRegion',\
'SetCharArrayRegion','SetShortArrayRegion','SetIntArrayRegion','SetLongArrayRegion','SetFloatArrayRegion','SetDoubleArrayRegion','RegisterNatives',\
'UnregisterNatives','MonitorEnter','MonitorExit','GetJavaVM','GetStringRegion','GetStringUTFRegion','GetPrimitiveArrayCritical','ReleasePrimitiveArrayCritical',\
'GetStringCritical','ReleaseStringCritical','NewWeakGlobalRef','DeleteWeakGlobalRef','ExceptionCheck' \
]
jni = {s:i*8 for i,s in enumerate(jni_funcs)}
jni = {k:v for k, v in sorted(jni.items(), key=lambda i: i[1])}

class JavaObj(object):
  def __init__(self):
    # init methods
    self.methods = [0] + [func for func in dir(self.__class__) if callable(getattr(self.__class__, func))]
    #print(self.methods)
    # init fields
    self.fields = [0] + list(vars(self))
    #print(self.fields)
    self.address = Context.current.javaenv.valid_address
    # Autoadd ourselves to the objects list
    Context.current.javaenv.objects[self.address] = self

  def getName(self):
    return UTFString(self.__class__.__name__).address

  def get_field_id(self, name):
    return self.fields.index(name)

  def get_method_id(self, name):
    # Find it if it exists
    method_id = self.methods.index(name)
    return method_id

class FakeField(JavaObj):
  def __init__(self):
    super(FakeField, self).__init__()

class YesObj(JavaObj):
  def __init__(self):
    super(YesObj, self).__init__()

  def jinit(self):
    return self.address

  def get_field_id(self, name):
    # Find it if it exists
    if name in self.fields:
      field_id = self.fields.index(name)
    # Or create one on the spot
    else:
      setattr (self, name, FakeField())
      # reinit fields
      self.fields = [0] + list(vars(self))
      field_id = self.fields.index(name)
    return field_id

  def bogus_method(self):
    return 0

  def get_method_id(self, name):
    # Find it if it exists
    try:
      method_id = self.methods.index(name)
    except ValueError as e:
      method_id = self.methods.index('bogus_method')
    return method_id

modifiers= { \
    'ABSTRACT' : 1024, \
    'FINAL' :  16, \
    'INTERFACE' : 512, \
    'NATIVE' : 256, \
    'PRIVATE' : 2, \
    'PROTECTED' : 4, \
    'PUBLIC' : 1, \
    'STATIC' : 8, \
    'STRICT': 2048, \
    'SYNCHRONIZED' : 32, \
    'TRANSIENT' : 128, \
    'VOLATILE' : 64, \
}

class UTFString(JavaObj):
  def __init__(self, string=None):
    self.string = string if string else ''
    super(UTFString, self).__init__()

  def intern(self):
    return self.address

class Java_Lang_Class(JavaObj):
  def __init__(self):
    super(Java_Lang_Class, self).__init__()

  def getDeclaredMethod(self, stringptr, classptr):
    method_name = Context.current.javaenv.objects[stringptr].string
    method = Java_Lang_Method(self.__class__, method_name)
    log.warning(f'getDeclaredMethod({method_name}) <- {method.address:08X}')
    return method.address

class Java_Lang_Method(JavaObj):
  def __init__(self, clazz, method_name):
    self.clazz = clazz
    self.method = method_name
    super(Java_Lang_Method, self).__init__()

  def getModifiers(self):
    return 2 # Private

class Java_Lang_System(JavaObj):
  def __init__(self):
    super(Java_Lang_System, self).__init__()
    self.properties = {'java.vm.version': UTFString('31')}

  def getProperty(self, stringptr):
    obj = Context.current.javaenv.objects[stringptr]
    string = obj.string
    log.warning(f'Java_Lang_System.getProperty({string})')
    value = self.properties[string]
    return value.address

class Android_Os_Process_Class(JavaObj):
  def setArgV0(self, stringptr):
    obj = Context.current.javaenv.objects[stringptr]
    string = obj.string
    log.warning(f'Process.setArgV0("{string}")')
    pass

class Android_App_ActivityThread_AppBindData(JavaObj):
  def __init__(self):
    super(Android_App_ActivityThread_AppBindData, self).__init__()

class Android_App_ActivityThread(Java_Lang_Class):
  def __init__(self):
    super(Android_App_ActivityThread, self).__init__()
    self.package_name = UTFString(android_config['application_info']['package_name'])

  def currentPackageName(self):
    return self.package_name.address

  def currentActivityThread(self):
    log.warning('ActivityThread.currentActivityThread()')
    return self.address # whatever, mixing with static for now

  def getSystemContext(self):
    new_obj = Android_Context()
    return new_obj.address

class Android_Context(JavaObj):
  def getPackageManager(self):
    new_obj = PackageManager()
    return new_obj.address

class PackageManager(JavaObj):
  def getApplicationInfo(self):
    new_obj = Android_Application_Info()
    return new_obj.address

  def getPackageInfo(self):
    new_obj = Android_Package_Info()
    return new_obj.address

class Android_Application_Info(JavaObj):
  def __init__(self):
    self.sourceDir = UTFString(android_config['application_info']['source_dir'])
    self.dataDir = UTFString(android_config['application_info']['data_dir'])
    self.nativeLibraryDir = UTFString(android_config['application_info']['nativelib_dir'])
    self.packageName = UTFString(android_config['application_info']['package_name'])
    self.splitSourceDirs = Array([UTFString(p) for p in android_config['application_info']['split_source_dirs']])
    super(Android_Application_Info, self).__init__()

class Android_Package_Info(JavaObj):
  def __init__(self):
    self.versionName = UTFString(android_config['package_info']['version'])
    super(Android_Package_Info, self).__init__()

class Android_Io_File(JavaObj):

  def __init__(self, filename=None):
    if filename:
      assert type(filename) == UTFString
      self.filename = filename.string
      # Relying on os is bad practice but that'll do for now
      flags = Context.current.linuxenv.O_DIRECTORY if os.path.isdir('file_sb/' + self.filename) else 0
      self.fdesc = Context.current.linuxenv.file_descriptors[Context.current.linuxenv.open_(self.filename, flags)]
    super(Android_Io_File, self).__init__()

  def jinit(self, filename):
    self.filename = Context.current.javaenv.objects[filename].string
    # Relying on os is bad practice but that'll do for now
    flags = Context.current.linuxenv.O_DIRECTORY if os.path.isdir('file_sb/' + self.filename) else 0
    fd = Context.current.linuxenv.open_(self.filename, flags)
    self.fdesc = Context.current.linuxenv.file_descriptors[fd] if fd != -1 else None
    return self.address

  def listFiles(self):
    new_obj = Array()
    for filename in self.fdesc.listdir():
      new_obj.elements.append(Android_Io_File(UTFString(self.filename+'/'+filename)))
    return new_obj.address

  def exists(self):
    return 0x1 if self.fdesc else 0x0

  def isDirectory(self):
    return os.path.isdir('file_sb/'+self.filename)

  def getAbsolutePath(self):
    abspath = UTFString(os.path.abspath(self.filename))
    return abspath.address

  def toString(self):
    return UTFString(self.filename).address

class Array(JavaObj):
  def __init__(self, *args):
    if not args:
      self.elements = []
    elif len(args)==1:
      assert isinstance(args[0], Iterable)
      self.elements = list(args[0])
    elif len(args)==2:
      size = args[0]
      clazzptr = args[1]
      if size and clazzptr:
        clazz = Context.current.javaenv.objects[clazzptr]
        self.elements = [clazz.__class__()]*size
    else:
      assert False
    super(Array, self).__init__()

class Android_App_ResourcesManager(Java_Lang_Class):
  pass
class Android_Content_Res_ResourcesKey(Java_Lang_Class):
  pass
class Android_Os_IBinder(Java_Lang_Class):
  pass
class Java_Lang_ClassLoader(Java_Lang_Class):
  pass
class Android_View_LayoutInflater(Java_Lang_Class):
  pass
class Android_View_View(Java_Lang_Class):
  pass
class Org_Xmlpull_V1_XmlPullParser(Java_Lang_Class):
  pass
class Android_Content_Context(Java_Lang_Class):
  pass
class Android_Util_AttributeSet(Java_Lang_Class):
  pass
class Android_App_ApplicationPackageManager(Java_Lang_Class):
  pass
class Android_Content_pm_ApplicationInfo(Java_Lang_Class):
  pass
class Java_Util_List(Java_Lang_Class):
  pass
class Java_Lang_Runtime(Java_Lang_Class):
  pass
class String_Array(Java_Lang_Class):
  pass

class Android_Os_Debug(Java_Lang_Class):
  # How about no ?
  def isDebuggerConnected(self):
    return 0x0
  pass

class Java_Lang_ProcessBuilder(Java_Lang_Class):
  def jinit(self):
    return self.address

  def getConstructor(self):
    return Java_Lang_Method(self.__class__, 'jinit').address

custom_classes = { cc : YesObj for cc in android_config['yes_classes'] }

class JavaEnv(object):
  javaenv = None
  JAVAVM_PTR = 0x10000000
  JAVAENV_PTR = 0x11600000

  def __init__(self, jitter):
    self.javavm_ptr = JavaEnv.JAVAVM_PTR
    self.javaenv_ptr = JavaEnv.JAVAENV_PTR
    self.objects = {} # classes are objects too!
    self._valid_address = 0x56700000
    self.classes = { \
                    'java/lang/System' : Java_Lang_System, \
                    'android/os/Process' : Android_Os_Process_Class, \
                    'android/app/ActivityThread' : Android_App_ActivityThread, \
                    'java/io/File' : Android_Io_File, \
                    'java/lang/Class' : Java_Lang_Class, \
                    'android/app/ActivityThread$AppBindData' : Android_App_ActivityThread_AppBindData, \
                    'android/app/ResourcesManager' : Android_App_ResourcesManager, \
                    'android/os/IBinder' : Android_Os_IBinder, \
                    'android/content/res/ResourcesKey' : Android_Content_Res_ResourcesKey, \
                    'java/lang/ClassLoader' : Java_Lang_ClassLoader, \
                    'android/view/LayoutInflater' : Android_View_LayoutInflater, \
                    'android/view/View' : Android_View_View, \
                    'org/xmlpull/v1/XmlPullParser' : Org_Xmlpull_V1_XmlPullParser, \
                    'android/content/Context' : Android_Content_Context, \
                    'android/util/AttributeSet' : Android_Util_AttributeSet, \
                    'android/app/ApplicationPackageManager' : Android_App_ApplicationPackageManager, \
                    'android/content/pm/ApplicationInfo' : Android_Content_pm_ApplicationInfo, \
                    'java/util/List' : Java_Util_List, \
                    'java/lang/ProcessBuilder' : Java_Lang_ProcessBuilder, \
                    'java/lang/Runtime' : Java_Lang_Runtime, \
                    '[Ljava/lang/String;' : String_Array, \
                    'android/os/Debug' : Android_Os_Debug, \
                }
    self.classes.update(custom_classes)
    self.setup_jitter(jitter)

  @classmethod
  def instantiate_new(cls, jitter):
    cls.javaenv = cls(jitter)
    return cls.javaenv

  def add_javaenv_fn(self, jitter, fname):
    jitter.add_breakpoint(0x13000000+jni[fname], globals()[f'JavaEnv_{fname}'])

  def register_class(self, cname, clazz):
    self.classes[cname] = clazz

  def setup_jitter(self, jitter, add_mems=True):
    if add_mems:
      jitter.vm.add_memory_page(self.javavm_ptr, PAGE_READ, pck64(0x11000000), 'JavaVM_ptr')
      jitter.vm.add_memory_page(0x11000000, PAGE_READ, pck64(0x0)*3 # reserved
                                                        + pck64(0x11100000) # DestroyJavaVM
                                                        + pck64(0x11200000) # AttachCurrentThread
                                                        + pck64(0x11300000) # DetachCurrentThread
                                                        + pck64(0x11400000) # GetEnv
                                                        + pck64(0x11500000) # AttachCurrentThreadAsDaemon
                                                        + b'\xAB'*0x1000 # Pad heavy
                                   , 'JavaVM')
      jitter.vm.add_memory_page(self.javaenv_ptr, PAGE_READ, pck64(0x12000000), 'JavaEnv_ptr')
      jitter.vm.add_memory_page(0x12000000, PAGE_READ, b''.join(pck64(0x13000000+off) for off in jni.values()), 'JavaEnv')
    # The JNI interface
    jitter.add_breakpoint(0x11200000, javavm_attach_current_thread)
    jitter.add_breakpoint(0x11300000, javavm_detach_current_thread)
    jitter.add_breakpoint(0x11400000, javavm_getenv)
    #jitter.add_breakpoint(0XBB72800, getVMPointer)
    self.add_javaenv_fn(jitter, 'FindClass')
    self.add_javaenv_fn(jitter, 'ExceptionCheck')
    self.add_javaenv_fn(jitter, 'GetStaticMethodID')
    self.add_javaenv_fn(jitter, 'NewStringUTF')
    self.add_javaenv_fn(jitter, 'GetStringUTFChars')
    self.add_javaenv_fn(jitter, 'ReleaseStringUTFChars')
    self.add_javaenv_fn(jitter, 'RegisterNatives')
    self.add_javaenv_fn(jitter, 'GetMethodID')
    self.add_javaenv_fn(jitter, 'CallVoidMethod')
    self.add_javaenv_fn(jitter, 'CallObjectMethod')
    self.add_javaenv_fn(jitter, 'CallObjectMethodV')
    self.add_javaenv_fn(jitter, 'DeleteLocalRef')
    self.add_javaenv_fn(jitter, 'CallStaticVoidMethodV')
    self.add_javaenv_fn(jitter, 'CallStaticObjectMethod')
    self.add_javaenv_fn(jitter, 'CallStaticObjectMethodV')
    self.add_javaenv_fn(jitter, 'ExceptionOccurred')
    self.add_javaenv_fn(jitter, 'GetObjectClass')
    self.add_javaenv_fn(jitter, 'GetStringUTFLength')
    self.add_javaenv_fn(jitter, 'GetFieldID')
    self.add_javaenv_fn(jitter, 'GetObjectField')
    self.add_javaenv_fn(jitter, 'GetArrayLength')
    self.add_javaenv_fn(jitter, 'ExceptionClear')
    self.add_javaenv_fn(jitter, 'NewObject')
    self.add_javaenv_fn(jitter, 'NewObjectV')
    self.add_javaenv_fn(jitter, 'GetObjectArrayElement')
    self.add_javaenv_fn(jitter, 'NewGlobalRef')
    self.add_javaenv_fn(jitter, 'DeleteGlobalRef')
    self.add_javaenv_fn(jitter, 'GetStaticFieldID')
    self.add_javaenv_fn(jitter, 'SetStaticIntField')
    self.add_javaenv_fn(jitter, 'SetStaticFloatField')
    self.add_javaenv_fn(jitter, 'SetStaticDoubleField')
    self.add_javaenv_fn(jitter, 'SetStaticLongField')
    self.add_javaenv_fn(jitter, 'SetStaticShortField')
    self.add_javaenv_fn(jitter, 'SetStaticByteField')
    self.add_javaenv_fn(jitter, 'SetStaticCharField')
    self.add_javaenv_fn(jitter, 'SetStaticBooleanField')
    self.add_javaenv_fn(jitter, 'SetStaticObjectField')
    self.add_javaenv_fn(jitter, 'GetStaticBooleanField')
    self.add_javaenv_fn(jitter, 'NewObjectArray')
    self.add_javaenv_fn(jitter, 'SetObjectArrayElement')
    self.add_javaenv_fn(jitter, 'CallLongMethod')
    self.add_javaenv_fn(jitter, 'CallIntMethodV')
    self.add_javaenv_fn(jitter, 'CallStaticBooleanMethodV')
    self.add_javaenv_fn(jitter, 'CallBooleanMethodV')
    return True

  @property
  def valid_address(self):
    self._valid_address +=1
    return self._valid_address

  def FindClass(self, name):
    clazz = self.classes.get(name)
    retval = clazz().address if clazz else 0x0
    if not retval and 'xposed' not in name.lower():
      log.warning(name)
      #import pdb; pdb.set_trace()
    return retval

  def GetObjectClass(self, ptr):
    return ptr

  def nbParams(self, sig):
    params = re.search(r'\((.*)\)', sig).group(1)
    if not params:
      count = 0
    else:
      count = params.count(';')+1
    return count

  def GetMethodID(self, clazz, name, sig=None):
    if name=='<init>':
      name = 'jinit'
    if sig:
      nbparams = self.nbParams(sig)
      name= f'{name}_{nbparams:02}'
    obj = self.objects[clazz]
    methodID = obj.get_method_id(name)
    #import pdb; pdb.set_trace()
    return methodID

  def CallMethod(self, objid, methodID, argslist):
    obj = self.objects[objid]
    method_name = obj.methods[methodID]
    # Get the method's number of parameters
    method = getattr(obj, method_name)
    nbparams = len(signature(method).parameters)
    ret = method(*argslist[:nbparams])
    retstr = f'{ret:08x}' if ret else 'VOID'
    log.warning(f'Call Returning: {retstr}')
    return ret

  def GetFieldID(self, clazz, name):
    obj = self.objects[clazz]
    fieldID = obj.get_field_id(name)
    return fieldID

  def GetObjectField(self, ptr, fieldID):
    obj = self.objects[ptr]
    field_name = obj.fields[fieldID]
    value = getattr(obj, field_name)
    return value.address

  def GetArrayLength(self, ptr):
    obj = self.objects[ptr]
    return len(obj.elements)

  def GetObjectArrayElement(self, array, index):
    obj = self.objects[array]
    return obj.elements[index].address

  def SetObjectArrayElement(self, array, index, value):
    self.objects[array].elements[index] = self.objects[value]

  def NewStringUTF(self, string):
    new_obj = UTFString(string)
    return new_obj.address

  def GetStringUTFChars(self, utfstring):
    obj = self.objects[utfstring]
    return obj.string

  def GetStringUTFLength(self, utfstring):
    obj = self.objects[utfstring]
    return len(obj.string)

  def generate_yesclass(self, name):
    YesClass = type(name, (YesObj, ), {})
    return YesClass()

### jitter callbacks

def javavm_attach_current_thread(jitter):
  ret_addr, args = jitter.func_args_systemv(['jvm', 'env', 'args'])
  jitter.func_ret_systemv(ret_addr, JNI_OK)
  return True

def javavm_detach_current_thread(jitter):
  ret_addr, args = jitter.func_args_systemv(['jvm'])
  jitter.func_ret_systemv(ret_addr, JNI_OK)
  return True

def javavm_getenv(jitter):
  ret_addr, args = jitter.func_args_systemv(['javavm', 'env', 'envkey'])
  jitter.vm.set_mem(args.env, pck64(JAVAENV_PTR))
  jitter.func_ret_systemv(ret_addr, 0x0) # return JNI_OK
  #import pdb; pdb.set_trace()
  return True

def JavaEnv_FindClass(jitter):
  ret_addr, args = jitter.func_args_systemv(['javaEnv', 'classname'])
  classname = jitter.get_c_str(args.classname)
  addr = Context.current.javaenv.FindClass(classname)
  log.warning(f'JavaEnv->FindClass("{classname}") <- {addr:08X}')
  jitter.func_ret_systemv(ret_addr, addr)
  return True

def JavaEnv_GetMethodID(jitter):
  ret_addr, args = jitter.func_args_systemv(['env', 'clazz', 'name', 'sig'])
  name = jitter.get_c_str(args.name)
  sig = jitter.get_c_str(args.sig)
  methodID = Context.current.javaenv.GetMethodID(args.clazz, name, sig=None) # TODO: ENABLE SIG IF NEEDED
  log.warning(f'JavaEnv->GetMethodID({args.clazz:08X}, {name}, {sig}) <- {methodID}')
  jitter.func_ret_systemv(ret_addr, methodID)
  return True

def JavaEnv_GetStaticMethodID(jitter):
  ret_addr, args = jitter.func_args_systemv(['javaEnv', 'jclass', 'name', 'sig'])
  name = jitter.get_c_str(args.name)
  methodID = Context.current.javaenv.GetMethodID(args.jclass, name)
  log.warning(f'JavaEnv->GetStaticMethodID({args.jclass:08X}, {name}) <- {methodID}')
  jitter.func_ret_systemv(ret_addr, methodID)
  return True

def JavaEnv_GetFieldID(jitter):
  ret_addr, args = jitter.func_args_systemv(['env', 'clazz', 'name', 'sig'])
  field_name = jitter.get_c_str(args.name)
  fieldID = Context.current.javaenv.GetFieldID(args.clazz, field_name)
  log.warning(f'JavaEnv->GetFieldID("{field_name}") <- {fieldID}')
  jitter.func_ret_systemv(ret_addr, fieldID)
  return True

def JavaEnv_GetStaticFieldID(jitter):
  ret_addr, args = jitter.func_args_systemv(['env', 'clazz', 'name', 'sig'])
  field_name = jitter.get_c_str(args.name)
  fieldID = Context.current.javaenv.GetFieldID(args.clazz, field_name)
  log.warning(f'JavaEnv->GetStaticFieldID("{field_name}") <- {fieldID}')
  jitter.func_ret_systemv(ret_addr, fieldID)
  return True

def JavaEnv_GetStaticBooleanField(jitter):
  ret_addr, args = jitter.func_args_systemv(['env', 'obj', 'fieldID'])
  addr = Context.current.javaenv.GetObjectField(args.obj, args.fieldID)
  log.warning(f'JavaEnv->GetStaticBooleanField("{args.fieldID}) <- {addr:08X}')
  jitter.func_ret_systemv(ret_addr, addr)
  return True

def JavaEnv_NewObjectArray(jitter):
  ret_addr, args = jitter.func_args_systemv(['env', 'length', 'elementClass', 'initialElement'])
  addr = Array(args.length, args.elementClass).address
  log.warning(f'JavaEnv->NewObjectArray({args.length}, {args.elementClass:08X} , {args.initialElement:08X}) <- {addr:08X}')
  jitter.func_ret_systemv(ret_addr, addr)
  return True

def JavaEnv_SetStaticIntField(jitter):
  ret_addr, args = jitter.func_args_systemv(['env', 'clazz', 'fieldID', 'value'])
  obj = Context.current.javaenv.objects[args.clazz]
  fieldname = obj.fields[args.fieldID]
  classname = obj.__class__.__name__
  log.warning(f'!!!NOP!!! JavaEnv->SetStaticIntField("{classname}", "{fieldname}", {args.value:08X})')
  jitter.func_ret_systemv(ret_addr, 0x0)
  return True

def JavaEnv_SetStaticLongField(jitter):
  ret_addr, args = jitter.func_args_systemv(['env', 'clazz', 'fieldID', 'value'])
  obj = Context.current.javaenv.objects[args.clazz]
  fieldname = obj.fields[args.fieldID]
  classname = obj.__class__.__name__
  log.warning(f'!!!NOP!!! JavaEnv->SetStaticLongField("{classname}", "{fieldname}", {args.value:08X})')
  jitter.func_ret_systemv(ret_addr, 0x0)
  return True

def JavaEnv_SetStaticShortField(jitter):
  ret_addr, args = jitter.func_args_systemv(['env', 'clazz', 'fieldID', 'value'])
  obj = Context.current.javaenv.objects[args.clazz]
  fieldname = obj.fields[args.fieldID]
  classname = obj.__class__.__name__
  log.warning(f'!!!NOP!!! JavaEnv->SetStaticShortField("{classname}", "{fieldname}", {args.value:08X})')
  jitter.func_ret_systemv(ret_addr, 0x0)
  return True

def JavaEnv_SetStaticFloatField(jitter):
  ret_addr, args = jitter.func_args_systemv(['env', 'clazz', 'fieldID', 'value'])
  obj = Context.current.javaenv.objects[args.clazz]
  fieldname = obj.fields[args.fieldID]
  classname = obj.__class__.__name__
  log.warning(f'!!!NOP!!! JavaEnv->SetStaticFloatField("{classname}", "{fieldname}", {args.value:f})')
  jitter.func_ret_systemv(ret_addr, 0x0)
  return True

def JavaEnv_SetStaticDoubleField(jitter):
  ret_addr, args = jitter.func_args_systemv(['env', 'clazz', 'fieldID', 'value'])
  obj = Context.current.javaenv.objects[args.clazz]
  fieldname = obj.fields[args.fieldID]
  classname = obj.__class__.__name__
  log.warning(f'!!!NOP!!! JavaEnv->SetStaticDoubleField("{classname}", "{fieldname}", {args.value:f})')
  jitter.func_ret_systemv(ret_addr, 0x0)
  return True

def JavaEnv_SetStaticByteField(jitter):
  ret_addr, args = jitter.func_args_systemv(['env', 'clazz', 'fieldID', 'value'])
  obj = Context.current.javaenv.objects[args.clazz]
  fieldname = obj.fields[args.fieldID]
  classname = obj.__class__.__name__
  log.warning(f'!!!NOP!!! JavaEnv->SetStaticByteField("{classname}", "{fieldname}", {args.value:08X})')
  jitter.func_ret_systemv(ret_addr, 0x0)
  return True

def JavaEnv_SetStaticCharField(jitter):
  ret_addr, args = jitter.func_args_systemv(['env', 'clazz', 'fieldID', 'value'])
  obj = Context.current.javaenv.objects[args.clazz]
  fieldname = obj.fields[args.fieldID]
  classname = obj.__class__.__name__
  log.warning(f'!!!NOP!!! JavaEnv->SetStaticCharField("{classname}", "{fieldname}", {args.value:08X})')
  jitter.func_ret_systemv(ret_addr, 0x0)
  return True

def JavaEnv_SetStaticBooleanField(jitter):
  ret_addr, args = jitter.func_args_systemv(['env', 'clazz', 'fieldID', 'value'])
  obj = Context.current.javaenv.objects[args.clazz]
  fieldname = obj.fields[args.fieldID]
  classname = obj.__class__.__name__
  log.warning(f'!!!NOP!!! JavaEnv->SetStaticBooleanField("{classname}", "{fieldname}", {args.value:08X})')
  jitter.func_ret_systemv(ret_addr, 0x0)
  return True

def JavaEnv_SetStaticObjectField(jitter):
  ret_addr, args = jitter.func_args_systemv(['env', 'clazz', 'fieldID', 'value'])
  obj = Context.current.javaenv.objects[args.clazz]
  fieldname = obj.fields[args.fieldID]
  classname = obj.__class__.__name__
  log.warning(f'!!!NOP!!! JavaEnv->SetStaticObjectField("{classname}", "{fieldname}", {args.value:08X})')
  jitter.func_ret_systemv(ret_addr, 0x0)
  return True

def JavaEnv_GetObjectField(jitter):
  ret_addr, args = jitter.func_args_systemv(['env', 'obj', 'fieldID'])
  addr = Context.current.javaenv.GetObjectField(args.obj, args.fieldID)
  log.warning(f'JavaEnv->GetObjectField("{args.fieldID}) <- {addr:08X}')
  jitter.func_ret_systemv(ret_addr, addr)
  return True

def JavaEnv_GetArrayLength(jitter):
  ret_addr, args = jitter.func_args_systemv(['env', 'array'])
  length = Context.current.javaenv.GetArrayLength(args.array)
  jitter.func_ret_systemv(ret_addr, length)

def JavaEnv_ExceptionClear(jitter):
  ret_addr, args = jitter.func_args_systemv([])
  jitter.func_ret_systemv(ret_addr, 0x0)

def JavaEnv_CallVoidMethod(jitter):
  ret_addr, args = jitter.func_args_systemv(['javaEnv', 'classobj', 'methodID', 'arg0', 'arg1', 'arg2', 'arg3', 'arg4'])
  fn_args = args[3:]
  ret = Context.current.javaenv.CallMethod(args.classobj, args.methodID, fn_args)
  jitter.func_ret_systemv(ret_addr, ret)
  return True

def JavaEnv_CallObjectMethod(jitter):
  ret_addr, args = jitter.func_args_systemv(['javaEnv', 'classobj', 'methodID', 'arg0', 'arg1', 'arg2', 'arg3', 'arg4'])
  fn_args = args[3:]
  ret = Context.current.javaenv.CallMethod(args.clazz, args.methodID, fn_args)
  jitter.func_ret_systemv(ret_addr, ret)
  return True

def JavaEnv_CallStaticVoidMethodV(jitter):
  ret_addr, args = jitter.func_args_systemv(['env', 'clazz', 'methodID', 'args'])
  fn_args = varargs_to_list_aarch64(jitter, args.args)
  ret = Context.current.javaenv.CallMethod(args.clazz, args.methodID, fn_args)
  jitter.func_ret_systemv(ret_addr, ret)
  return True

def JavaEnv_CallStaticObjectMethod(jitter):
  ret_addr, args = jitter.func_args_systemv(['env', 'clazz', 'methodID', 'arg0', 'arg1', 'arg2', 'arg3', 'arg4'])
  fn_args = args[3:]
  ret = Context.current.javaenv.CallMethod(args.clazz, args.methodID, fn_args)
  jitter.func_ret_systemv(ret_addr, ret)
  return True

def JavaEnv_CallStaticObjectMethodV(jitter):
  ret_addr, args = jitter.func_args_systemv(['env', 'clazz', 'methodID', 'args'])
  fn_args = varargs_to_list_aarch64(jitter, args.args)
  ret = Context.current.javaenv.CallMethod(args.clazz, args.methodID, fn_args)
  jitter.func_ret_systemv(ret_addr, ret)
  return True

def JavaEnv_CallLongMethod(jitter):
  ret_addr, args = jitter.func_args_systemv(['env', 'clazz', 'methodID', 'arg0', 'arg1', 'arg2', 'arg3', 'arg4'])
  fn_args = args[3:]
  ret = Context.current.javaenv.CallMethod(args.clazz, args.methodID, fn_args)
  jitter.func_ret_systemv(ret_addr, ret)
  return True

def JavaEnv_CallIntMethodV(jitter):
  ret_addr, args = jitter.func_args_systemv(['env', 'clazz', 'methodID', 'args'])
  fn_args = varargs_to_list_aarch64(jitter, args.args)
  ret = Context.current.javaenv.CallMethod(args.clazz, args.methodID, fn_args)
  jitter.func_ret_systemv(ret_addr, ret)
  return True

def JavaEnv_CallBooleanMethodV(jitter):
  ret_addr, args = jitter.func_args_systemv(['env', 'obj', 'methodID', 'args'])
  fn_args = varargs_to_list_aarch64(jitter, args.args)
  ret = Context.current.javaenv.CallMethod(args.obj, args.methodID, fn_args)
  jitter.func_ret_systemv(ret_addr, ret)
  return True

def JavaEnv_CallStaticBooleanMethodV(jitter):
  ret_addr, args = jitter.func_args_systemv(['env', 'clazz', 'methodID', 'args'])
  fn_args = varargs_to_list_aarch64(jitter, args.args)
  ret = Context.current.javaenv.CallMethod(args.clazz, args.methodID, fn_args)
  jitter.func_ret_systemv(ret_addr, ret)
  return True

def JavaEnv_CallObjectMethodV(jitter):
  ret_addr, args = jitter.func_args_systemv(['env', 'obj', 'methodID', 'args'])
  fn_args = varargs_to_list_aarch64(jitter, args.args)
  ret = Context.current.javaenv.CallMethod(args.obj, args.methodID, fn_args)
  jitter.func_ret_systemv(ret_addr, ret)
  return True

def JavaEnv_GetObjectArrayElement(jitter):
  ret_addr, args = jitter.func_args_systemv(['env', 'array', 'index'])
  ret = Context.current.javaenv.GetObjectArrayElement(args.array, args.index)
  jitter.func_ret_systemv(ret_addr, ret)
  return True

def JavaEnv_SetObjectArrayElement(jitter):
  ret_addr, args = jitter.func_args_systemv(['env', 'array', 'index', 'value'])
  Context.current.javaenv.SetObjectArrayElement(args.array, args.index, args.value)
  jitter.func_ret_systemv(ret_addr, 0x0)
  return True

def JavaEnv_NewGlobalRef(jitter):
  ret_addr, args = jitter.func_args_systemv(['env', 'obj'])
  jitter.func_ret_systemv(ret_addr, args.obj)
  return True

def JavaEnv_DeleteGlobalRef(jitter):
  ret_addr, args = jitter.func_args_systemv(['env', 'obj'])
  jitter.func_ret_systemv(ret_addr, 0x0)
  return True

def JavaEnv_ExceptionCheck(jitter):
  ret_addr, _ = jitter.func_args_systemv([])
  jitter.func_ret_systemv(ret_addr, 0x0)
  return True

def JavaEnv_GetObjectClass(jitter):
  ret_addr, args = jitter.func_args_systemv(['env', 'obj'])
  ret = Context.current.javaenv.GetObjectClass(args.obj)
  jitter.func_ret_systemv(ret_addr, ret)
  return True

def JavaEnv_RegisterNatives(jitter):
  ret_addr, args = jitter.func_args_systemv(['javaEnv', 'classname', 'gMethods', 'numMethods'])
  for i in range(args.numMethods):
    ptr = args.gMethods+i*0x18
    name = jitter.get_c_str(jitter.vm.get_u64(ptr+0x0))
    sig = jitter.get_c_str(jitter.vm.get_u64(ptr+0x8))
    fnptr = jitter.vm.get_u64(ptr+0x10)
    log.warning(f'JavaEnv_RegisterNatives:\nName= {name}\nSig= {sig}\nFnPtr= {fnptr:08X}')
  jitter.func_ret_systemv(ret_addr, 0x0)
  return True

def JavaEnv_NewObject(jitter):
  ret_addr, args = jitter.func_args_systemv(['env', 'clazz', 'methodID', 'arg0', 'arg1', 'arg2', 'arg3'])
  fn_args = args[3:]
  ret = Context.current.javaenv.CallMethod(args.clazz, args.methodID, fn_args)
  jitter.func_ret_systemv(ret_addr, ret)
  return True

def JavaEnv_NewObjectV(jitter):
  ret_addr, args = jitter.func_args_systemv(['env', 'clazz', 'methodID', 'args'])
  fn_args = varargs_to_list_aarch64(jitter, args.args)
  ret = Context.current.javaenv.CallMethod(args.clazz, args.methodID, fn_args)
  jitter.func_ret_systemv(ret_addr, ret)
  return True

def JavaEnv_NewStringUTF(jitter):
  ret_addr, args = jitter.func_args_systemv(['javaEnv', 'bytes'])
  string = jitter.get_c_str(args.bytes)
  ret = Context.current.javaenv.NewStringUTF(string)
  log.warning(f'NEW UTF String {ret:08X} : {string}')
  jitter.func_ret_systemv(ret_addr, ret)
  return True

def JavaEnv_GetStringUTFChars(jitter):
  ret_addr, args = jitter.func_args_systemv(['javaEnv', 'string', 'isCopy'])
  string = Context.current.javaenv.GetStringUTFChars(args.string)
  addr = Context.current.linobjs.heap.alloc(jitter, len(string)+1)
  jitter.set_c_str(addr, string)
  log.warning(f'GetStringUTFChars({args.string}) <- {string}')
  jitter.func_ret_systemv(ret_addr, addr)
  return True

def JavaEnv_ReleaseStringUTFChars(jitter):
  ret_addr, args = jitter.func_args_systemv(['javaEnv', 'string', 'utf'])
  # TODO: Should free here
  jitter.func_ret_systemv(ret_addr, 0x0)
  return True

def JavaEnv_GetStringUTFLength(jitter):
  ret_addr, args = jitter.func_args_systemv(['javaEnv', 'string'])
  length = Context.current.javaenv.GetStringUTFLength(args.string)
  jitter.func_ret_systemv(ret_addr, length)
  return True

def JavaEnv_DeleteLocalRef(jitter):
  ret_addr, args = jitter.func_args_systemv(['javaEnv', 'localRef'])
  jitter.func_ret_systemv(ret_addr, 0x0)
  return True

def JavaEnv_ExceptionOccurred(jitter):
  # Just report that it all went well
  ret_addr, args = jitter.func_args_systemv(['javaEnv'])
  jitter.func_ret_systemv(ret_addr, 0x0)
  return True

