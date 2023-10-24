'''
This IDAPython script automates the following operations to find x64 vulnerable kernel drivers with firmware access.

* Triage
    1. Identify IOCTL handlers in WDM/WDF drivers
    2. Find execution paths from the handlers to the target API (MmMapIoSpace*) and instructions (IN/OUT)

* Analysis
    1. Fix union fields for IOCTL in the handlers and subroutines
    2. Propagate function argument names/types in subroutines recursively to decide if input/output can be controlled
       (sometimes you need to refresh the code by pressing F5)

Takahiro Haruyama (@cci_forensics)
'''

from idc import *
from idautils import *
import idaapi

from ida_hexrays import *
from ida_struct import *
import ida_typeinf, ida_pro, ida_auto, ida_loader, ida_idp, ida_kernwin

import ntpath, os

g_debug = False
#g_debug = True
g_skip_lumina = False
#g_skip_lumina = True
g_target_file_name = os.path.basename(get_input_file_path())

ERR_DECOMPILE_FAILED = -1
ERR_UNKNOWN_WDF_VERSION = -2
ERR_NO_XREFTO_WDF_BIND_INFO = -3

g_target_api_names = ['MmMapIoSpace', 'MmMapIoSpaceEx']
g_ioctl_handler_addrs = set()
g_ioctl_handler_name = 'fn_ioctl_handler'
g_follow_fn_names = ['DriverEntry', '_DriverEntry@8']
#g_tinfo_apply_flag = ida_typeinf.TINFO_GUESSED | ida_typeinf.TINFO_DELAYFUNC
g_tinfo_apply_flag = ida_typeinf.TINFO_DEFINITE
#g_tinfo_apply_flag = ida_typeinf.TINFO_GUESSED
g_in_helper_names = ['__inbyte', '__inword', '__indword']
g_out_helper_names = ['__outbyte', '__outword', '__outdword']
g_tapi_paths = set()
g_in_paths = set()
g_out_paths = set()
RENAME_RETRY_CNT = 10

# WDM
IRP_MJ_DEVICE_CONTROL = 14 # _DRIVER_OBJECT.MajorFunction[14] = DispatchDeviceControl
SOFF_PARAMS = 0x8 # Parameters structure offset in _IO_STACK_LOCATION
UNUM_IOCTL = 0x10 # DeviceIoControl union number in _IO_STACK_LOCATION.Parameters
SOFF_AIRP = 0x18  # AssociatedIrp structure offset in _IRP
UNUM_SBUF = 0x2   # SystemBuffer union number in _IRP.AssociatedIrp
import_type(-1, 'IO_STACK_LOCATION')
import_type(-1, 'IRP')
g_wdm_struc_union = [
    {'name':'IO_STACK_LOCATION', 'offset':SOFF_PARAMS, 'union_num':UNUM_IOCTL},
    {'name':'IRP', 'offset':SOFF_AIRP, 'union_num':UNUM_SBUF},
]

# WDF
g_wdf_hfile_path = ntpath.dirname(__file__).replace('/', '\\') + r'\kmdf_re\code\WDFStructs.h'
g_name_WDFFUNCTIONS = 'g_WDF_functions'
SOFF_FUNCTABLE = 0x20 # FuncTable offset in _WDF_BIND_INFO
SOFF_VERSION = 0x10 # Version in _WDF_BIND_INFO
SOFF_IOQUEUECREATE = 0x4C0 # pfnWdfIoQueueCreate offset in WDFFUNCTIONS
'''
NTSTATUS WdfIoQueueCreate(
  _In_      WDFDEVICE              Device,
  _In_      PWDF_IO_QUEUE_CONFIG   Config,
  _In_opt_  PWDF_OBJECT_ATTRIBUTES QueueAttributes,
  _Out_opt_ WDFQUEUE               *Queue
);
'''
ARG_IOQUEUECONFIG = 2 # RCX = WdfDriverGlobals object
SOFF_IODEVCTL = 0x28 # EvtIoDeviceControl offset in WDF_IO_QUEUE_CONFIG
g_decl_WdfVersionBind = 'NTSTATUS __fastcall WdfVersionBind(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath, PWDF_BIND_INFO BindInfo, PVOID ComponentGlobals);'
g_decl_wrapper_WdfIoQueueCreate = 'NTSTATUS __fastcall WdfIoQueueCreate(PVOID Device, PWDF_IO_QUEUE_CONFIG Config, PVOID QueueAttributes, PVOID *Queue);'
g_decl_EvtWdfIoQueueIoDeviceControl = 'void __fastcall EvtWdfIoQueueIoDeviceControl(PVOID Queue, PVOID Request, size_t OutputBufferLength, size_t InputBufferLength, ULONG IoControlCode);'
# APIs handling user input/output
g_decl_WdfRequestRetrieveInputBuffer = 'NTSTATUS __fastcall WdfRequestRetrieveInputBuffer(PVOID ComponentGlobals, PVOID Request, size_t MinimumRequiredLength, PVOID *Buffer, size_t *Length);'
g_decl_WdfRequestRetrieveOutputBuffer = 'NTSTATUS __fastcall WdfRequestRetrieveOutputBuffer(PVOID ComponentGlobals, PVOID Request, size_t MinimumRequiredLength, PVOID *Buffer, size_t *Length);'
g_decl_WdfRequestRetrieveInputWdmMdl = 'NTSTATUS __fastcall WdfRequestRetrieveInputWdmMdl(PVOID ComponentGlobals, PVOID Request, PMDL *Mdl);'
g_decl_WdfRequestRetrieveOutputWdmMdl = 'NTSTATUS __fastcall WdfRequestRetrieveOutputWdmMdl(PVOID ComponentGlobals, PVOID Request, PMDL *Mdl);'
g_decl_WdfRequestRetrieveInputMemory = 'NTSTATUS __fastcall WdfRequestRetrieveInputMemory(PVOID ComponentGlobals, PVOID Request, PVOID *Memory);'
g_decl_WdfRequestRetrieveOutputMemory = 'NTSTATUS __fastcall WdfRequestRetrieveOutputMemory(PVOID ComponentGlobals, PVOID Request, PVOID *Memory);'
g_decl_WdfRequestGetParameters = 'NTSTATUS __fastcall WdfRequestGetParameters(PVOID ComponentGlobals, PVOID Request, PWDF_REQUEST_PARAMETERS Parameters);'

g_buf_fns_off_decl = {
    0x868: g_decl_WdfRequestRetrieveInputBuffer,
    0x870: g_decl_WdfRequestRetrieveOutputBuffer,
    0x878: g_decl_WdfRequestRetrieveInputWdmMdl,
    0x880: g_decl_WdfRequestRetrieveOutputWdmMdl,
    0x858: g_decl_WdfRequestRetrieveInputMemory,
    0x860: g_decl_WdfRequestRetrieveOutputMemory,
    0x850: g_decl_WdfRequestGetParameters,
}
g_buf_fns_off_arg_names = {
    0x868: {3:'Buffer', 4:'Length'},
    0x870: {3:'Buffer', 4:'Length'},
    0x878: {2:'Mdl'},
    0x880: {2:'Mdl'},
    0x858: {2:'Memory'},
    0x860: {2:'Memory'},
    0x850: {2:'Parameters'},
}


# Colorize output for Windows
if os.name == 'nt':
    import ctypes
    ENABLE_PROCESSED_OUTPUT = 0x0001
    ENABLE_WRAP_AT_EOL_OUTPUT = 0x0002
    ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
    MODE = ENABLE_PROCESSED_OUTPUT + ENABLE_WRAP_AT_EOL_OUTPUT + ENABLE_VIRTUAL_TERMINAL_PROCESSING
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.GetStdHandle(-11)
    kernel32.SetConsoleMode(handle, MODE)

def info(msg):
    print("\033[34m\033[1m[*]\033[0m {}".format(msg))

def success(msg):
    print("\033[32m\033[1m[+]\033[0m {}".format(msg))
    
def error(msg):
    print("\033[31m\033[1m[!]\033[0m {}".format(msg))

def debug(msg):
    if g_debug:
        print("\033[33m\033[1m[D]\033[0m {}".format(msg))


class my_visitor_t(ctree_visitor_t):

    def __init__(self):
        
        ctree_visitor_t.__init__(self, CV_FAST)

    def check_var_flags(self, var, ea):
        _print = debug
        
        # Check the flags to judge if I should rename
        if var.has_nice_name:
            _print('{:#x}: {} has "nice name"'.format(ea, var.name))
        if var.has_user_name:
            _print('{:#x}: {} has user-defined name'.format(ea, var.name))
        if var.has_user_info:
            _print('{:#x}: {} has user-defined info'.format(ea, var.name))
        if var.is_arg_var:
            _print('{:#x}: {} is a function argument'.format(ea, var.name))
        #if var.is_promoted_arg():
        #    _print('{} is a promoted function argument'.format(var.name))
        if var.is_notarg:
            _print('{:#x}: {} is a local variable'.format(ea, var.name))

    # IDA decompiler has no API forcing lvar name
    def force_rename_lvar(self, ea, var, new_name):

        func_ea = get_func_attr(ea, FUNCATTR_START)
        debug('force_rename_lvar: function ea = {:#x}'.format(func_ea))

        old_name = var.name
        
        if rename_lvar(func_ea, var.name, new_name):
            info('{:#x}: lvar name changed "{}" ->  "{}" (rename_lvar)'.format(ea, old_name, new_name))
            var.name = new_name # to refresh immediately
            return
                
        for i in range(RENAME_RETRY_CNT):
            
            if rename_lvar(func_ea, var.name, new_name + '_{}'.format(i + 1)):
                info('{:#x}: lvar name changed "{}" -> "{}" (rename_lvar)'.format(ea, old_name,
                                                                                  new_name + '_{}'.format(i + 1)))
                var.name = new_name + '_{}'.format(i + 1)
                break
        else:
            error('{:#x}: renaming {} failed (rename_lvar, {} times)'.format(ea, var.name, RENAME_RETRY_CNT))
        '''
            # Try to rename using modify_user_lvars
            my_lvar_mod = my_lvar_modifier_t(var.name, new_name=new_name)
            if modify_user_lvars(func_ea, my_lvar_mod):
                info('{:#x}: lvar name "{}" set (modify_user_lvars)'.format(ea, new_name))
            else:
                error('{:#x}: renaming {} failed (modify_user_lvars)'.format(ea, var.name))
        '''

    # Find lvar with type recursively 
    def search_lvar(self, expr, _type=None):
        debug('{:#x}: cot number = {}'.format(expr.ea, expr.op))
        var = tif = None

        if expr.op == cot_var:
            var = expr.v.getv()
            tif = _type
            debug('{:#x}: var={} type={}'.format(expr.ea, var.name, str(tif)))
            if tif:                
                ida_typeinf.remove_tinfo_pointer(tif, None, tif.get_til())

        elif expr.op == cot_cast:            
            var, tif = self.search_lvar(expr.x, expr.type)

        elif expr.op in [cot_ref, cot_ptr]:
            var, tif = self.search_lvar(expr.x, _type)

        #debug('{:#x}: var={} ({})'.format(expr.ea, var.name, str(tif)))
        return var, tif

    def is_obj_WDFFUNCTIONS(self, expr):

        obj_name = None
        if expr.op == cot_obj:
            obj_name = get_name(expr.obj_ea)
        
        return str(expr.type).find('WDFFUNCTIONS') != -1 or obj_name == g_name_WDFFUNCTIONS

# Summarize a name in a specified tree
class sumname_visitor_t(my_visitor_t):

    MAX_NAME_LEN = 64

    def __init__(self):
        
        ctree_visitor_t.__init__(self, CV_PARENTS)
        #ctree_visitor_t.__init__(self, CV_FAST)
        self.summed_name = ''
        self.ignore_names = ['LowPart', 'anonymous_0']
        self.contains_struc_mem = False

    #def leave_expr(self, expr): # this makes function argument renaming fail
    def visit_expr(self, expr):

        debug('{:#x} (sumname_visitor_t): op = {}'.format(expr.ea, expr.op))
        
        if expr.op == cot_var:
            var = expr.v.getv()
            self.check_var_flags(var, expr.ea)

            if (var.has_user_name or var.is_arg_var or not var.name.startswith('v')) and \
               self.summed_name.find(var.name) == -1:
                #if self.summed_name.endswith('_deref') and var.name.startswith('_deref'):
                #    self.summed_name += var.name[len('_deref'):] # prevent "_deref_deref_deref..."
                #else:
                self.summed_name += '_' + var.name
            '''
            if not var.has_user_name and not var.is_arg_var and var.name.startswith('v'):
                # Abort (only user-defined or function argument names taken)
                #self.summed_name = ''
                #return 1
                return 0 # consider the case "deref_SystemBuffer_field_20 + v6"
            '''

        elif expr.op in [cot_memref, cot_memptr]: # x.m or x->m
            union_or_struc_name = expr.x.type.get_type_name()                    
            mid = get_member_id(get_struc(get_struc_id(union_or_struc_name)), expr.m)
            debug('{:#x} (sumname_visitor_t): mid = {:#x}'.format(expr.ea, mid))
            
            if mid != BADADDR:
                mname = get_member_name(mid)
                debug('{:#x} (sumname_visitor_t): mname = {}'.format(expr.ea, mname))
                
                if mname and mname not in self.ignore_names:
                    self.summed_name += '_' + mname
                    
                    # Abort if one member name collected
                    return 1

        #elif expr.op == cot_memptr: # x->m
        #    pass # TBD

        elif expr.op == cot_ref: # &x
            self.summed_name += '_ref'

        elif expr.op == cot_ptr: # *x
            self.summed_name += '_deref'

        elif expr.op == cot_num:
            parent = self.parent_expr()
            debug('{:#x} (sumname_visitor_t): cot_num under parent {}'.format(expr.ea, parent.op))
            
            if parent.op == cot_add:
                
                if parent.x.op == cot_cast:
                    type_no_ptr = ida_typeinf.remove_pointer(parent.type)
                    debug('Casted type without pointer = {}, size = {}'.format(type_no_ptr, type_no_ptr.get_size()))
                    field_num = expr.n._value * type_no_ptr.get_size()
                else:
                    field_num = expr.n._value
                    
                self.summed_name += '_field_{:x}'.format(field_num)

        elif expr.op == cot_obj: # e.g., global variable
            name = get_name(expr.obj_ea)
            debug('{:#x} (sumname_visitor_t): global variable {} ({:#x})'.format(expr.ea, name, expr.obj_ea))
            self.summed_name += '_' + name

        elif expr.op == cot_call:
            # Abort (avoid assignment for return value)
            self.summed_name = ''
            return 1
                
        return 0

    def get_summed_name(self):
        debug('sumname_visitor_t: summarized name before filtering = {}'.format(self.summed_name))

        # Avoid ones without memref/memptr or with just ref (e.g., &v1)
        if self.summed_name.startswith('_field_') or self.summed_name == '_ref':
            return ''
        
        else:
            if len(self.summed_name) > self.MAX_NAME_LEN:
                shortened = self.summed_name[:self.MAX_NAME_LEN] + '_cut'
                debug('sumname_visitor_t: summarized name {} is too long and will be cut back as {}'.format(self.summed_name, shortened))
                self.summed_name = shortened
            return self.summed_name

# Change type of the specified lvar name
class my_lvar_modifier_t(user_lvar_modifier_t):

    def __init__(self, target_name, new_name=None, new_decl=None, new_tif=None):
        
        user_lvar_modifier_t.__init__(self)
        self.target_name = target_name
        self.new_name = new_name
        self.new_decl = new_decl
        self.new_tif = new_tif

    def modify_lvars(self, lvars):

        #debug('modify_lvars: len(lvars.lvvec) = {}'.format(len(lvars.lvvec)))
        if len(lvars.lvvec) == 0:
            error('modify_lvars: len(lvars.lvvec) == 0')

        for idx, one in enumerate(lvars.lvvec):
            debug('modify_lvars: target_name = "{}" current = "{}"'.format(self.target_name, one.name))
            # Set the type to the target var
            if one.name == self.target_name:

                if self.new_name:
                    one.name = self.new_name
                    info('modify_lvars: Name "{}" set to {}'.format(one.name, self.target_name))

                tif = None
                if self.new_decl:
                    
                    tif = ida_typeinf.tinfo_t()
                    res = ida_typeinf.parse_decl(tif, None, self.new_decl, 0)
                    #if not res:
                    #    error('{}: parse_decl from {} FAILED'.format(one.name, self.new_decl))
                        
                elif self.new_tif:
                    tif = self.new_tif

                if tif:
                    one.type = tif
                    info('modify_lvars: Type "{}" set to {}'.format(str(tif), one.name))

                return True

        return False

class wdf_ioctl_finder_t(my_visitor_t):

    def __init__(self):
        
        ctree_visitor_t.__init__(self, CV_PARENTS | CV_POST | CV_RESTART)
        self.handler_ea = None
        self.is_config_type_applied = self.is_config_arg_var = False

    def leave_expr(self, expr):

        # The search by expr.find_parent_of() will be limited to the children

        # Apply WDF_IO_QUEUE_CONFIG to the Config argument of WdfIoQueueCreate
        # Release: call -> cast -> memptr or memref
        # Debug:   call -> ptr  -> cast -> add
        if expr.op == cot_cast or (expr.op == cot_ptr and expr.x.op == cot_cast):

            e_call = self.parent_expr()
            if expr.is_call_object_of(e_call):

                e_target = expr.x if expr.op == cot_cast else expr.x.x

                if e_target.x is not None and self.is_obj_WDFFUNCTIONS(e_target.x) and \
                   ((e_target.op in [cot_memptr, cot_memref] and e_target.m == SOFF_IOQUEUECREATE) or \
                    (e_target.op == cot_add and e_target.y.op == cot_num and e_target.y.n._value == SOFF_IOQUEUECREATE)):
                    info('{:#x}: WdfIoQueueCreate called'.format(e_call.ea))
                    
                    arg_config = e_call.a.at(ARG_IOQUEUECONFIG)
                    var_config = None

                    if arg_config.op == cot_var:
                        var_config = arg_config.v.getv()
                    elif arg_config.op == cot_ref and arg_config.x.op == cot_var:
                        var_config = arg_config.x.v.getv()
                    
                    if var_config:
                        info('var_config found')

                        # Probably the lvar flags are not reliable?
                        #if var_config.has_user_name and var_config.has_user_type:
                        #if var_config.name == 'Config' and var_config.tif.get_type_name() == 'WDF_IO_QUEUE_CONFIG':
                        #if var_config.name == 'Config':
                        if self.is_config_type_applied:
                            info('"Config" has user-defined name and type already')
                        else:
                            # Rename the lvar
                            self.force_rename_lvar(e_call.ea, var_config, 'Config')
                            
                            # Apply WDF_IO_QUEUE_CONFIG to Config
                            if var_config.is_arg_var:
                                # Debug build contains the API wrapper
                                my_lvar_mod = my_lvar_modifier_t(var_config.name, new_decl='PWDF_IO_QUEUE_CONFIG;')
                                self.is_config_arg_var = True
                            else:
                                # Release build
                                my_lvar_mod = my_lvar_modifier_t(var_config.name, new_decl='WDF_IO_QUEUE_CONFIG;')
                            modify_user_lvars(get_func_attr(e_call.ea, FUNCATTR_START), my_lvar_mod)
                            self.is_config_type_applied = True

        # Get the assignment to WDF_IO_QUEUE_CONFIG.EvtIoDeviceControl
        elif expr.op == cot_asg:

            x = expr.x
            y = expr.y

            # Identify a WDF IOCTL handler
            if x.op == cot_memref and x.m == SOFF_IODEVCTL and str(x.x.type).find('WDF_IO_QUEUE_CONFIG') != -1:

                if y.op == cot_ref and y.x.op == cot_obj:
                    self.handler_ea = y.x.obj_ea
                elif y.op == cot_obj:
                    self.handler_ea = y.obj_ea

                if self.handler_ea:
                    success('{:#x}: EvtIoDeviceControl (WDF IOCTL handler) {:#x} FOUND'.format(expr.ea, self.handler_ea))
                    ida_name.force_name(self.handler_ea, g_ioctl_handler_name + '_wdf')                    
                    global g_ioctl_handler_addrs
                    g_ioctl_handler_addrs.add(self.handler_ea)
            
        return 0

    def get_ioctl_handler(self):

        return self.handler_ea
    
class ioctl_propagator_t(my_visitor_t):

    def __init__(self, call_path, ea, cfunc=None):
        
        #ctree_visitor_t.__init__(self, CV_FAST)
        #ctree_visitor_t.__init__(self, CV_PARENTS | CV_RESTART)
        ctree_visitor_t.__init__(self, CV_PARENTS | CV_POST | CV_RESTART)
        
        self.call_path = call_path + [ea]
        self.union_propagate_ll = {} # forced to rename local variable locations

        self.current_cfunc = cfunc

    def run_wdf_ioctl_finder(self, ea):
        
        func_ea = get_func_attr(ea, FUNCATTR_START)
        debug('{:#x}: Searching WDF IOCTL handler..'.format(func_ea))

        cfunc = get_ctree_root(func_ea)
        if cfunc:

            wif = wdf_ioctl_finder_t()
            wif.apply_to_exprs(cfunc.body, None)

            handler_ea = wif.get_ioctl_handler()            
            if handler_ea:
                return handler_ea
            
            # Trace back Config in the parent function if a function arg var is directly-used as the API arg
            elif wif.is_config_arg_var:
                # Likely the function is just the API wrapper
                ida_name.force_name(func_ea, 'fn_WdfIoQueueCreate')
                self.apply_func_type(None, func_ea, None, g_decl_wrapper_WdfIoQueueCreate, None)
                
                for ref in CodeRefsTo(func_ea, False):

                    info('Retry in the parent function {:#x} (debug build)'.format(ref))
                    handler_ea = self.run_wdf_ioctl_finder(ref)
                    if handler_ea:
                        return handler_ea

        return None
        
    def detect_wdf_ioctl_handler(self):
        
        # Wait until creating the xref to _WDF_BIND_INFO
        ida_auto.auto_wait()
 
        # Get the WDF version
        try:
            ref, = list(DataRefsTo(get_struc_id('_WDF_BIND_INFO')))
        except ValueError:
            error('detect_wdf_ioctl_handler: No reference to _WDF_BIND_INFO')
            if ida_kernwin.cvar.batch:
                exit_without_change(ERR_NO_XREFTO_WDF_BIND_INFO)
            else:
                return None
        ea_wdf_functions = get_qword(ref + SOFF_FUNCTABLE)
        ver_major = get_wide_dword(ref + SOFF_VERSION)
        ver_minor = get_wide_dword(ref + SOFF_VERSION + 4)
        ver_build = get_wide_dword(ref + SOFF_VERSION + 8)
        wdf_ver = '.'.join([str(x) for x in [ver_major, ver_minor, ver_build]])
        info('WDF version: Major.Minor.Build = {}'.format(wdf_ver))

        # undefine already-defined structures for tracking xrefs
        del_items(ea_wdf_functions)
        
        # Apply type PWDFFUNCTIONS to the FuncTable (new version >= 1.15.0)
        #if wdf_ver in ['1.15.0', '1.19.0', '1.21.0', '1.23.0', '1.25.0', '1.27.0', '1.31.0', '1.33.0', ]:        
        if ver_major >= 1 and ver_minor >= 15:
            # New version has the pointer to the structure
            ida_typeinf.apply_cdecl(None, ea_wdf_functions, 'PWDFFUNCTIONS;')
            ida_name.force_name(ea_wdf_functions, g_name_WDFFUNCTIONS)
            success('{:#x}: Type PWDFFUNCTIONS set (new KMDF version)'.format(ea_wdf_functions))
            
        # Apply type _WDFFUNCTIONS to the FuncTable (old version)            
        #elif wdf_ver in ['1.5.5825', '1.5.6000', '1.7.6001', '1.9.7600', '1.11.0', '1.13.0', ]:
        else:
            # Old version has the structure itself
            ida_typeinf.apply_cdecl(None, ea_wdf_functions, '_WDFFUNCTIONS;')
            ida_name.force_name(ea_wdf_functions, g_name_WDFFUNCTIONS)
            success('{:#x}: Type _WDFFUNCTIONS set (old KMDF version)'.format(ea_wdf_functions))

        # Apply types of WDF APIs handling input/output
        import_type(-1, '_WDFFUNCTIONS')
        for off, decl in g_buf_fns_off_decl.items():
            tif = ida_typeinf.tinfo_t()
            ida_typeinf.parse_decl(tif, None, decl, 0)
            tif.create_ptr(tif)
            sptr = get_struc(get_struc_id('_WDFFUNCTIONS'))
            mptr = get_member(sptr, off)
            res = set_member_tinfo(sptr, mptr, off, tif, 0)
            if res == SMT_OK:
                info('WDF API function type set OK "{}"'.format(decl))
            else:
                error('WDF API function type set FAILED ({}) "{}"'.format(res, decl))
        
        # Find IOCTL handler in the function calling WdfIoQueueCreate
        
        # Old version: get the reference to WdfIoQueueCreate directly
        if ida_typeinf.idc_get_type(ea_wdf_functions) == '_WDFFUNCTIONS':
            
            for ref_ea in DataRefsTo(ea_wdf_functions + SOFF_IOQUEUECREATE):
                info('{:#x}: Direct reference to {}.WdfIoQueueCreate found'.format(ref_ea, g_name_WDFFUNCTIONS))

                # Traversing requires twice (1st=apply WDF_IO_QUEUE_CONFIG, 2nd=find EvtIoDeviceControl)
                self.run_wdf_ioctl_finder(ref_ea)
                handler_ea = self.run_wdf_ioctl_finder(ref_ea)
                if handler_ea:
                    return handler_ea
        
        # Both versions: traverse read xrefs to the table (pointer)
        info('Traversing cross-references to detect a WDF IOCTL handler..')
        for ref in XrefsTo(ea_wdf_functions):
            #if XrefTypeName(ref.type) == 'Data_Read':

            # Traversing requires twice (1st=apply WDF_IO_QUEUE_CONFIG, 2nd=find EvtIoDeviceControl)
            self.run_wdf_ioctl_finder(ref.frm)
            handler_ea = self.run_wdf_ioctl_finder(ref.frm)
            if handler_ea:
                return handler_ea

        else:
            error('WDF IOCTL handler NOT FOUND')

        return None

    def apply_func_type(self, caller_ea, callee_ea, func_tif, func_cdecl, path_start):

        if func_tif:
            apply_flags = g_tinfo_apply_flag
            if ida_typeinf.apply_tinfo(callee_ea, func_tif, apply_flags):
                info('{:#x}: [FUNC TYPE APPLIED (tinfo)] {}'.format(callee_ea, str(func_tif)))
            else:
                error('{:#x}: Applying a function type by tinfo FAILED {}'.format(callee_ea, str(func_tif)))

        elif func_cdecl:
            if ida_typeinf.apply_cdecl(None, callee_ea, func_cdecl):
                info('{:#x}: [FUNC TYPE APPLIED (cdecl)] {}'.format(callee_ea, func_cdecl))
            else:
                error('{:#x}: Applying a function type by cdecl FAILED {}'.format(callee_ea, func_cdecl))

        '''
        if not path_start:
            if ida_typeinf.apply_callee_tinfo(caller_ea, func_tif):
                info('{:#x}: [FUNC TYPE APPLIED] (callee) {}'.format(caller_ea, str(func_tif)))
            else:
                error('{:#x}: Applying a function type (callee) FAILED {}'.format(caller_ea, str(func_tif)))
        '''

    def propagate_arg_types(self, caller_ea, callee_ea, func_tif=None, func_cdecl=None, path_start=False):

        if callee_ea in self.call_path:
            debug('{:#x}: Recursion detected'.format(caller_ea))
            return
        
        # Apply the function prototype
        self.apply_func_type(caller_ea, callee_ea, func_tif, func_cdecl, path_start)

        if get_name(callee_ea) == 'WdfVersionBind':
            
            # Identify IOCTL handler based on the WDF FuncTable
            ioctl_ea = self.detect_wdf_ioctl_handler()
            
            # Analyze this IOCTL handler and subroutines
            if ioctl_ea:
                debug('{:#x}: type = {}'.format(ioctl_ea, type(ioctl_ea)))
                self.propagate_arg_types(None, ioctl_ea, func_cdecl=g_decl_EvtWdfIoQueueIoDeviceControl,
                                         path_start=True)
            
            return

        # Apply the same op recursively
        cfunc = get_ctree_root(callee_ea)
        if cfunc:
            
            if path_start:
                iv = ioctl_propagator_t([], callee_ea, cfunc) # Start from the IOCTL handler
            else:
                iv = ioctl_propagator_t(self.call_path, callee_ea, cfunc)
                
            #iv.apply_to(cfunc.body, None)
            iv.apply_to_exprs(cfunc.body, None)

            # delayed saving to prevent lvar renaming errors
            cfunc.save_user_unions()

    def is_libthunk(self, ea):
        
        fname = get_func_name(ea)
        flags = get_func_attr(ea, FUNCATTR_FLAGS)

        if flags & FUNC_LIB:
            debug('{}: ignored because of library function'.format(fname))
            return True

        if flags & FUNC_THUNK:
            debug('{}: ignored because of thunk function'.format(fname))
            return True
            
        return False

    def is_lumina(self, ea):
        
        fname = get_func_name(ea)
        flags = get_func_attr(ea, FUNCATTR_FLAGS)

        if flags & FUNC_LUMINA:
            debug('{}: function information provided by Lumina'.format(fname))
            return True
            
        return False
    
    def get_struc_member_tinfo(self, struc_name, mem_offset):
        
        # Get the member at the offset
        mem = get_member(get_struc(get_struc_id(struc_name)), mem_offset)

        # Get the member tinfo_t
        tif = ida_typeinf.tinfo_t()
        if get_or_guess_member_tinfo(tif, mem):
            return tif
        else:
            error('Cannot get the structure {} member {:#x} tinfo'.format(struc_name, mem_offset))
            return None

    def set_union_type_number(self, expr, tif, unum):

        # Change the union type
        expr.type = tif
        info('{:#x}: [UNION TYPE APPLIED] {}'.format(expr.ea, tif.get_type_name()))

        # Change the union number
        expr.m = unum
        info('{:#x}: union member number changed to {:#x}'.format(expr.ea, expr.m))

        #cfunc = get_ctree_root(get_func_attr(expr.ea, FUNCATTR_START))
        cfunc = self.current_cfunc
        if cfunc:
            
            # Save the user selection into idb            
            path = ida_pro.intvec_t()
            path.add_unique(unum)
            cfunc.set_user_union_selection(expr.ea, path)
            #cfunc.save_user_unions() <- trigger lvar renaming errors

        # Save the location to rename the left-side lvar forcibly
        self.union_propagate_ll[expr.ea] = tif

    def wdm_fix_union_type_number(self, expr):

        for target in g_wdm_struc_union:

            if str(expr.x.x.type).find(target['name']) != -1 and expr.x.m == target['offset']:
                debug('{:#x}: changing the union type and number in {}'.format(expr.ea, target['name']))
                
                tif_struc_mem = self.get_struc_member_tinfo(target['name'], target['offset'])
                if tif_struc_mem:
                    tif_union_num = self.get_struc_member_tinfo(tif_struc_mem.get_type_name(), target['union_num'])
                    if tif_union_num:
                        self.set_union_type_number(expr, tif_union_num, target['union_num'])

                break
            
    def get_name_by_traverse(self, item, parent):
        
        sv = sumname_visitor_t()
        #sv.apply_to_exprs(item, None)
        sv.apply_to_exprs(item, parent)
        
        return sv.get_summed_name()

    def wdf_set_arg_name_and_type(self, expr, m):

        expr_call = self.parent_expr()
                
        if expr.is_call_object_of(expr_call):

            for i, vname in g_buf_fns_off_arg_names[m].items():
                arg = expr_call.a.at(i)
                var, tif = self.search_lvar(arg)
                debug('{:#x}: _WDFFUNCTIONS m={:#x} arg{} var={} ({})'.format(expr_call.ea, m, i, var, tif))

                if var:
                    self.force_rename_lvar(expr_call.ea, var, vname)
                    if tif:
                        my_lvar_mod = my_lvar_modifier_t(var.name, new_tif=tif)
                        modify_user_lvars(get_func_attr(expr_call.ea, FUNCATTR_START), my_lvar_mod)

    # WDM: Identify IOCTL handler then fix the IOCTL-related union member numbers
    # WDF: Set argument names and types of APIs handling input/output
    def visit_expr(self, expr):
        
        if expr.op == cot_asg:
            
            if expr.x.op == cot_idx:
                x = expr.x.x
                y = expr.x.y

                # WDM: Check the assignment to _DRIVER_OBJECT.MajorFunction[14] (WDM IOCTL handler)
                if x.op == cot_memptr and str(x.type) == 'PDRIVER_DISPATCH[28]' and \
                   y.op == cot_num and int(y.n._value) == IRP_MJ_DEVICE_CONTROL:
                    debug('{:#x}: likely assignment for IRP_MJ_DEVICE_CONTROL'.format(expr.ea))

                    # Check the right-hand is a casted ref
                    # After applying the type, the ref will become cot_obj
                    if expr.y.op == cot_cast:
                        # get the cot_obj
                        fptr = expr.y.x.x if expr.y.x.op == cot_ref else expr.y.x
                        success('{:#x}: WDM IOCTL handler {:#x} FOUND'.format(expr.ea, fptr.obj_ea))

                        ida_name.force_name(fptr.obj_ea, g_ioctl_handler_name + '_wdm')
                        global g_ioctl_handler_addrs
                        g_ioctl_handler_addrs.add(fptr.obj_ea)

                        # Analyze this IOCTL handler and subroutines
                        self.propagate_arg_types(expr.ea, fptr.obj_ea, func_tif=expr.y.type, path_start=True)

        elif expr.op == cot_memptr:

            if ida_kernwin.cvar.batch: # Skip in batch mode
                return 0
            
            debug('{:#x}: memptr {} (offset {:#x})'.format(expr.ea, str(expr.x.type), expr.m))

            # WDM: Fix the correct union type & member number
            if expr.x.op == cot_memptr:
                self.wdm_fix_union_type_number(expr)
            
            # WDF: Set argument names and types of WDF APIs handling input/output (new KMDF version)
            if expr.m in g_buf_fns_off_arg_names and self.is_obj_WDFFUNCTIONS(expr.x):

                self.wdf_set_arg_name_and_type(expr, expr.m)

        elif expr.op == cot_memref:

            if ida_kernwin.cvar.batch: # Skip in batch mode
                return 0
            
            debug('{:#x}: memref {} (offset {:#x})'.format(expr.ea, str(expr.x.type), expr.m))
            
            # WDM: Fix the correct union type & member number
            if expr.x.op == cot_memptr:
                self.wdm_fix_union_type_number(expr)
            
            # WDF: Set argument names and types of WDF APIs handling input/output (old KMDF version)
            # Pattern1: call -> memref
            if expr.m in g_buf_fns_off_arg_names and self.is_obj_WDFFUNCTIONS(expr.x):

                self.wdf_set_arg_name_and_type(expr, expr.m)
                                
        elif expr.op == cot_cast:
                                
            if ida_kernwin.cvar.batch: # Skip in batch mode
                return 0
            
            if expr.x.op == cot_memref:

                debug('{:#x}: memref {} (offset {:#x})'.format(expr.x.ea, str(expr.x.x.type), expr.x.m))

                # WDF: Set argument names and types of WDF APIs handling input/output (old KMDF version)
                # Pattern2: call -> cast -> memref
                if expr.x.m in g_buf_fns_off_arg_names and self.is_obj_WDFFUNCTIONS(expr.x.x):

                    self.wdf_set_arg_name_and_type(expr, expr.x.m)
                    
        return 0

    # Propagate type/name recursively and save paths to the target APIs/instructions
    # WDF: Load WDF type information then identify IOCTL handler
    def leave_expr(self, expr):

        if expr.op == cot_call:
            #func_name = get_func_name(expr.x.obj_ea)
            func_name = get_name(expr.x.obj_ea) # to get API name
            debug('{:#x}: call {} ({:#x})'.format(expr.ea, func_name, expr.x.obj_ea))

            # Identify the last path to the API call
            if func_name in g_target_api_names and self.call_path[0] in g_ioctl_handler_addrs:
                
                # Save the path
                global g_tapi_paths
                #g_tapi_paths.add(tuple(self.call_path + [expr.x.obj_ea])) # API address
                g_tapi_paths.add(tuple(self.call_path + [expr.ea])) # API call address

            # WDF: Detect WDF drivers and load WDFStructs.h
            if func_name == 'WdfVersionBind':
                info('{:#x}: WdfVersionBind called. Parsing a header file {}'.format(expr.ea, g_wdf_hfile_path))
                parse_decls(g_wdf_hfile_path, PT_FILE)
            
            # Avoid invalid ea, API calls and inline library functions
            elif expr.x.obj_ea == BADADDR or self.is_libthunk(expr.x.obj_ea) or \
                (not func_name.startswith('sub_') and func_name not in g_follow_fn_names and \
                 not self.is_lumina(expr.x.obj_ea)):
                return 0

            # Avoid Lumina functions explicitly
            if self.is_lumina(expr.x.obj_ea) and g_skip_lumina:
                return 0
            
            # Analyze the function arguments
            debug(('{:#x}: analyzing function arguments'.format(expr.ea)))
            pt_args = []
            for i in range(expr.a.size()):
                arg = expr.a.at(i)
                arg_type = str(arg.type)
                #info(arg.op)

                if ida_kernwin.cvar.batch: # Skip in batch mode
                    arg_name = ''
                else:
                    arg_name = self.get_name_by_traverse(arg, expr)
                if arg_name:
                    debug('{:#x}: argument summarized name {}'.format(arg.ea, arg_name))
                    arg_name += '_' + str(i) # Avoid duplicative names
                    #debug(arg.calc_type(True))                    
                    
                debug('arg {}: type = {}, name = {}'.format(i, arg_type, arg_name))
                pt_args.append('{} {}'.format(arg_type, arg_name))

            # Rename the function
            if func_name.startswith('sub_'):
                new_func_name = 'fn_{:X}'.format(expr.x.obj_ea)
            elif demangle_name(func_name, get_inf_attr(INF_SHORT_DN)):
                new_func_name = demangle_name(func_name, get_inf_attr(INF_SHORT_DN)).split('(')[0]
            else: # DriverEntry or Lumina functions or WdfVersionBind
                new_func_name = func_name
            ida_name.force_name(expr.x.obj_ea, new_func_name)

            cdecl_args = ', '.join(pt_args)            
            func_pt = '{} __fastcall {}({});'.format(expr.x.type.get_rettype(), new_func_name, cdecl_args)
            
            # WDF: Change the argument types for WdfVersionBind
            if func_name == 'WdfVersionBind':
                func_pt = g_decl_WdfVersionBind
                
            debug('{:#x}: assembled function prototype for {:#x} = "{}"'.format(expr.ea, expr.x.obj_ea,
                                                                               func_pt))            
            self.propagate_arg_types(expr.ea, expr.x.obj_ea, func_cdecl=func_pt)
        
        elif expr.op == cot_asg:

            if ida_kernwin.cvar.batch: # Skip in batch mode
                return 0

            # x: local variable without user-defined name and no function argument
            var, tif = self.search_lvar(expr.x)
            if var:
                self.check_var_flags(var, expr.ea)

                # Avoid vars with user-defined names or from arguments
                if var.has_user_name or var.is_arg_var:
                #if var.has_user_name:
                    return 0
                
                # Avoid vars automatically-renamed by IDA (but include if the location is in the list)
                debug('union_propagate_ll = {}'.format(['{:#x}'.format(x) for x in self.union_propagate_ll]))
                if not var.name.startswith('v') and expr.ea not in self.union_propagate_ll and \
                   expr.y.ea not in self.union_propagate_ll:
                    return 0
                
                debug('{:#x}: assign to lvar {}'.format(expr.ea, var.name))
                                
                # y: something derived from function argument (e.g., ptr->add->cast, cast, etc.)
                
                '''                
                # Memo: the following code will cause a crash
                func_ea = get_func_attr(expr.ea, FUNCATTR_START)
                cfunc = get_ctree_root(func_ea)
                cp = cfunc_parentee_t(cfunc)
                tif = ida_typeinf.tinfo_t()
                if cp.calc_rvalue_type(tif, expr.x):
                    debug('calculated type is {}'.format(str(tif)))
                '''
                
                # Traverse from y to summarize the right side name
                summed_name = self.get_name_by_traverse(expr.y, expr)
                if summed_name:
                    debug('{:#x}: right side summarized name {}'.format(expr.y.ea, summed_name))
                    #debug(expr.y.calc_type(True)) # cause INTERR
                    
                    self.force_rename_lvar(expr.ea, var, summed_name)

                    # Set types of fixed union member values
                    #if expr.y.ea in self.union_propagate_ll and expr.y.op == cot_cast:
                    if expr.y.ea in self.union_propagate_ll:
                        #my_lvar_mod = my_lvar_modifier_t(var.name, new_tif=self.union_propagate_ll[expr.y.ea])
                        my_lvar_mod = my_lvar_modifier_t(var.name, new_tif=expr.y.type)
                        modify_user_lvars(get_func_attr(expr.ea, FUNCATTR_START), my_lvar_mod)
        
        #elif expr.op == cot_cast:
        #    if expr.x.v:
        #        var = expr.x.v.getv()
        #        debug('{:#x}: cast var {}'.format(expr.ea, var.name))
        #        self.check_var_flags(var, expr.ea)

        elif expr.op == cot_helper:

            the_ea = self.parent_expr().ea

            if self.call_path[0] in g_ioctl_handler_addrs:
            
                if expr.helper in g_in_helper_names:
                    debug('{:#x}: IN instruction found'.format(the_ea))

                    # Save the path
                    global g_in_paths
                    g_in_paths.add(tuple(self.call_path + [the_ea]))

                elif expr.helper in g_out_helper_names:
                    debug('{:#x}: OUT instruction found'.format(the_ea))

                    # Save the path
                    global g_out_paths
                    g_out_paths.add(tuple(self.call_path + [the_ea]))

        return 0


# Ported from examples/hexrays/decompile_entry_points.py
def init_hexrays():
    
    ALL_DECOMPILERS = {
        ida_idp.PLFM_386: "hexrays",
        ida_idp.PLFM_ARM: "hexarm",
        ida_idp.PLFM_PPC: "hexppc",
        ida_idp.PLFM_MIPS: "hexmips",
    }
    cpu = ida_idp.ph.id
    decompiler = ALL_DECOMPILERS.get(cpu, None)
    
    if not decompiler:
        error("No known decompilers for architecture with ID: %d" % ida_idp.ph.id)
        return False
    
    if ida_ida.inf_is_64bit():
        if cpu == ida_idp.PLFM_386:
            decompiler = "hexx64"
        else:
            decompiler += "64"
    
    if ida_loader.load_plugin(decompiler) and init_hexrays_plugin():
        return True
    else:
        error('Couldn\'t load or initialize decompiler: "%s"' % decompiler)
        return False

def exit_without_change(status):

    print('-' * 50) # Differentiate the log

    # Not create/change idb
    process_config_line("ABANDON_DATABASE=YES")

    # Exit with the status code
    qexit(status)

def get_ctree_root(ea):
    
    cfunc = None
    try:
        #cfunc = idaapi.decompile(ea)
        cfunc = decompile(ea, flags=DECOMP_NO_CACHE)
    except:
        error('Decompilation of a function {:#x} failed'.format(ea))

    return cfunc

def add_bookmark(ea, comment):
    
    last_free_idx = -1
    for i in range(0, 1024):
        slot_ea = get_bookmark(i)
        if slot_ea == BADADDR or slot_ea == ea:
            # empty slot found or overwrite existing one
            last_free_idx = i
            break
        
    # Check Empty Slot
    if last_free_idx < 0:
        return False
    
    # Register Slot
    put_bookmark(ea, 0, 0, 0, last_free_idx, comment)
    
    return True

def print_and_bookmark_paths(target_desc, paths):

    if paths:
        success('Paths from the handlers to {} FOUND:'.format(target_desc))
        
        for path in paths:

            # Rename the functions leading to the target API (e.g., fn_path1, fn_path2, etc.)
            for i in range(1, len(path[:-1])):
                func_name = get_name(path[i])
                
                # Save the Lumina function names
                if not func_name.startswith('fn_path_') and func_name.startswith('fn_'):
                    ida_name.force_name(path[i], 'fn_path_{}'.format(i))

            # Bookmark the ea calling the API
            add_bookmark(path[-1], target_desc)
                
            print(' -> '.join([get_name(x) for x in path[:-1]]) +
                  ' -> {} at {:#x}'.format(target_desc, path[-1]))

        return 100

    return 0

def main():

    '''
            -1: Decompiler initialization failure
             0: The execution works but no IOCTL handler found
           100: IOCTL handler found but no path found
    200 or 300: IOCTL handler found and 1 or 2 paths found (e.g., paths to the target API and OUT insn)
           400: IOCTL and all paths found
    '''
    status = 0

    info('start')

    if ida_kernwin.cvar.batch: # batch mode execution

        # Wait until the initial auto analysis is finished
        ida_auto.auto_wait()

        # We need to load the decompiler manually
        if not init_hexrays():
            error('{}: Decompiler initialization failed. Aborted.'.format(g_target_file_name))
            if ida_kernwin.cvar.batch:
                exit_without_change(ERR_DECOMPILE_FAILED)

    # Demangle names
    idaapi.cvar.inf.demnames = 1
    ida_kernwin.refresh_idaview_anyway()

    #ea = get_screen_ea()
    ea = get_inf_attr(INF_START_IP)
    info('{:#x}: analysis start at "{}"'.format(ea, get_name(ea)))
    cfunc = get_ctree_root(ea)

    if cfunc:
        iv = ioctl_propagator_t([], ea)
        
        #iv.apply_to(cfunc.body, None)
        iv.apply_to_exprs(cfunc.body, None)

    if g_ioctl_handler_addrs:
        success('IOCTL handler addresses = {}'.format(['{:#x}'.format(x) for x in g_ioctl_handler_addrs]))
        status += 100

    status += print_and_bookmark_paths('call target API', g_tapi_paths)
    status += print_and_bookmark_paths('IN instruction', g_in_paths)
    status += print_and_bookmark_paths('OUT instruction', g_out_paths)
    
    info('{}: Done with status {}'.format(g_target_file_name, status))

    if ida_kernwin.cvar.batch:
        exit_without_change(status)

if __name__ == '__main__':
    main()
