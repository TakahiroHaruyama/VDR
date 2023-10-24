import argparse, os, subprocess, time, datetime
import pefile

g_ioctl_surface_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ida_ioctl_propagate.py')
#g_log_path = os.path.join(os.environ['IDADIR'], 'ioctl_batch.log')
g_found = []
g_error = []

ERR_DECOMPILE_FAILED = -1
ERR_UNKNOWN_WDF_VERSION = -2
ERR_NO_XREFTO_WDF_BIND_INFO = -3

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

g_debug = False

def info(msg):
    print("\033[34m\033[1m{}\033[0m {}".format('[*]', msg))

def success(msg):
    print("\033[32m\033[1m{}\033[0m {}".format('[+]', msg))
    
def error(msg):
    print("\033[31m\033[1m{}\033[0m {}".format('[!]', msg))

def debug(msg):
    if g_debug:
        print("\033[33m\033[1m{}\033[0m {}".format('[D]', msg))

def auto_int(x):
    return int(x, 0)        

def iter_file(d):
    
    for entry in os.listdir(d):
        if os.path.isfile(os.path.join(d, entry)):
            yield os.path.join(d, entry)

def iter_file_recursive(d):
    
    for root, dirs, files in os.walk(d):
        for file_ in files:
            yield os.path.join(root, file_)

def run_surface(target, log_path):

    # Identify x64 kernel driver
    try:
        pe = pefile.PE(target)
    except pefile.PEFormatError:
        debug('{}: Not PE file'.format(target))
        return 0
    if pefile.MACHINE_TYPE[pe.FILE_HEADER.Machine] != 'IMAGE_FILE_MACHINE_AMD64':
        debug('{}: Not x64 binary'.format(target))
        return 0

    # Make the command line
    ida_path = os.path.join(os.environ['IDADIR'], 'ida64.exe')
    if log_path:
        cmd = [ida_path, '-A', '-S{}'.format(g_ioctl_surface_path), '-L{}'.format(log_path), target]
    else:
        cmd = [ida_path, '-A', '-S{}'.format(g_ioctl_surface_path), target]
    debug(' '.join(cmd))
    
    # Run the script
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate()

    # Print the result
    global g_found, g_error
    ret_code = ctypes.c_int32(proc.returncode).value
    if ret_code == 400:
        res = "\033[32m\033[1m ALL PATHs FOUND \033[0m"
        g_found.append(target)
    elif ret_code in [200, 300]:
        res = "\033[33m\033[1m 1 or 2 PATHs FOUND \033[0m"
    elif ret_code == 100:
        res = "\033[33m\033[1m ONLY IOCTL HANDLER FOUND \033[0m"
    elif ret_code == 0:
        res = "\033[34m\033[1m NO IOCTL HANDLER FOUND \033[0m"
    elif ret_code == ERR_DECOMPILE_FAILED:
        res = "\033[31m\033[1m DECOMPILATION FAILED \033[0m"
        g_error.append(target)
    elif ret_code == ERR_UNKNOWN_WDF_VERSION:
        res = "\033[31m\033[1m UNKNOWN WDF VERSION \033[0m"
        g_error.append(target)
    elif ret_code == ERR_NO_XREFTO_WDF_BIND_INFO:
        res = "\033[31m\033[1m NO XREF TO _WDF_BIND_INFO \033[0m"
        g_error.append(target)
    else:
        # probably another issue
        res = "\033[31m\033[1m UNEXPECTED STATUS {} \033[0m".format(ret_code)
        g_error.append(target)
        
    success('{}: {}'.format(target, res))
    return 1
            
def parse_args():
    global g_debug
    
    parser = argparse.ArgumentParser(description='script desc', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('target', help="PE file or folder to analyze")
    parser.add_argument("-r", "--recursive", action='store_true', help="find file recursively")
    parser.add_argument("-d", "--debug", action='store_true', help="output debug message")
    parser.add_argument("-l", "--log", default=None, help="save IDA output to the log file")
    
    args = parser.parse_args()    
    g_debug = args.debug
    return args

def main():

    tstart = time.time()
    info('Start')
    
    args = parse_args()
    cnt = 0

    if os.path.isfile(args.target):
        cnt += run_surface(args.target, args.log)
    
    elif os.path.isdir(args.target):
        gen_lf = iter_file_recursive if args.recursive else iter_file
        
        for t in gen_lf(args.target):
            cnt += run_surface(t, args.log)

    tdelta = datetime.timedelta(seconds=time.time()-tstart)
    info('{} analyses done in {}'.format(cnt, tdelta))
    
    if g_found:
        success('{} potentially-vulnerable drivers found:'.format(len(g_found)))
        for f in g_found:
            print(os.path.basename(f))

    if g_error:
        error('{} drivers with error status:'.format(len(g_error)))
        for f in g_error:
            print(os.path.basename(f))

if ( __name__ == "__main__" ):
    main()        
        
