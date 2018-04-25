#!/usr/bin/env python3
"""
PYTHON_VERSION: 3.5

Dumps the stack and heap from a process
Only works on linux
"""
from ptrace.debugger.debugger import PtraceDebugger
from ptrace.debugger.process import PtraceProcess
import argparse

def read_memory(start, end, process):
    return process.readBytes(start, (end-start))

def dump(process, pid):
    dumpfile = open('{}.dmp'.format(str(pid)), 'wb')
    mapfile = open('/proc/{}/maps'.format(process.pid))

    for line in mapfile:
        if 'heap' in line or 'stack' in line:
            start, end = line.split()[0].split('-')
            start = int(start, 16)
            end = int(end, 16)
            dumpfile.write(read_memory(start, end, process))
    mapfile.close()
    dumpfile.close()

def start(pid):
    # need to attach to the process with ptrace before you can read it's proc/$pid/maps
    # or be root I guess
    # https://unix.stackexchange.com/questions/6301/how-do-i-read-from-proc-pid-mem-under-linux
    # http://lkml.iu.edu/hypermail/linux/kernel/0505.0/0858.html 
    dbg = PtraceDebugger()
    process = dbg.addProcess(pid, False)
    dump(process, pid)
    dbg.quit()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("pid", help="What process do you want to dump?", type=int)
    args = parser.parse_args()
    start(args.pid)
