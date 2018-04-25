#!/usr/bin/env python3

import subprocess
import dumper
import detect

def process_list():
    proc1 = subprocess.Popen(['ps', 'aux'], stdout=subprocess.PIPE)
    out = proc1.communicate()[0]
    print(out)


def menu():
    while 1:
        print("What do you want to do?")
        print("1) View running processes")
        print("2) Dump a process memory")
        print("3) Check dump for shellcode")
        choice = input("> ")

        if '1' in choice:
            process_list()
        elif '2' in choice:
            print("What process? (pid)")
            pid = input("> ")
            dumper.start(pid)
        elif '3' in choice:
            print("What dumpfile?")
            dump = input("> ")
            print("What shellcode?")
            print(detect.shellcodes.keys())
            shellcode = input("> ")
            detect.check_match(dump, shellcode)
        else:
            print("Invalid option")
        print("")


if __name__ == "__main__":
    menu()