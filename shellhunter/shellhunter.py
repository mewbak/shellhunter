#!/usr/bin/env python3

import subprocess


def process_list():
    proc1 = subprocess.Popen(['ps', 'aux'], stdout=subprocess.PIPE)
    out = proc1.communicate()[0]
    proc1.stdout.close()
    out = out.decode().split('\n')
    for proc in out:
        print(proc)


def menu():
    while 1:
        print("What do you want to do?")
        print("1) View running processes")
        print("2) Dump a process memory")
        print("3) Check dump for shellcode")
        print("4) Exit")
        choice = input("> ")

        if '1' in choice:
            process_list()
        elif '2' in choice:
            print("What process? (pid)")
            pid = int(input("> "))
            dumper.start(pid)
        elif '3' in choice:
            print("What dumpfile?")
            dump = input("> ")
            print("What shellcode?")
            print('  '.join(detect.shellcodes.keys()))
            shellcode = input("> ")
            detect.check_match(dump, shellcode)
        elif '4' in choice:
            return
        else:
            print("Invalid option")
        print("")


if __name__ == "__main__":
    menu()
