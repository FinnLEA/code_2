import os

encoding = 'utf-8'

def bin2asm(bytes):
    string = "\t"
    i = 0
    string+="\n\t"

    for byte in bytes:
        if i%16 == 0:
            string+="db "
        string+="0" + str(hex(ord(chr(byte))))[2:] + "h"
        i+=1
        if (i%16 == 0 or len(bytes)==i):
            string+="\n\t"
        else:
           string+=", "
    return string

try:
    v32bin = open('..\\bin\\x86\\virus32.bin', 'rb')
    v32asm = open(".\\virus32.asm", 'w+')
    v32asm.write(bin2asm(v32bin.read()))
    v32bin.close()
    v32asm.close()

    v64bin = open('..\\bin\\x64\\virus64.bin', 'rb')
    v64asm = open(".\\virus64.asm", 'w+')
    v64asm.write(bin2asm(v64bin.read()))
    v64bin.close()
    v64asm.close()
except Exception as exc:
    print(exc)