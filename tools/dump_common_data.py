#!/usr/bin/env python3
#
# Usage: dump_common_data.py file.s
# Dumps all incbin data and prints the revised file to stdout.

import os
import re
import sys

labelNames = {}

print("# Scanning for labels first...")

file = open("main.s", "rt")
label = ''
address = 0
for line in file.readlines():
    line = line.rstrip()
    m = re.match(r'\s*\.global (.*) # (.*)', line)
    if m:
        g = m.groups()
        print("# Found label \"%s\" at 0x%08X" % (g[0], int(g[1], 16)))
        label = g[0]
        address = int(g[1], 0)
        labelNames[address] = label
        label = ''
        address = 0
    m = re.match(r'(.*):', line)
    if m:
        g = m.groups()
        label = g[0]
    else:
        m = re.match(r'\/\* ([0-9A-F]{8})', line)
        if m and label != '':
            g = m.groups()
            print("# Found label \"%s\" at 0x%08X" % (label, int(g[0], 16)))
            address = int(g[0], 16)
            labelNames[address] = label
            label = ''
            address = 0

# Reads a bytearray from baserom.dol
def read_baserom(start, size):
    with open('baserom', 'rb') as f:
        f.seek(start, os.SEEK_SET)
        return bytearray(f.read(size))

if len(sys.argv) != 3:
    print('Usage: %s ASM_FILE OUTPUT' % sys.argv[0])
    exit()

# reads a 32-bit big endian value starting at pos
def read_u32(data, pos):
    return (data[pos]<<24) | (data[pos+1]<<16) | (data[pos+2]<<8) | (data[pos+3])

def is_ascii(code):
    if code >= 0x20 and code <= 0x7E:  # normal characters
        return True
    if code in [0x09, 0x0A]:  # tab, newline
        return True
    return False

# reads a string starting at pos
def read_string(data, pos):
    text = ''
    while pos < len(data) and is_ascii(data[pos]):
        text += chr(data[pos])
        pos += 1
    if pos < len(data) and data[pos] == 0:
        return text
    return ''

output_file = open(sys.argv[2], "wt")

# escapes special characters in the string for use in a C string literal
def escape_string(text):
    return text.replace('\\','\\\\').replace('"','\\"').replace('\n','\\n').replace('\t','\\t')

# returns True if value is 4-byte aligned
def is_aligned(num):
    return num % 4 == 0

# returns True if value is a possible pointer
def is_pointer(num):
    return num in labelNames # commented out as this just returns false positives

# returns True if all elements are zero
def is_all_zero(arr):
    for val in arr:
        if val != 0:
            return False
    return True

def is_all_FF(arr):
    for val in arr:
        if val != 0xFF:
            return False
    return True

# returns string of comma-separated hex bytes
def hex_bytes(data):
    return ', '.join('0x%02X' % n for n in data)

def convert_data(data, offset, incsize):
    global output_file
    text = ''
    if is_all_zero(data) or is_all_FF(data):
        text += '\t.byte %s\n' % hex_bytes(data)
        return text
    if incsize <= 0x1:
        text += '\t.byte 0x%02X\n' % data[0]
        return text
    elif incsize == 2:
        text += '\t.byte 0x%02X, 0x%02X\n' % (data[0], data[1])
        return text
    elif incsize == 3:
        text += '\t.byte 0x%02X, 0x%02X, 0x%02X\n' % (data[0], data[1], data[2])
        return text
    size = len(data)
    pos = 0
    while pos < size:
        print("# Offset: 0x%08X" % (offset + pos))
        # # pad unaligned
        # pad = []
        # while not is_aligned(offset + pos) and pos < size:
        #     pad.append(data[pos])
        #     pos += 1
        

        # if len(pad) > 0:
        #     text += '\t.byte %s\n' % hex_bytes(pad)
        # string?
        string = read_string(data, pos)
        if len(string) > 2:
            text += '\t.asciz "%s"\n' % escape_string(string) 
            pos += len(string) + 1
            continue

        if not is_aligned(offset + pos) or size - pos < 4:
            text += '\t.byte %s\n' % hex_bytes(data[pos:pos+incsize])
            pos += incsize
            continue


        if pos + 4 <= size:
            val = read_u32(data, pos)
            if is_pointer(val):
                text += '\t.4byte %s ;# ptr (0x%08X)\n' % (labelNames[val], val)
            else:
                text += '\t.4byte 0x%08X\n' % val
            pos += 4  
    return text

currSection = ''

with open(sys.argv[1], 'rt') as f:
    for line in f.readlines():
        line = line.rstrip()
            # Incbin directive
        m = re.match(r'\t\.incbin\s+"baserom"\s*,\s*([^, \.]+),\s*([^, \.]+)', line)
        if m:
            g = m.groups()
            start = int(g[0], 0)
            size = int(g[1], 0)
            data = read_baserom(start, size)
            output_file.write('\t# ROM: 0x%X\n' % start)
            output_file.write(convert_data(data, start, size))
            continue
        output_file.write("%s\n" % line)