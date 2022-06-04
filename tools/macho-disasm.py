#!/usr/bin/python

import os
import re
import sys

from capstone import *
from capstone.ppc import *
from macholib.mach_o import *
from macholib.MachO import *
from macholib.SymbolTable import *

macho = MachO(sys.argv[1])
symtab = SymbolTable(macho)

output_file = open(sys.argv[2], 'w')
# addr -> name
labels = {}



r13_addr = None
r2_addr = None

with open(sys.argv[1], 'rb') as machofile:
    filecontent = bytearray(machofile.read())

def read_u8(offset):
    return filecontent[offset]

def read_u16(offset):
    return (filecontent[offset + 0] << 8) | filecontent[offset + 1]

def read_u32(offset):
    return (filecontent[offset + 0] << 24) | (filecontent[offset + 1] << 16) | (filecontent[offset + 2] << 8) | filecontent[offset + 3]

def add_label(addr, name=None):
    if addr in labels:
        return labels[addr]
    if name == None:
        name = 'lbl_%08X' % addr
    labels[addr] = name
    return name


def sign_extend_16(value):
    if value > 0 and (value & 0x8000):
        value -= 0x10000
    return value

def sign_extend_12(value):
    if value > 0 and (value & 0x800):
        value -= 0x1000
    return value

cmdSizes = []

segmentNames = []
segmentOffsets = []
segmentAddresses = []

textOffsets = []
textAddresses = []
textSizes = []
textNames = []

dataOffsets = []
dataAddresses = []
dataSizes = []
dataNames = []

bssOffsets = []
bssAddresses = []
bssSizes = []
bssNames = []

entryPoint = None

for h in macho.headers:
    for (load_cmd, cmd, data) in h.commands:
        if data:
            for d in data:
                if hasattr(d, "sectname"):
                    sectionName = getattr(d, 'sectname', '').decode().rstrip('\0')
                    is_code = (getattr(d, 'flags', 0) & 0x80000000) != 0
                    print("# DEBUG: sectionName: %s, is_code: %s" % (sectionName, is_code))
                    print("# DEBUG:\tflags: %s" % d.flags)
                    print("# DEBUG:\taddr: %s" % d.addr)
                    print("# DEBUG:\tsize: %s" % d.size)
                    print("# DEBUG:\toffset: %s" % d.offset)
                    print("# DEBUG:\talign: %s" % d.align)
                    print("# DEBUG:\treloff: %s" % d.reloff)
                    print("# DEBUG:\tnreloc: %s" % d.nreloc)
                    print("# DEBUG:\tflags: %s" % d.flags)
                    if is_code:
                        textOffsets.append(d.offset)
                        textAddresses.append(d.addr)
                        textSizes.append(d.size)
                        textNames.append(sectionName)
                    elif d.offset != 0 and d.size != 0:
                        dataOffsets.append(d.offset)
                        dataAddresses.append(d.addr)
                        dataSizes.append(d.size)
                        dataNames.append(sectionName)
                    else :
                        bssOffsets.append(d.offset)
                        bssAddresses.append(d.addr)
                        bssSizes.append(d.size)
                        bssNames.append(sectionName)
                    
            if hasattr(d, "entryoff"):
                entryPoint = getattr(d, 'entryoff', 0)

output_file.write('/*\n')
output_file.write('Code sections:\n')
for i in range(0, len(textOffsets)):
    if textOffsets[i] != 0 and textAddresses[i] != 0 and textSizes[i] != 0:
        output_file.write('\t%s:\t0x%08X\t0x%08X\t0x%08X\n' % (textNames[i], textOffsets[i], textAddresses[i], textAddresses[i] + textSizes[i]))
output_file.write('Data sections:\n')
for i in range(0, len(dataOffsets)):
    if dataOffsets[i] != 0 and dataAddresses[i] != 0 and dataSizes[i] != 0:
        output_file.write('\t%s:\t0x%08X\t0x%08X\t0x%08X\n' % (dataNames[i], dataOffsets[i], dataAddresses[i], dataAddresses[i] + dataSizes[i]))
output_file.write('BSS sections:\n')
for i in range(0, len(bssOffsets)):
    if bssOffsets[i] != 0 and bssAddresses[i] != 0 and bssSizes[i] != 0:
        output_file.write('\t%s:\t0x%08X\t0x%08X\t0x%08X\n' % (bssNames[i], bssOffsets[i], bssAddresses[i], bssAddresses[i] + bssSizes[i]))
if entryPoint != None:
    output_file.write('Entry Point: 0x%08X\n' % entryPoint)
output_file.write('*/\n')

if entryPoint != None:
    labels[entryPoint] = '__start'

for sym in symtab.nlists:
    if sym[0].n_value != 0:
        #print("# DEBUG: Symbol 0x%08X: %s" % (sym[0].n_value, sym[1].decode()))
        labels[sym[0].n_value] = "\"%s\"" % sym[1].decode() 


def is_label_candidate(addr):
    if addr % 4 != 0:
        return False
    for i in range(0, len(textOffsets)):
        if addr >= textAddresses[i] and addr < textAddresses[i] + textSizes[i] and (addr & 3) == 0:
            return True
    for i in range(0, len(dataOffsets)):
        if addr >= dataAddresses[i] and addr < dataAddresses[i] + dataSizes[i]:
            return True
    for i in range(0, len(bssOffsets)):
        if addr >= bssAddresses[i] and addr < bssAddresses[i] + bssSizes[i]:
            return True
    return False

def off_to_addr(off: int) -> int:
    for i in range(0, len(textOffsets)):
        if off >= textOffsets[i] and off < textOffsets[i] + textSizes[i]:
            return textAddresses[i] + (off - textOffsets[i])
    for i in range(0, len(dataOffsets)):
        if off >= dataOffsets[i] and off < dataOffsets[i] + dataSizes[i]:
            return dataAddresses[i] + (off - dataOffsets[i])
    return None

def addr_to_off(addr: int) -> int:
    for i in range(0, len(textAddresses)):
        if addr >= textAddresses[i] and addr < textAddresses[i] + textSizes[i]:
            return textOffsets[i] + (addr - textAddresses[i])
    for i in range(0, len(dataAddresses)):
        if addr >= dataAddresses[i] and addr < dataAddresses[i] + dataSizes[i]:
            return dataOffsets[i] + (addr - dataAddresses[i])
    return None

def addr_is_in_text(addr):
    for i in range(0, len(textAddresses)):
        if addr >= textAddresses[i] and addr < textAddresses[i] + textSizes[i]:
            return True
    return False

# TODO: find all of them
loadStoreInsns = {
    PPC_INS_LWZ,
    PPC_INS_LMW,
    PPC_INS_LHA,
    PPC_INS_LHAU,
    PPC_INS_LHZ,
    PPC_INS_LHZU,
    PPC_INS_LBZ,
    PPC_INS_LBZU,
    PPC_INS_LFD,
    PPC_INS_LFDU,
    PPC_INS_LFS,
    PPC_INS_LFSU,
    PPC_INS_STW,
    PPC_INS_STWU,
    PPC_INS_STMW,
    PPC_INS_STH,
    PPC_INS_STHU,
    PPC_INS_STB,
    PPC_INS_STBU,
    PPC_INS_STFS,
    PPC_INS_STFSU,
    PPC_INS_STFD,
    PPC_INS_STDU,
}



# Returns true if the instruction is a load or store with the given register as a base 
def is_load_store_reg_offset(insn, reg):
    return insn.id in loadStoreInsns and (reg == None or insn.operands[1].mem.base == reg)

cs = Cs(CS_ARCH_PPC, CS_MODE_32 | CS_MODE_BIG_ENDIAN)
cs.detail = True
cs.imm_unsigned = False

blacklistedInsns = {
    # Unsupported instructions
    # PPC_INS_VMSUMSHM, PPC_INS_VMHADDSHS, PPC_INS_XXSLDWI, PPC_INS_VSEL,
    # PPC_INS_XVSUBSP, PPC_INS_XXSEL, PPC_INS_XVMULSP, PPC_INS_XVDIVSP,
    # PPC_INS_VADDUHM, PPC_INS_XXPERMDI, PPC_INS_XVMADDASP, PPC_INS_XVMADDMSP,
    # PPC_INS_XVCMPGTSP, PPC_INS_XXMRGHD, PPC_INS_XSMSUBMDP, PPC_INS_XSTDIVDP,
    # PPC_INS_XVADDSP, PPC_INS_XVCMPEQSP, PPC_INS_XVMSUBASP, PPC_INS_XVCMPGESP,
    # PPC_INS_VMRGHB, PPC_INS_MFTB, PPC_INS_MFTBU, PPC_INS_VPKUHUM,
    # PPC_INS_XSCMPODP, PPC_INS_XSCMPUDP, PPC_INS_XSMADDADP, PPC_INS_XSMADDMDP,
    # PPC_INS_XSMSUBADP, PPC_INS_XSNMADDADP, PPC_INS_XVCMPEQDP, PPC_INS_XVCMPGEDP,
    # PPC_INS_XVCMPGTDP, PPC_INS_XVMADDADP, PPC_INS_XVMADDMDP, PPC_INS_XVMSUBADP,
    # PPC_INS_XVMSUBMDP, PPC_INS_XVMSUBMSP, PPC_INS_XVNMADDADP, PPC_INS_XVNMADDMDP,
    # PPC_INS_XVNMSUBADP, PPC_INS_XVNMSUBASP, PPC_INS_XVNMSUBMDP, PPC_INS_XVNMSUBMSP,
    # PPC_INS_XVTDIVSP, PPC_INS_XVDIVDP, PPC_INS_VMADDFP, PPC_INS_XXMRGHW,
    # PPC_INS_VADDUBM, PPC_INS_XSSUBDP, PPC_INS_VADDUWM, PPC_INS_VMSUMUBM,

    # Instructions that Capstone gets wrong
    PPC_INS_MFESR, PPC_INS_MFDEAR, PPC_INS_MTESR, PPC_INS_MTDEAR, PPC_INS_MFICCR, PPC_INS_MFASR
}

def disasm_iter(offset, address, size, callback):
    if size == 0:
        return
    start = address
    end = address + size
    while address < end:
        code = filecontent[offset + (address-start) : offset + size]
        for insn in cs.disasm(code, address):
            address = insn.address
            if insn.id in blacklistedInsns:
                callback(address, offset + address - start, None, insn.bytes)
            else:
                callback(address, offset + address - start, insn, insn.bytes)
            address += 4
        if address < end:
            o = offset + address - start
            callback(address, offset + address - start, None, filecontent[o : o + 4])
            address += 4

lisInsns = {}  # register : insn

splitDataLoads = {}  # address of load insn (both high and low) : data

linkedInsns = {}  # addr of lis insn : ori/addi insn

mflrs = {}


# Returns true if the instruction writes to the specified register
def reg_modified(insn, reg):
    if insn.op[0].type == PPC_OP_REG and insn.op[0].reg == reg:
        return True
    else:
        return False

def get_last_mflr(addr, reg): # returns the address of the most recent instance of mflr
    #print("# DEBUG: get_last_mflr(0x%08X, %d)" % (addr, reg))
    for i in range(addr, addr - 0x10000, -4):
        if i in mflrs and mflrs[i].operands[0].reg == reg:
            return i
    return None

# Computes the combined value from a lis, addi/ori instruction pairr
def combine_split_load_value(hiLoadInsn, loLoadInsn):
    value = None
    if hiLoadInsn.id == PPC_INS_LIS:
        #assert loLoadInsn.id in {PPC_INS_ADDI, PPC_INS_ORI}
        #assert loLoadInsn.operands[1].reg == hiLoadInsn.operands[0].reg
        # hiLoadInsn must be "lis rX, hiPart"
        value = hiLoadInsn.operands[1].imm << 16
        # loLoadInsn must be "addi rY, rX, loPart"
        if loLoadInsn.id == PPC_INS_ORI:
            value |= loLoadInsn.operands[2].imm
        elif loLoadInsn.id == PPC_INS_ADDI:
            value += sign_extend_16(loLoadInsn.operands[2].imm)
        elif is_load_store_reg_offset(loLoadInsn, hiLoadInsn.operands[0].reg):
            value += sign_extend_16(loLoadInsn.operands[1].mem.disp)
        else:
            assert False
    else:
        assert hiLoadInsn.id == PPC_INS_ADDIS
        value = hiLoadInsn.operands[2].imm << 16
        if loLoadInsn.id == PPC_INS_ORI:
            value |= loLoadInsn.operands[2].imm
        elif loLoadInsn.id == PPC_INS_ADDI:
            value += sign_extend_16(loLoadInsn.operands[2].imm)
        elif is_load_store_reg_offset(loLoadInsn, hiLoadInsn.operands[0].reg):
            value += sign_extend_16(loLoadInsn.operands[1].mem.disp)
        else:
            assert False
        address = get_last_mflr(hiLoadInsn.address, hiLoadInsn.operands[1].reg)
        value += address
    return value

def is_store_insn(insn):
    # TODO: all store instructions
    return insn.id in {PPC_INS_STW}

# Get labels
def get_label_callback(address, offset, insn, bytes):
    global r13_addr
    global r2_addr
    if insn == None:
        return
    #print("# %08X: %s %s" % (address, insn.mnemonic, insn.op_str))
    # if branch instruction
    if insn.id in {PPC_INS_B, PPC_INS_BL, PPC_INS_BC, PPC_INS_BDZ, PPC_INS_BDNZ, PPC_INS_BDNZL}:
        lisInsns.clear()
        for op in insn.operands:
            if op.type == PPC_OP_IMM:
                #print("label 0x%08X" % op.imm)
                if insn.id == PPC_INS_BL:
                    #labelNames[op.imm] = 'func_%08X' % op.imm
                    add_label(op.imm, 'func_%08X' % op.imm)
                else:
                    add_label(op.imm)
    if insn.id == PPC_INS_MFLR:
        mflrs[address] = insn
    # Detect split load (high part)
    # this is 'lis rX, hipart'
    if insn.id == PPC_INS_LIS:
        # Record instruction that loads into register with 'lis'
        lisInsns[insn.operands[0].reg] = insn
    elif insn.id == PPC_INS_ADDIS and get_last_mflr(insn.address, insn.operands[1].reg) != None:
        lisInsns[insn.operands[0].reg] = insn
    # Detect split load (low part)
    # this is either 'addi/ori rY, rX, lopart' or 'load/store rY, lopart(rX)'
    elif (insn.id in {PPC_INS_ADDI, PPC_INS_ORI} and insn.operands[1].reg in lisInsns) \
     or  (is_load_store_reg_offset(insn, None) and insn.operands[1].mem.base in lisInsns):
        hiLoadInsn = lisInsns[insn.operands[1].reg]
        # Compute combined value
        value = combine_split_load_value(hiLoadInsn, insn)
        if is_label_candidate(value):
            add_label(value)
        # Record linked instruction
        linkedInsns[hiLoadInsn.address] = insn
        splitDataLoads[hiLoadInsn.address] = value
        splitDataLoads[insn.address] = value
        lisInsns.pop(insn.operands[1].reg, None)
        # detect r2/r13 initialization
        if insn.id == PPC_INS_ORI and insn.operands[0].reg == insn.operands[1].reg:
            if r2_addr == None and insn.operands[0].reg == PPC_REG_R2:
                r2_addr = value
                print('# DEBUG: set r2 to 0x%08X' % value)
            elif r13_addr == None and insn.operands[0].reg == PPC_REG_R13:
                r13_addr = value
                print('# DEBUG: set r13 to 0x%08X' % value)
        if addr_to_off(value) != None:
                print("# DEBUG: recursively checking, starting at address %08X, for pointers..." % value)
                off = read_u32(addr_to_off(value))
                if is_label_candidate(off):
                    add_label(off)
                if addr_to_off(off) != None:
                    if not addr_is_in_text(off):
                        while off != 0 and addr_to_off(off) != None:
                            if addr_is_in_text(off) and off % 4 == 0:
                                print("# DEBUG: add label sub_%08X" % off)
                                add_label(off, 'sub_%08X' % off)
                                off = 0
                            else:   
                                off = read_u32(addr_to_off(off))
                                if is_label_candidate(off):
                                    print("# DEBUG: add label 0x%08X" % off)
                                    add_label(off)
                                    if read_u32(addr_to_off(off)) == 0: # definitely not a pointer
                                        off = 0
                off = read_u32(addr_to_off(value))
                if addr_to_off(off) != None:
                    if not addr_is_in_text(off):
                        while off != 0 and addr_to_off(off) != None:
                            if addr_is_in_text(off) and off % 4 == 0:
                                print("# DEBUG: add label sub_%08X" % off)
                                add_label(off, 'sub_%08X' % off)
                                off = 0
                            else:   
                                off = read_u32(addr_to_off(off))
                                if is_label_candidate(off):
                                    print("# DEBUG: add label 0x%08X" % off)
                                    add_label(off)
                                    if read_u32(addr_to_off(off)) == 0: # definitely not a pointer
                                        off = 0
                
    # Remove record if register is overwritten
    elif (not is_store_insn(insn)) and len(insn.operands) >= 1 and insn.operands[0].type == PPC_OP_REG:
        lisInsns.pop(insn.operands[0].reg, None)

    # Handle r13 offset values
    if r13_addr != None:
        if insn.id == PPC_INS_ADDI and insn.operands[1].value.reg == PPC_REG_R13:  # r13 offset
            value = r13_addr + sign_extend_16(insn.operands[2].imm)
            if is_label_candidate(value):
                add_label(value)
                #labelNames[value] = 'r13_%08X' % value
        if is_load_store_reg_offset(insn, PPC_REG_R13):
            value = r13_addr + sign_extend_16(insn.operands[1].mem.disp)
            if is_label_candidate(value):
                add_label(value)
                #labelNames[value] = 'r13_%08X' % value

    # Handle r2 offset values
    if r2_addr != None:
        if insn.id == PPC_INS_ADDI and insn.operands[1].value.reg == PPC_REG_R2:  # r13 offset
            value = r2_addr + sign_extend_16(insn.operands[2].imm)
            if is_label_candidate(value):
                add_label(value)
                #labelNames[value] = 'r2_%08X' % value
        if is_load_store_reg_offset(insn, PPC_REG_R2):
            value = r2_addr + sign_extend_16(insn.operands[1].mem.disp)
            if addr_to_off(value) != None:
                add_label(value)
                off = read_u32(addr_to_off(value))
                if off % 4 == 0 and addr_to_off(off) != None:
                    if not addr_is_in_text(off):
                        add_label(off)
                        while off % 4 == 0 and addr_to_off(off) != None:
                            if addr_is_in_text(off):
                                print("# DEBUG: add label 0x%08X" % off)
                                add_label(off, 'sub_%08X' % off)
                                off = 0
                            else:   
                                off = read_u32(addr_to_off(value))
                                if is_label_candidate(off):
                                    print("# DEBUG: add label 0x%08X" % off)
                                    add_label(off)

for i in range(0, len(textAddresses)):
    if textSizes[i] != 0:
        disasm_iter(textOffsets[i], textAddresses[i], textSizes[i], get_label_callback)
def align_length(address, orig_length, alignment):
    while (address + orig_length) % alignment != 0:
        orig_length += 1
    return orig_length
for d in range(len(dataAddresses)):
    for i in range(dataAddresses[d], dataAddresses[d] + dataSizes[d]):
        if i in labels:
            print("# DEBUG: checking for pointers in data at 0x%08X, until the next label" % i)
            i += 4
            while not align_length(0, i, 4) in labels and i < dataAddresses[d] + dataSizes[d]:
                if addr_to_off(i) != None:
                    off = read_u32(addr_to_off(i))
                    if is_label_candidate(off) and off % 4 == 0:
                        print("# DEBUG: add label 0x%08X" % off)
                        add_label(off)
                        add_label(i)
                i += 4
            print("# DEBUG: done checking for pointers in data at 0x%08X" % i)

# Write macros
output_file.write('# PowerPC Register Constants\n')
for i in range(0, 32):
    output_file.write(".set r%i, %i\n" % (i, i))
for i in range(0, 32):
    output_file.write(".set f%i, %i\n" % (i, i))
if r13_addr != None:
    output_file.write('# Small Data Area (read/write) Base\n')
    output_file.write(".set _SDA_BASE_, 0x%08X\n" % r13_addr)
if r2_addr != None:
    output_file.write('# Small Data Area (read only) Base')
    output_file.write(".set _SDA2_BASE_, 0x%08X\n" % r2_addr)
output_file.write('\n')

# Converts the instruction to a string, fixing various issues with Capstone
def insn_to_text(insn, raw):
    # Probably data, not a real instruction
    if insn.id == PPC_INS_BDNZ and (insn.bytes[0] & 1):
        return None
    if insn.id in {PPC_INS_B, PPC_INS_BL, PPC_INS_BDZ, PPC_INS_BDNZ, PPC_INS_BDNZL}:
        return "%s %s" % (insn.mnemonic, add_label(insn.operands[0].imm))
    elif insn.id == PPC_INS_BC:
        branchPred = '+' if (insn.bytes[1] & 0x20) else ''
        if insn.operands[0].type == PPC_OP_IMM:
            return "%s%s %s" % (insn.mnemonic, branchPred, add_label(insn.operands[0].imm))
        elif insn.operands[1].type == PPC_OP_IMM:
            return "%s%s %s, %s" % (insn.mnemonic, branchPred, insn.reg_name(insn.operands[0].value.reg), add_label(insn.operands[1].imm))
    # Handle split loads (high part)
    if insn.address in splitDataLoads and insn.id in {PPC_INS_LIS, PPC_INS_ADDIS}:
        loLoadInsn = linkedInsns[insn.address]
        #assert loLoadInsn.id in {PPC_INS_ADDI, PPC_INS_ORI}
        value = splitDataLoads[insn.address]
        suffix = 'h' if loLoadInsn.id == PPC_INS_ORI else 'ha'
        if insn.id == PPC_INS_LIS:
            return '%s %s, %s@%s' % (insn.mnemonic, insn.reg_name(insn.operands[0].reg), add_label(value), suffix)
        else:
            return '%s %s, %s, %s@%s' % (insn.mnemonic, insn.reg_name(insn.operands[0].reg), insn.reg_name(insn.operands[1].reg), add_label(value), suffix)
    # Handle split loads (low part)
    elif insn.address in splitDataLoads and insn.id in {PPC_INS_ADDI, PPC_INS_ORI}:
        value = splitDataLoads[insn.address]
        return '%s %s, %s, %s@l' % (insn.mnemonic, insn.reg_name(insn.operands[0].reg), insn.reg_name(insn.operands[1].reg), add_label(value))
    elif insn.address in splitDataLoads and is_load_store_reg_offset(insn, None):
        value = splitDataLoads[insn.address]
        return '%s %s, %s@l(%s)' % (insn.mnemonic, insn.reg_name(insn.operands[0].reg), add_label(value), insn.reg_name(insn.operands[1].mem.base))

    # r13 offset loads
    if r13_addr != None:
        if insn.id == PPC_INS_ADDI and insn.operands[1].reg == PPC_REG_R13:
            value = r13_addr + sign_extend_16(insn.operands[2].imm)
            if value in labels:
                return "%s %s, %s, %s@sda21" % (insn.mnemonic, insn.reg_name(insn.operands[0].reg), insn.reg_name(insn.operands[1].reg), add_label(value))
        if is_load_store_reg_offset(insn, PPC_REG_R13):
            value = r13_addr + sign_extend_16(insn.operands[1].mem.disp)
            if value in labels:
                return "%s %s, %s@sda21(%s)" % (insn.mnemonic, insn.reg_name(insn.operands[0].value.reg), add_label(value), insn.reg_name(insn.operands[1].mem.base))

    # r2 offset loads
    if r2_addr != None:
        if insn.id == PPC_INS_ADDI and insn.operands[1].reg == PPC_REG_R2:
            value = r2_addr + sign_extend_16(insn.operands[2].imm)
            if value in labels:
                return "%s %s, %s, %s@sda21" % (insn.mnemonic, insn.reg_name(insn.operands[0].reg), insn.reg_name(insn.operands[1].reg), add_label(value))
        if is_load_store_reg_offset(insn, PPC_REG_R2):
            value = r2_addr + sign_extend_16(insn.operands[1].mem.disp)
            if value in labels:
                return "%s %s, %s@sda21(%s)" % (insn.mnemonic, insn.reg_name(insn.operands[0].value.reg), add_label(value), insn.reg_name(insn.operands[1].mem.base))

    # Sign-extend immediate values because Capstone is an idiot and doesn't do that automatically
    if insn.id in {PPC_INS_ADDI, PPC_INS_ADDIC, PPC_INS_SUBFIC, PPC_INS_MULLI} and (insn.operands[2].imm & 0x8000):
        return "%s %s, %s, %i" % (insn.mnemonic, insn.reg_name(insn.operands[0].reg), insn.reg_name(insn.operands[1].value.reg), insn.operands[2].imm - 0x10000)
    elif (insn.id == PPC_INS_LI or insn.id == PPC_INS_CMPWI) and (insn.operands[1].imm & 0x8000):
        return "%s %s, %i" % (insn.mnemonic, insn.reg_name(insn.operands[0].reg), insn.operands[1].imm - 0x10000)
    # cntlz -> cntlzw
    elif insn.id == PPC_INS_CNTLZW:
        return "cntlzw %s" % insn.op_str
    elif insn.id == PPC_INS_MTICCR:
        return 'mtictc %s' % insn.op_str
    # Dunno why GNU assembler doesn't accept this
    elif insn.id == PPC_INS_LMW and insn.operands[0].reg == PPC_REG_R0:
        return '.4byte 0x%08X  /* illegal %s %s */' % (raw, insn.mnemonic, insn.op_str)
    return '%s %s' % (insn.mnemonic, insn.op_str)

def disasm_fcmp(inst):
    crd = (inst & 0x03800000) >> 23
    a = (inst & 0x001f0000) >> 16
    b = (inst & 0x0000f800) >> 11
    return 'fcmpo cr%i, f%i, f%i' % (crd, a, b)

def disasm_mspr(inst, mode):
    if (inst & 1):
        return None
    d = (inst & 0x03e00000) >> 21
    a = (inst & 0x001f0000) >> 16
    b = (inst & 0x0000f800) >>11
    spr = (b << 5) + a
    if mode:
        return 'mtspr 0x%X, r%i' % (spr, d)
    else:
        return 'mfspr r%i, 0x%X' % (d, spr)

def disasm_mcrxr(inst):
    if (inst & 0x007ff801):
        return None
    crd = (inst & 0x03800000) >> 23
    return 'mcrxr cr%i' % crd


# Disassemble code
def disassemble_callback(address, offset, insn, bytes):
    global output_file
    # Output label (if any)
    if address in labels:
        if not labels[address].startswith("lbl_"):
            output_file.write("\n.global %s\n" % labels[address])
        output_file.write("%s:\n" % labels[address])
    prefixComment = '/* %08X %08X  %02X %02X %02X %02X */' % (address, offset, bytes[0], bytes[1], bytes[2], bytes[3])
    asm = None
    raw = read_u32(offset)
    if insn != None:
        asm = insn_to_text(insn, raw)
    else:  # Capstone couldn't disassemble it 
        idx = (raw & 0xfc000000) >> 26
        idx2 = (raw & 0x000007fe) >> 1
        # mtspr
        if idx == 31 and idx2 == 467:
            asm = disasm_mspr(raw, 1)
        # mfspr
        elif idx == 31 and idx2 == 339:
            asm = disasm_mspr(raw, 0)
        # mcrxr
        elif idx == 31 and idx2 == 512:
            asm = disasm_mcrxr(raw)
        # fcmpo
        elif idx == 63 and idx2 == 32:
            asm = disasm_fcmp(raw)
    if asm == None:
        asm = '.4byte 0x%08X  /* unknown instruction */' % raw
    output_file.write('%s\t%s\n' % (prefixComment, asm))

for i in range(0, len(textSizes)):
    if textSizes[i] != 0:
        output_file.write("\n.section %s, \"ax\"  # 0x%08X - 0x%08X\n" % (textNames[i], textAddresses[i], textAddresses[i] + textSizes[i]))
        disasm_iter(textOffsets[i], textAddresses[i], textSizes[i], disassemble_callback)

# Disassemble data
for i in range(0, len(dataSizes)):
    offset = dataOffsets[i]
    address = dataAddresses[i]
    size = dataSizes[i]
    start = address
    end = start + size
    if size == 0:
        continue
    output_file.write("\n.section %s, \"wa\"  # 0x%08X - 0x%08X\n" % (dataNames[i], start, end))
    # Get a sorted list of labels in this data section
    sectionLabels = []
    for l in labels:
        if l >= start and l < end:
            sectionLabels.append(l)
    sectionLabels.sort()
    # Split incbins by labels
    j = 0
    while address < end:
        if j < len(sectionLabels):
            incbinSize = sectionLabels[j] - address
            if incbinSize != 0:
                output_file.write("\t.incbin \"baserom\", 0x%X, 0x%X\n" % (offset, incbinSize))
            l = add_label(sectionLabels[j])
            output_file.write(".global %s # 0x%08X\n%s:\n" % (l, sectionLabels[j], l))
            j += 1
        else:
            incbinSize = end - address
            if incbinSize != 0:
                output_file.write("\t.incbin \"baserom\", 0x%X, 0x%X\n" % (offset, incbinSize))
        offset += incbinSize
        address += incbinSize
    # # Remove labels to avoid duplicates in case of overlap with other sections
    # for l in sectionLabels:
    #     labels.remove(l)

for i in range (0, len(bssAddresses)):
    output_file.write("\n.section %s, \"wa\"  # 0x%08X - 0x%08X\n" % (bssNames[i], bssAddresses[i], bssAddresses[i] + bssSizes[i]))
    start = bssAddresses[i]
    address = start
    end = start + bssSizes[i]
    sectionLabels = []
    for l in labels:
        if l >= start and l < end:
            sectionLabels.append(l)
    sectionLabels.sort()
    # Split incbins by labels
    j = 0
    while address < end:
        if j < len(sectionLabels):
            gapsize = sectionLabels[j] - address
            if gapsize != 0:
                output_file.write("\t.skip 0x%X\n" % gapsize)
            l = add_label(sectionLabels[j])
            output_file.write(".global %s # 0x%08X\n%s:\n" % (l,sectionLabels[j], l))
            j += 1
        else:
            gapsize = end - address
            if gapsize != 0:
                output_file.write("\t.skip 0x%X\n" % gapsize)
        address += gapsize

