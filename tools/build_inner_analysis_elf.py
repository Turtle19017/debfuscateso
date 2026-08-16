#!/usr/bin/env python3
import argparse, csv, struct
from pathlib import Path

ET_DYN=3; EM_AARCH64=183; EV_CURRENT=1
PT_LOAD=1
PF_X=1; PF_W=2; PF_R=4
SHT_NULL=0; SHT_PROGBITS=1; SHT_SYMTAB=2; SHT_STRTAB=3; SHT_NOBITS=8
SHF_WRITE=1; SHF_ALLOC=2; SHF_EXECINSTR=4
STB_GLOBAL=1
STT_NOTYPE=0; STT_OBJECT=1; STT_FUNC=2

PAYLOAD_OFF=0x1000
RO_END=0x25E2E0
TEXT_END=0x4D6810
PLT_END=0x4E29C0
MEM_END=0x643000

KNOWN_SYMBOLS=[
    ('inner_code_start', 0x25E2E0, 0, STT_FUNC, 2),
    ('menu_renderer', 0x27CAEC, 0, STT_FUNC, 2),
    ('key_input_callsite', 0x27CFFC, 0, STT_NOTYPE, 2),
    ('auto_login_worker', 0x2948DC, 0, STT_FUNC, 2),
    ('login_worker', 0x29527C, 0, STT_FUNC, 2),
    ('auth_core', 0x298B94, 0, STT_FUNC, 2),
    ('plt0', 0x4D6810, 0x20, STT_FUNC, 3),
    ('plt_entries', 0x4D6830, PLT_END-0x4D6830, STT_NOTYPE, 3),
    ('login_status', 0x537730, 0, STT_OBJECT, 5),
    ('save_key_flag', 0x5390F8, 1, STT_OBJECT, 5),
    ('auto_login_flag', 0x5390F9, 1, STT_OBJECT, 5),
    ('saved_key', 0x539100, 0, STT_OBJECT, 5),
    ('key_buffer', 0x53912C, 0x100, STT_OBJECT, 5),
    ('auth_busy', 0x5392A0, 1, STT_OBJECT, 5),
]

def align(v,a): return (v+a-1)&~(a-1)

def pack_ehdr(phoff, shoff, phnum, shnum, shstrndx):
    ident=bytearray(16); ident[:4]=b'\x7fELF'; ident[4]=2; ident[5]=1; ident[6]=1
    return bytes(ident)+struct.pack('<HHIQQQIHHHHHH', ET_DYN, EM_AARCH64, EV_CURRENT,
        0, phoff, shoff, 0, 64, 56, phnum, 64, shnum, shstrndx)

def pack_phdr(flags, off, va, filesz, memsz, alignv=0x1000):
    return struct.pack('<IIQQQQQQ', PT_LOAD, flags, off, va, va, filesz, memsz, alignv)

def pack_shdr(name, typ, flags, addr, off, size, link=0, info=0, addralign=1, entsize=0):
    return struct.pack('<IIQQQQIIQQ', name, typ, flags, addr, off, size, link, info, addralign, entsize)

def section_for_value(value):
    if 0 <= value < RO_END: return 1
    if RO_END <= value < TEXT_END: return 2
    if TEXT_END <= value < PLT_END: return 3
    if PLT_END <= value < MEM_END:
        return 4 if value < 0x530070 else 5
    return 0

def load_recovered_symbols(metadata_dir):
    """Load dynsym.tsv/plt.tsv produced by recover_inner_symbols.py."""
    if not metadata_dir:
        return []
    d=Path(metadata_dir)
    extra=[]
    with (d/'dynsym.tsv').open(encoding='utf-8') as f:
        for row in csv.DictReader(f, delimiter='\t'):
            name=row['name']
            value=int(row['value'],16)
            size=int(row['size'],16)
            typ=int(row['type'])
            if not name or value == 0 or not (0 <= value < MEM_END):
                continue
            shndx=section_for_value(value)
            if not shndx:
                continue
            extra.append((name,value,size,typ,shndx))
    with (d/'plt.tsv').open(encoding='utf-8') as f:
        for row in csv.DictReader(f, delimiter='\t'):
            name=row['symbol_name']
            value=int(row['plt_address'],16)
            if not name or not (TEXT_END <= value < PLT_END):
                continue
            extra.append((name,value,0x10,STT_FUNC,3))
    return extra

def main():
    ap=argparse.ArgumentParser(description='Wrap recovered YSM inner memory image in a synthetic AArch64 ELF for analysis.')
    ap.add_argument('input'); ap.add_argument('output')
    ap.add_argument('--metadata-dir', help='directory from recover_inner_symbols.py; adds recovered dynsym and PLT labels')
    args=ap.parse_args()
    payload=Path(args.input).read_bytes()
    if len(payload)!=0x530070:
        print(f'[!] warning: expected sample size 0x530070, got 0x{len(payload):x}')
    if len(payload)>MEM_END: raise SystemExit('payload larger than configured synthetic memory end')

    secnames=['', '.blob', '.text', '.plt', '.data', '.bss', '.strtab', '.symtab', '.shstrtab']
    shstr=bytearray(b'\x00'); nameoff={'':0}
    for s in secnames[1:]: nameoff[s]=len(shstr); shstr += s.encode()+b'\x00'

    all_symbols=list(KNOWN_SYMBOLS) + load_recovered_symbols(args.metadata_dir)
    strtab=bytearray(b'\x00'); symname={}
    def intern(name):
        if name not in symname:
            symname[name]=len(strtab); strtab.extend(name.encode('utf-8',errors='replace')+b'\x00')
        return symname[name]
    syms=[b'\x00'*24]
    for n,val,size,typ,shndx in all_symbols:
        info=(STB_GLOBAL<<4)|(typ & 0xF)
        syms.append(struct.pack('<IBBHQQ', intern(n), info, 0, shndx, val, size))
    symtab=b''.join(syms)

    data=bytearray(PAYLOAD_OFF)
    data += payload
    strtab_off=align(len(data),8); data += b'\x00'*(strtab_off-len(data)); data += strtab
    symtab_off=align(len(data),8); data += b'\x00'*(symtab_off-len(data)); data += symtab
    shstr_off=align(len(data),8); data += b'\x00'*(shstr_off-len(data)); data += shstr
    shoff=align(len(data),8); data += b'\x00'*(shoff-len(data))

    sh=[]
    sh.append(pack_shdr(0,SHT_NULL,0,0,0,0))
    sh.append(pack_shdr(nameoff['.blob'],SHT_PROGBITS,SHF_ALLOC,0,PAYLOAD_OFF,RO_END,addralign=16))
    sh.append(pack_shdr(nameoff['.text'],SHT_PROGBITS,SHF_ALLOC|SHF_EXECINSTR,RO_END,PAYLOAD_OFF+RO_END,TEXT_END-RO_END,addralign=16))
    sh.append(pack_shdr(nameoff['.plt'],SHT_PROGBITS,SHF_ALLOC|SHF_EXECINSTR,TEXT_END,PAYLOAD_OFF+TEXT_END,PLT_END-TEXT_END,addralign=16,entsize=16))
    sh.append(pack_shdr(nameoff['.data'],SHT_PROGBITS,SHF_ALLOC|SHF_WRITE,PLT_END,PAYLOAD_OFF+PLT_END,len(payload)-PLT_END,addralign=16))
    sh.append(pack_shdr(nameoff['.bss'],SHT_NOBITS,SHF_ALLOC|SHF_WRITE,len(payload),PAYLOAD_OFF+len(payload),MEM_END-len(payload),addralign=16))
    sh.append(pack_shdr(nameoff['.strtab'],SHT_STRTAB,0,0,strtab_off,len(strtab),addralign=1))
    sh.append(pack_shdr(nameoff['.symtab'],SHT_SYMTAB,0,0,symtab_off,len(symtab),link=6,info=1,addralign=8,entsize=24))
    sh.append(pack_shdr(nameoff['.shstrtab'],SHT_STRTAB,0,0,shstr_off,len(shstr),addralign=1))
    for x in sh: data += x

    phoff=64; phnum=3
    ph=[
      pack_phdr(PF_R, PAYLOAD_OFF, 0, RO_END, RO_END),
      pack_phdr(PF_R|PF_X, PAYLOAD_OFF+RO_END, RO_END, PLT_END-RO_END, PLT_END-RO_END),
      pack_phdr(PF_R|PF_W, PAYLOAD_OFF+PLT_END, PLT_END, len(payload)-PLT_END, MEM_END-PLT_END),
    ]
    hdr=pack_ehdr(phoff,shoff,phnum,len(sh),8)
    data[:64]=hdr
    pos=phoff
    for x in ph: data[pos:pos+56]=x; pos+=56
    Path(args.output).write_bytes(data)
    print(f'[+] wrote {args.output}')
    print(f'    payload file offset : 0x{PAYLOAD_OFF:x}')
    print(f'    .text               : 0x{RO_END:x}..0x{TEXT_END:x}')
    print(f'    .plt                : 0x{TEXT_END:x}..0x{PLT_END:x}')
    print(f'    file-backed end     : 0x{len(payload):x}')
    print(f'    synthetic memory end: 0x{MEM_END:x}')
    print(f'    symbols             : {len(all_symbols)}')

if __name__=='__main__': main()
