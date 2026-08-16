#!/usr/bin/env python3
"""Build a near-original-layout ELF from the recovered YSM inner raw file.

What is preserved/recovered:
- original e_phoff=0x40, e_phnum=9 and 9 program-header roles/offsets/VAs/sizes
- original three PT_LOAD file-to-VA mappings
- original PT_DYNAMIC location (file 0x505570 / VA 0x509570)
- original PT_NOTE bytes and Android NDK note
- recovered dynstr/dynsym/dependencies/RELA semantics

What is reconstructed rather than byte-for-byte original:
- p_paddr/p_align (not retained by the compact protected PHDR table)
- dynamic-table contents
- placement of recovered dynamic metadata

The exact SysV hash buckets/chains used by the custom resolver are recoverable.
The surviving original shstrtab encodes both `.gnu.hash` and the suffix alias `.hash`,
so the SysV table is now strong evidence for the original `.hash` semantics as well.
The producer's original `.gnu.hash` bytes are still not recovered.

Recovered metadata is placed into the original third PT_LOAD's former BSS space;
that segment's p_filesz is extended, but p_memsz and all virtual addresses remain
within the recovered original segment bounds.  This avoids adding a synthetic
fourth PT_LOAD and keeps the original 9-entry PHDR shape.
"""
from __future__ import annotations

import argparse
import csv
import json
import struct
from pathlib import Path

ET_DYN=3; EM_AARCH64=183; EV_CURRENT=1
PT_LOAD=1; PT_DYNAMIC=2
DT_NULL=0; DT_NEEDED=1; DT_PLTRELSZ=2; DT_PLTGOT=3; DT_HASH=4; DT_STRTAB=5; DT_SYMTAB=6
DT_RELA=7; DT_RELASZ=8; DT_RELAENT=9; DT_STRSZ=10; DT_SYMENT=11; DT_SONAME=14
DT_PLTREL=20; DT_JMPREL=23; DT_INIT_ARRAY=25; DT_FINI_ARRAY=26; DT_INIT_ARRAYSZ=27; DT_FINI_ARRAYSZ=28; DT_RELACOUNT=0x6FFFFFF9

DYNAMIC_FILE_OFF=0x505570
DYNAMIC_SIZE=0x230


def align(v:int,a:int)->int:
    return (v+a-1)&~(a-1)


def elf_hash(name:bytes)->int:
    h=0
    for c in name:
        h=(h<<4)+c
        g=h & 0xF0000000
        if g:
            h ^= g>>24
        h &= ~g
    return h & 0xffffffff


def parse_dynsym_names(dynsym:bytes,dynstr:bytes)->list[bytes]:
    if len(dynsym)%24:
        raise ValueError('dynsym length not divisible by 24')
    out=[]
    for i in range(len(dynsym)//24):
        st_name=struct.unpack_from('<I',dynsym,i*24)[0]
        if st_name==0:
            out.append(b''); continue
        if st_name>=len(dynstr):
            out.append(b''); continue
        e=dynstr.find(b'\0',st_name)
        if e<0:e=len(dynstr)
        out.append(dynstr[st_name:e])
    return out


def build_sysv_hash(names:list[bytes])->bytes:
    nchain=len(names)
    # A stable prime-sized bucket set; original bucket count was not retained.
    nbucket=4093 if nchain>4093 else max(1,nchain)
    buckets=[0]*nbucket
    chains=[0]*nchain
    for idx,name in enumerate(names):
        if idx==0 or not name:
            continue
        b=elf_hash(name)%nbucket
        if buckets[b]==0:
            buckets[b]=idx
        else:
            cur=buckets[b]
            while chains[cur]!=0:
                cur=chains[cur]
            chains[cur]=idx
    return struct.pack('<II',nbucket,nchain)+struct.pack(f'<{nbucket}I',*buckets)+struct.pack(f'<{nchain}I',*chains)


def pack_ehdr(phoff:int,phnum:int)->bytes:
    ident=bytearray(16);ident[:4]=b'\x7fELF';ident[4]=2;ident[5]=1;ident[6]=1
    return bytes(ident)+struct.pack('<HHIQQQIHHHHHH',ET_DYN,EM_AARCH64,EV_CURRENT,
        0,phoff,0,0,64,56,phnum,64,0,0)


def pack_phdr(r:dict)->bytes:
    return struct.pack('<IIQQQQQQ',r['p_type'],r['p_flags'],r['p_offset'],r['p_vaddr'],
        r['p_paddr_inferred'],r['p_filesz'],r['p_memsz'],r['p_align_inferred'])


def find_cstr_offset(buf:bytes,text:str)->int:
    needle=text.encode()+b'\0'
    off=buf.find(needle)
    if off<0:
        raise ValueError(f'{text!r} not present in recovered dynstr')
    return off


def main()->int:
    ap=argparse.ArgumentParser()
    ap.add_argument('inner_raw',type=Path)
    ap.add_argument('output',type=Path)
    ap.add_argument('--metadata-dir',type=Path,required=True,
                    help='directory containing dynstr.bin/dynsym.bin/rela.*.bin/needed.txt')
    ap.add_argument('--phdr-manifest',type=Path,required=True,
                    help='manifest.json from recover_inner_phdrs.py')
    ap.add_argument('--aux-dir',type=Path,
                    help='optional output from recover_inner_aux_metadata.py; uses exact custom SysV hash and init/fini-array metadata')
    args=ap.parse_args()

    raw=args.inner_raw.read_bytes()
    m=json.loads(args.phdr_manifest.read_text(encoding='utf-8'))
    recs=[dict(r) for r in m['program_headers']]
    if len(recs)!=9:
        raise SystemExit(f'expected recovered 9 PHDRs, got {len(recs)}')

    md=args.metadata_dir
    dynstr=(md/'dynstr.bin').read_bytes()
    dynsym=(md/'dynsym.bin').read_bytes()
    rela_sym=(md/'rela.dyn.bin').read_bytes()
    rela_plt=(md/'rela.plt.bin').read_bytes()
    rela_rel=(md/'rela.relative.bin').read_bytes()
    needed=[x.strip() for x in (md/'needed.txt').read_text(encoding='utf-8').splitlines() if x.strip()]
    if len(needed)!=10:
        print(f'[!] warning: expected 10 dependencies, got {len(needed)}')

    rela_dyn=rela_rel+rela_sym
    relacount=len(rela_rel)//24
    if len(rela_dyn)%24 or len(rela_plt)%24:
        raise SystemExit('bad RELA byte length')

    names=parse_dynsym_names(dynsym,dynstr)
    aux=None
    if args.aux_dir:
        aux=json.loads((args.aux_dir/'aux_metadata.json').read_text(encoding='utf-8'))
        sysv_hash=(args.aux_dir/'hash.sysv.bin').read_bytes()
        if len(sysv_hash)!=aux['sysv_hash']['hash_blob_size']:
            raise SystemExit('exact SysV hash size does not match aux metadata')
    else:
        sysv_hash=build_sysv_hash(names)

    loads=[r for r in recs if r['p_type']==PT_LOAD]
    if len(loads)!=3:
        raise SystemExit(f'expected 3 PT_LOADs, got {len(loads)}')
    load3=loads[2]
    delta=load3['p_vaddr']-load3['p_offset']
    if delta!=0x8000:
        print(f'[!] warning: third LOAD vaddr-file delta is 0x{delta:x}, expected sample 0x8000')

    data=bytearray(raw)
    # Keep all recovered trailing bytes (compiler comments etc.) and place new metadata after them.
    cursor=align(len(data),16)
    data.extend(b'\0'*(cursor-len(data)))

    placements={}
    def add(name:str,blob:bytes,alignment:int=8):
        nonlocal cursor
        cursor=align(cursor,alignment)
        if len(data)<cursor:data.extend(b'\0'*(cursor-len(data)))
        off=cursor
        data.extend(blob);cursor+=len(blob)
        va=off+delta
        placements[name]={'file_offset':off,'va':va,'size':len(blob)}
        return va

    dynstr_va=add('dynstr',dynstr,1)
    dynsym_va=add('dynsym',dynsym,8)
    hash_va=add('hash',sysv_hash,4)
    rela_dyn_va=add('rela_dyn',rela_dyn,8)
    rela_plt_va=add('rela_plt',rela_plt,8)

    gotplt=None
    with (md/'plt.tsv').open(encoding='utf-8') as f:
        rows=list(csv.DictReader(f,delimiter='\t'))
        if rows:
            gotplt=min(int(r['target_offset'],16) for r in rows) - 3 * 8  # AArch64 .got.plt reserved qwords
    if gotplt is None:
        raise SystemExit('cannot determine DT_PLTGOT from plt.tsv')

    dyn=[]
    for lib in needed:
        dyn.append((DT_NEEDED,find_cstr_offset(dynstr,lib)))
    dyn += [
        (DT_HASH,hash_va),
        (DT_STRTAB,dynstr_va),
        (DT_SYMTAB,dynsym_va),
        (DT_STRSZ,len(dynstr)),
        (DT_SYMENT,24),
        (DT_RELA,rela_dyn_va),
        (DT_RELASZ,len(rela_dyn)),
        (DT_RELAENT,24),
        (DT_RELACOUNT,relacount),
        (DT_PLTGOT,gotplt),
        (DT_PLTRELSZ,len(rela_plt)),
        (DT_PLTREL,DT_RELA),
        (DT_JMPREL,rela_plt_va),
        (DT_SONAME,find_cstr_offset(dynstr,'libysmteam.so')),
    ]
    if aux:
        dyn += [
            (DT_FINI_ARRAY,aux['fini_array']['va']),
            (DT_FINI_ARRAYSZ,aux['fini_array']['byte_size']),
            (DT_INIT_ARRAY,aux['init_array']['va']),
            (DT_INIT_ARRAYSZ,aux['init_array']['byte_size']),
        ]
    dyn.append((DT_NULL,0))
    dynblob=b''.join(struct.pack('<QQ',tag,val) for tag,val in dyn)
    if len(dynblob)>DYNAMIC_SIZE:
        raise SystemExit(f'reconstructed dynamic table 0x{len(dynblob):x} exceeds PT_DYNAMIC 0x{DYNAMIC_SIZE:x}')
    if len(data)<DYNAMIC_FILE_OFF+DYNAMIC_SIZE:
        raise SystemExit('raw image does not contain recovered PT_DYNAMIC file range')
    data[DYNAMIC_FILE_OFF:DYNAMIC_FILE_OFF+DYNAMIC_SIZE]=dynblob+b'\0'*(DYNAMIC_SIZE-len(dynblob))

    # Extend only the third original PT_LOAD's file-backed extent to cover appended metadata.
    required_filesz=cursor-load3['p_offset']
    if required_filesz>load3['p_memsz']:
        raise SystemExit(
            f'metadata exceeds original third LOAD memory capacity: filesz 0x{required_filesz:x} > memsz 0x{load3["p_memsz"]:x}'
        )
    old_filesz=load3['p_filesz']
    load3['p_filesz']=required_filesz

    # Restore the original-shape ELF header and 9 PHDRs.
    phoff=m['elf_header_facts']['e_phoff']
    phnum=m['elf_header_facts']['e_phnum']
    phblob=b''.join(pack_phdr(r) for r in recs)
    if phoff+len(phblob)!=0x238:
        raise SystemExit('unexpected PHDR extent; refusing to overwrite PT_NOTE')
    note_before=bytes(data[0x238:0x2d0])
    data[:64]=pack_ehdr(phoff,phnum)
    data[phoff:phoff+len(phblob)]=phblob
    if bytes(data[0x238:0x2d0])!=note_before:
        raise SystemExit('PT_NOTE changed unexpectedly')

    args.output.write_bytes(data)

    manifest={
        'kind':'near-original-layout reconstruction',
        'original_phdr_shape':{'e_phoff':phoff,'e_phnum':phnum,'phdr_end':phoff+len(phblob)},
        'third_load':{
            'offset':load3['p_offset'],'vaddr':load3['p_vaddr'],'memsz':load3['p_memsz'],
            'original_filesz':old_filesz,'reconstructed_filesz':load3['p_filesz'],
            'file_to_va_delta':delta,
        },
        'dynamic':{'file_offset':DYNAMIC_FILE_OFF,'size':DYNAMIC_SIZE,'entries':len(dyn)},
        'placements':placements,
        'relocations':{
            'relative':len(rela_rel)//24,'symbol_rela':len(rela_sym)//24,
            'rela_dyn_total':len(rela_dyn)//24,'rela_plt':len(rela_plt)//24,
        },
        'needed':needed,
        'caveats':[
            'p_paddr and p_align are inferred because the compact protected PHDR records omit them',
            'the dynamic table and dynamic metadata placement are semantic reconstructions',
            'when --aux-dir is used, the SysV bucket/chain contents exactly match C8920; surviving shstrtab also encodes a .hash suffix alias, while original .gnu.hash bytes remain unrecovered',
            'the third PT_LOAD p_filesz is extended into its original BSS capacity to hold reconstructed metadata',
        ],
    }
    args.output.with_suffix(args.output.suffix+'.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')

    print(f'[+] wrote {args.output}')
    print(f'    original PHDRs     : {phnum}, e_phoff=0x{phoff:x}')
    print(f'    PT_DYNAMIC         : file=0x{DYNAMIC_FILE_OFF:x} size=0x{DYNAMIC_SIZE:x}')
    print(f'    third LOAD filesz  : 0x{old_filesz:x} -> 0x{load3["p_filesz"]:x} (memsz 0x{load3["p_memsz"]:x})')
    print(f'    DT_RELA entries    : {len(rela_dyn)//24} ({relacount} RELATIVE first)')
    print(f'    DT_JMPREL entries  : {len(rela_plt)//24}')
    for k,v in placements.items():
        print(f'    {k:<10}: off=0x{v["file_offset"]:x} va=0x{v["va"]:x} size=0x{v["size"]:x}')
    return 0

if __name__=='__main__':
    raise SystemExit(main())
