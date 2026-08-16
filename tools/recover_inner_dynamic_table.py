#!/usr/bin/env python3
"""Reconstruct the mapped sample's 35-entry LLD-shaped Elf64_Dyn table."""
from __future__ import annotations
import argparse, json, struct
from pathlib import Path

DT_NULL=0; DT_NEEDED=1; DT_PLTRELSZ=2; DT_PLTGOT=3; DT_HASH=4; DT_STRTAB=5; DT_SYMTAB=6
DT_RELA=7; DT_RELASZ=8; DT_RELAENT=9; DT_STRSZ=10; DT_SYMENT=11; DT_SONAME=14; DT_PLTREL=20; DT_JMPREL=23
DT_INIT_ARRAY=25; DT_FINI_ARRAY=26; DT_INIT_ARRAYSZ=27; DT_FINI_ARRAYSZ=28; DT_FLAGS=30
DT_GNU_HASH=0x6ffffef5; DT_VERSYM=0x6ffffff0; DT_FLAGS_1=0x6ffffffb; DT_RELACOUNT=0x6ffffff9
DT_VERNEED=0x6ffffffe; DT_VERNEEDNUM=0x6fffffff
DF_BIND_NOW=0x8; DF_1_NOW=0x1
PT_DYNAMIC_FILE=0x505570; PT_DYNAMIC_SIZE=0x230
TAG_NAMES={v:k for k,v in globals().copy().items() if k.startswith('DT_') and isinstance(v,int)}

def doff(buf: bytes, text: str) -> int:
    p=buf.find(text.encode()+b'\0')
    if p<0: raise ValueError(f'missing dynstr string {text!r}')
    return p

def main() -> int:
    ap=argparse.ArgumentParser()
    ap.add_argument('inner_raw',type=Path)
    ap.add_argument('output_dir',type=Path)
    ap.add_argument('--metadata-dir',type=Path,required=True)
    ap.add_argument('--aux-dir',type=Path,required=True)
    ap.add_argument('--layout-manifest',type=Path,required=True)
    a=ap.parse_args()
    raw=a.inner_raw.read_bytes(); md=a.metadata_dir
    dynstr=(md/'dynstr.bin').read_bytes(); rela_rel=(md/'rela.relative.bin').read_bytes(); rela_sym=(md/'rela.dyn.bin').read_bytes(); rela_plt=(md/'rela.plt.bin').read_bytes()
    needed=[x.strip() for x in (md/'needed.txt').read_text().splitlines() if x.strip()]
    aux=json.loads((a.aux_dir/'aux_metadata.json').read_text()); layout=json.loads(a.layout_manifest.read_text())
    sec={x['name']:x for x in layout['sections']}
    if len(needed)!=10: raise SystemExit(f'expected 10 dependencies, got {len(needed)}')
    if len(raw)<PT_DYNAMIC_FILE+PT_DYNAMIC_SIZE: raise SystemExit('inner too small')
    rawdyn=raw[PT_DYNAMIC_FILE:PT_DYNAMIC_FILE+PT_DYNAMIC_SIZE]
    entries=[]
    entries += [(DT_NEEDED,doff(dynstr,x)) for x in needed]
    entries += [
        (DT_SONAME,doff(dynstr,'libysmteam.so')),
        (DT_FLAGS,DF_BIND_NOW),(DT_FLAGS_1,DF_1_NOW),
        (DT_RELA,sec['.rela.dyn']['start']),(DT_RELASZ,len(rela_rel)+len(rela_sym)),(DT_RELAENT,24),(DT_RELACOUNT,len(rela_rel)//24),
        (DT_JMPREL,sec['.rela.plt']['start']),(DT_PLTRELSZ,len(rela_plt)),(DT_PLTGOT,0x50A6B8),(DT_PLTREL,DT_RELA),
        (DT_SYMTAB,sec['.dynsym']['start']),(DT_SYMENT,24),(DT_STRTAB,sec['.dynstr']['start']),(DT_STRSZ,len(dynstr)),
        (DT_GNU_HASH,sec['.gnu.hash']['start']),(DT_HASH,sec['.hash']['start']),
        (DT_INIT_ARRAY,aux['init_array']['va']),(DT_INIT_ARRAYSZ,aux['init_array']['byte_size']),
        (DT_FINI_ARRAY,aux['fini_array']['va']),(DT_FINI_ARRAYSZ,aux['fini_array']['byte_size']),
        (DT_VERSYM,sec['.gnu.version']['start']),(DT_VERNEED,sec['.gnu.version_r']['start']),(DT_VERNEEDNUM,len(layout['verneed_entries'])),
        (DT_NULL,0),
    ]
    if len(entries)!=35: raise SystemExit(f'entry count {len(entries)} != 35')
    blob=b''.join(struct.pack('<qQ',t,v) for t,v in entries)
    if len(blob)!=PT_DYNAMIC_SIZE: raise SystemExit('dynamic blob does not exactly fill PT_DYNAMIC')
    a.output_dir.mkdir(parents=True,exist_ok=True)
    (a.output_dir/'dynamic.bin').write_bytes(blob)
    with (a.output_dir/'dynamic.tsv').open('w') as f:
        f.write('index\ttag\tname\tvalue\n')
        for i,(t,v) in enumerate(entries): f.write(f'{i}\t0x{t:x}\t{TAG_NAMES.get(t,"UNKNOWN")}\t0x{v:x}\n')
    (a.output_dir/'dynamic.json').write_text(json.dumps({
        'pt_dynamic':{'file_offset':PT_DYNAMIC_FILE,'size':PT_DYNAMIC_SIZE,'entry_size':16,'entry_count':35},
        'raw_pt_dynamic_all_7bit':all(x<0x80 for x in rawdyn),'raw_pt_dynamic_max_byte':max(rawdyn),
        'needed_count':10,'bind_now':{'DT_FLAGS':DF_BIND_NOW,'DT_FLAGS_1':DF_1_NOW},
        'ordering':'canonical NDK/LLD-shaped reconstruction; stripped raw bytes do not directly preserve tag order'},indent=2))
    print(f'[+] PT_DYNAMIC raw all-7bit: {all(x<0x80 for x in rawdyn)}, max=0x{max(rawdyn):02x}')
    print(f'[+] reconstructed entries: {len(entries)} -> 0x{len(blob):x} bytes (exact PT_DYNAMIC fill)')
    print('[+] wrote',a.output_dir)
    return 0
if __name__=='__main__': raise SystemExit(main())
