#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, struct
from pathlib import Path

def align(v,a): return (v+a-1)&~(a-1)

def parse_verneed(raw,start,dynstr):
    p=start; entries=[]; max_end=start
    while True:
        vn_version,vn_cnt,vn_file,vn_aux,vn_next=struct.unpack_from('<HHIII',raw,p)
        aux=[]; ap=p+vn_aux
        for _ in range(vn_cnt):
            h,flags,other,name,nxt=struct.unpack_from('<IHHII',raw,ap)
            def cstr(off):
                e=dynstr.find(b'\0',off)
                return dynstr[off:e].decode('utf-8','replace') if 0<=off<len(dynstr) else '<bad>'
            aux.append(dict(offset=ap,hash=h,flags=flags,other=other,name_offset=name,name=cstr(name),next=nxt))
            max_end=max(max_end,ap+16)
            if nxt==0: break
            ap+=nxt
        def cstr(off):
            e=dynstr.find(b'\0',off)
            return dynstr[off:e].decode('utf-8','replace') if 0<=off<len(dynstr) else '<bad>'
        entries.append(dict(offset=p,version=vn_version,count=vn_cnt,file_offset=vn_file,file=cstr(vn_file),aux_offset=vn_aux,next=vn_next,aux=aux))
        max_end=max(max_end,p+16)
        if vn_next==0: break
        p+=vn_next
        if len(entries)>64: raise ValueError('bad verneed chain')
    return entries,max_end

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('inner_raw',type=Path)
    ap.add_argument('output_dir',type=Path)
    ap.add_argument('--metadata-dir',type=Path,required=True)
    ap.add_argument('--aux-dir',type=Path,required=True)
    args=ap.parse_args()
    raw=args.inner_raw.read_bytes(); md=args.metadata_dir
    dynsym=(md/'dynsym.bin').read_bytes(); dynstr=(md/'dynstr.bin').read_bytes()
    rela_sym=(md/'rela.dyn.bin').read_bytes(); rela_rel=(md/'rela.relative.bin').read_bytes(); rela_plt=(md/'rela.plt.bin').read_bytes()
    hsys=(args.aux_dir/'hash.sysv.bin').read_bytes()
    nsyms=len(dynsym)//24

    note_start=0x238; note_end=0x2d0
    dynsym_start=note_end; dynsym_end=dynsym_start+len(dynsym)
    versym_start=dynsym_end; versym_size=nsyms*2; versym_end=versym_start+versym_size
    verneed_start=align(versym_end,4)
    verneed,verneed_end=parse_verneed(raw,verneed_start,dynstr)
    gnuhash_start=align(verneed_end,8)
    nb,symoff,bloom_size,bloom_shift=struct.unpack_from('<IIII',raw,gnuhash_start)
    gnuhash_size=16+bloom_size*8+nb*4+(nsyms-symoff)*4
    gnuhash_end=gnuhash_start+gnuhash_size
    hash_start=gnuhash_end; hash_end=hash_start+len(hsys)
    dynstr_start=hash_end; dynstr_end=dynstr_start+len(dynstr)
    rela_dyn_start=align(dynstr_end,8); rela_dyn_size=len(rela_rel)+len(rela_sym); rela_dyn_end=rela_dyn_start+rela_dyn_size
    rela_plt_start=align(rela_dyn_end,8); rela_plt_end=rela_plt_start+len(rela_plt)
    gcc_start=rela_plt_end
    gcc_end=0xF5EB0
    rodata_start=gcc_end; rodata_end=0x1FFAFC

    if raw[versym_start:versym_start+2] != b'\0\0': raise SystemExit('bad versym start')
    vals=struct.unpack_from(f'<{nsyms}H',raw,versym_start)
    if max(vals)>0x7fff: raise SystemExit('implausible versym')
    if (nb,symoff,bloom_size,bloom_shift)!=(1625,336,2048,26):
        print('[!] GNU hash header differs:',nb,symoff,bloom_size,bloom_shift)
    hnb,hnc=struct.unpack_from('<II',raw,hash_start)
    if (hnb,hnc)!=(nsyms,nsyms): raise SystemExit(f'bad SysV hash header {(hnb,hnc)}')
    tail=b'libysmteam.so\0'
    if raw[dynstr_end-len(tail):dynstr_end] != tail: raise SystemExit('dynstr tail anchor mismatch')
    if raw[gcc_start] != 0xff: raise SystemExit(f'expected LSDA at 0x{gcc_start:x}')

    sections=[
      ('note.android.ident',note_start,note_end),('dynsym',dynsym_start,dynsym_end),('gnu.version',versym_start,versym_end),
      ('gnu.version_r',verneed_start,verneed_end),('gnu.hash',gnuhash_start,gnuhash_end),('hash',hash_start,hash_end),
      ('dynstr',dynstr_start,dynstr_end),('rela.dyn',rela_dyn_start,rela_dyn_end),('rela.plt',rela_plt_start,rela_plt_end),
      ('gcc_except_table',gcc_start,gcc_end),('rodata',rodata_start,rodata_end)]
    out=args.output_dir; out.mkdir(parents=True,exist_ok=True)
    manifest={
      'dynsym_count':nsyms,
      'gnu_hash_header':dict(nbucket=nb,symoffset=symoff,bloom_size=bloom_size,bloom_shift=bloom_shift),
      'verneed_entries':verneed,
      'sections':[dict(name='.'+n,start=a,end=b,size=b-a) for n,a,b in sections],
      'correction':'.gcc_except_table starts at 0xED3B0, immediately after .rela.plt; 0xED59C was only the minimum LSDA referenced by the earlier FDE walk.'
    }
    (out/'original_layout.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    with (out/'sections.tsv').open('w',encoding='utf-8') as f:
        f.write('name\tstart\tend\tsize\n')
        for n,a,b in sections:f.write(f'.{n}\t0x{a:x}\t0x{b:x}\t0x{b-a:x}\n')
    print('[+] exact/inferred original low-layout chain')
    for n,a,b in sections: print(f'    .{n:<18} 0x{a:06x}..0x{b:06x} size=0x{b-a:x}')
    print(f'[+] verneed entries: {len(verneed)}')
    print(f'[+] GNU hash: nbucket={nb} symoffset={symoff} bloom={bloom_size} shift={bloom_shift}')
    print(f'[+] .rela.dyn: {rela_dyn_size//24} entries; .rela.plt: {len(rela_plt)//24}')

if __name__=='__main__': main()
