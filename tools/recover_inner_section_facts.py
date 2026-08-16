#!/usr/bin/env python3
"""Recover high-confidence section-layout facts from the reconstructed YSM inner file.

This does NOT pretend to decrypt the destroyed section-header entries.  Instead it
combines surviving non-alloc trailing sections, recovered PHDRs, EH-frame metadata,
and recovered relocation/constructor metadata to recover exact section boundaries
where the evidence is direct.
"""
from __future__ import annotations
import argparse, csv, json, struct
from pathlib import Path

ELF64_SHDR_SIZE=0x40
PT_LOAD=1; PT_DYNAMIC=2; PT_GNU_EH_FRAME=0x6474e550


def align(v,a): return (v+a-1)&~(a-1)

def parse_shstr(buf: bytes, start: int, end: int):
    out=[]; i=start
    while i<end:
        j=buf.find(b'\0',i,end)
        if j<0: break
        if j>i:
            try:s=buf[i:j].decode('ascii')
            except UnicodeDecodeError:s=''
            if s: out.append({'offset':i-start,'name':s})
        i=j+1
    return out

def suffix_aliases(shstr: bytes):
    out=[]
    for i,c in enumerate(shstr):
        if c==ord('.'):
            j=shstr.find(b'\0',i)
            if j>i:
                try:name=shstr[i:j].decode('ascii')
                except: continue
                out.append((i,name))
    return out

def parse_eh_frame_end(raw: bytes, start: int):
    off=start; entries=0
    while off+4<=len(raw):
        n=struct.unpack_from('<I',raw,off)[0]
        if n==0:
            return off+4,entries
        if n==0xffffffff:
            if off+12>len(raw): raise ValueError('truncated extended EH frame length')
            n64=struct.unpack_from('<Q',raw,off+4)[0]
            nxt=off+12+n64
        else:
            nxt=off+4+n
        if nxt<=off or nxt>len(raw):
            raise ValueError(f'invalid EH frame record at 0x{off:x}')
        entries+=1; off=nxt
    raise ValueError('no EH frame terminator')

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('inner_raw',type=Path)
    ap.add_argument('output_dir',type=Path)
    ap.add_argument('--phdr-manifest',type=Path,required=True)
    ap.add_argument('--metadata-dir',type=Path,required=True)
    ap.add_argument('--aux-dir',type=Path,required=True)
    args=ap.parse_args()
    raw=args.inner_raw.read_bytes()
    ph=json.loads(args.phdr_manifest.read_text())
    aux=json.loads((args.aux_dir/'aux_metadata.json').read_text())
    recs=ph['program_headers']
    loads=[r for r in recs if r['p_type']==PT_LOAD]
    dyn=next(r for r in recs if r['p_type']==PT_DYNAMIC)
    eh=next(r for r in recs if r['p_type']==PT_GNU_EH_FRAME)
    if len(loads)!=3: raise SystemExit('expected 3 LOADs')

    facts=[]
    def add(name,addr,off,size,kind='exact',note=''):
        facts.append(dict(name=name,addr=addr,offset=off,size=size,end_addr=addr+size if addr is not None else None,end_offset=off+size if off is not None else None,confidence=kind,note=note))

    # PT_NOTE-backed section.
    note=next(r for r in recs if r['p_type']==4)
    add('.note.android.ident',note['p_vaddr'],note['p_offset'],note['p_filesz'],note='exact PT_NOTE extent')

    # EH frame header directly names .eh_frame start via DW_EH_PE_pcrel|sdata4 (0x1b).
    eh_off=eh['p_offset']; hdr=raw[eh_off:eh_off+12]
    if hdr[:4] != bytes([1,0x1b,0x03,0x3b]):
        raise SystemExit(f'unexpected .eh_frame_hdr encoding {hdr[:4].hex()}')
    rel=struct.unpack_from('<i',raw,eh_off+4)[0]
    eh_frame_start=(eh['p_vaddr']+4+rel)
    fde_count=struct.unpack_from('<I',raw,eh_off+8)[0]
    if 12+fde_count*8 != eh['p_filesz']:
        raise SystemExit('EH frame header count does not match PT_GNU_EH_FRAME size')
    add('.eh_frame_hdr',eh['p_vaddr'],eh['p_offset'],eh['p_filesz'],note=f'header advertises {fde_count} FDE search-table entries')
    eh_frame_end,eh_records=parse_eh_frame_end(raw,eh_frame_start)
    add('.eh_frame',eh_frame_start,eh_frame_start,eh_frame_end-eh_frame_start,note=f'parsed {eh_records} CIE/FDE records + zero terminator')

    # PLT facts from recovered mapping.
    with (args.metadata_dir/'plt.tsv').open(encoding='utf-8') as f:
        plt=list(csv.DictReader(f,delimiter='\t'))
    first_regular=min(int(r['plt_address'],16) for r in plt)
    plt_start=first_regular-0x20
    plt_end=first_regular+len(plt)*0x10
    load1=loads[0]
    if plt_end != load1['p_vaddr']+load1['p_filesz']:
        raise SystemExit('PLT extent does not end at first LOAD boundary')
    # text starts at next 16-byte aligned location after parsed EH frame, observed BTI there.
    text_start=align(eh_frame_end,16)
    add('.text',text_start,text_start,plt_start-text_start,note='starts at first aligned code after .eh_frame; ends at PLT0')
    add('.plt',plt_start,plt_start,plt_end-plt_start,note=f'PLT0 0x20 + {len(plt)} regular 0x10-byte stubs')

    # Writable RELRO load.
    load2=loads[1]; d=load2['p_vaddr']-load2['p_offset']
    fini=aux['fini_array']; init=aux['init_array']
    fini_va=fini['va']; init_va=init['va']
    dyn_va=dyn['p_vaddr']; dyn_end=dyn_va+dyn['p_filesz']
    if fini_va+fini['byte_size'] != init_va or init_va+init['byte_size'] != dyn_va:
        raise SystemExit('fini/init/dynamic are not contiguous as expected')
    add('.data.rel.ro',load2['p_vaddr'],load2['p_offset'],fini_va-load2['p_vaddr'],note='from second LOAD start to exact .fini_array')
    add('.fini_array',fini_va,fini_va-d,fini['byte_size'],note='exact recovered constructor metadata')
    add('.init_array',init_va,init_va-d,init['byte_size'],note='exact recovered constructor metadata')
    add('.dynamic',dyn_va,dyn['p_offset'],dyn['p_filesz'],note='exact PT_DYNAMIC extent')

    # GOT / GOT.PLT. First GLOB_DAT target starts exactly at PT_DYNAMIC end.
    with (args.metadata_dir/'relocs.tsv').open(encoding='utf-8') as f:
        rels=list(csv.DictReader(f,delimiter='\t'))
    glob=[int(r['target_offset'],16) for r in rels if int(r['reloc_type'],16)==0x401]
    jumps=[int(r['target_offset'],16) for r in plt]
    got_start=min(glob)
    if got_start!=dyn_end: raise SystemExit('first GLOB_DAT does not equal dynamic end')
    first_jump=min(jumps)
    gotplt_start=first_jump-3*8  # AArch64 reserved .got.plt[0..2]
    load2_file_end_va=load2['p_vaddr']+load2['p_filesz']
    if load2_file_end_va != max(jumps)+8:
        raise SystemExit('last JUMP_SLOT does not end at second LOAD file-backed end')
    add('.got',got_start,got_start-d,gotplt_start-got_start,note='dynamic end to three reserved GOT.PLT qwords')
    add('.got.plt',gotplt_start,gotplt_start-d,load2_file_end_va-gotplt_start,note=f'3 reserved qwords + {len(jumps)} JUMP_SLOT qwords')
    relro_end=load2['p_vaddr']+load2['p_memsz']
    add('.relro_padding',load2_file_end_va,None,relro_end-load2_file_end_va,note='zero-fill tail of GNU_RELRO LOAD')

    # Third LOAD naturally splits into file-backed .data and zero-fill .bss.
    load3=loads[2]; delta3=load3['p_vaddr']-load3['p_offset']
    data_end=load3['p_vaddr']+load3['p_filesz']
    bss_end=load3['p_vaddr']+load3['p_memsz']
    add('.data',load3['p_vaddr'],load3['p_offset'],load3['p_filesz'],note='entire original third LOAD file-backed extent')
    add('.bss',data_end,None,bss_end-data_end,note='original third LOAD zero-fill extent')

    # Non-alloc trailer: .comment, .shstrtab, then destroyed section-header bytes.
    comment_off=load3['p_offset']+load3['p_filesz']
    marker=b'\0.init_array\0.fini_array\0.text\0.got\0.comment\0'
    shstr_off=raw.find(marker,comment_off)
    if shstr_off<0: raise SystemExit('cannot locate surviving shstrtab')
    # marker begins with the leading NUL of shstrtab.
    # Find the .data string and its final NUL; known table is then padded to 8.
    data_name=raw.find(b'.data\0',shstr_off)
    if data_name<0: raise SystemExit('cannot locate .data in shstrtab')
    shstr_end=data_name+len(b'.data\0')
    add('.comment',None,comment_off,shstr_off-comment_off,note='non-alloc compiler-identification strings after third LOAD')
    add('.shstrtab',None,shstr_off,shstr_end-shstr_off,note='surviving plaintext original section-name table')
    shoff=align(shstr_end,8)
    tail=len(raw)-shoff
    if tail%ELF64_SHDR_SIZE: raise SystemExit('trailing destroyed table not divisible by Elf64_Shdr size')
    shnum=tail//ELF64_SHDR_SIZE

    shstr=raw[shstr_off:shstr_end]
    full=[x['name'] for x in parse_shstr(raw,shstr_off,shstr_end)]
    aliases=dict(suffix_aliases(shstr))
    # Two suffix aliases explain the two section names not stored as standalone C strings.
    expected_aliases=[]
    for n in ('.plt','.hash'):
        loc=[off for off,name in aliases.items() if name==n]
        if loc: expected_aliases.append({'name':n,'name_offset':loc[0]})
    candidate_names=['']+full+[x['name'] for x in expected_aliases]

    out=args.output_dir; out.mkdir(parents=True,exist_ok=True)
    manifest={
      'raw_size':len(raw),
      'facts':facts,
      'section_header_tail':{
        'shstrtab_offset':shstr_off,'shstrtab_size':len(shstr),
        'aligned_candidate_e_shoff':shoff,'tail_size':tail,'elf64_shdr_size':ELF64_SHDR_SIZE,
        'candidate_e_shnum':shnum,
        'full_section_names':full,
        'suffix_alias_names':expected_aliases,
        'name_count_including_null_and_aliases':len(candidate_names),
        'structural_match':len(candidate_names)==shnum,
        'important_note':'tail bytes are scrambled/destroyed; individual original Elf64_Shdr fields and e_shstrndx are not recovered',
      },
      'corrections':{
        'gotplt_start':gotplt_start,
        'gotplt_reserved_qwords':3,
        'plt_is_real_section_name_via_suffix_offset': next((x['name_offset'] for x in expected_aliases if x['name']=='.plt'),None),
        'hash_is_real_section_name_via_suffix_offset': next((x['name_offset'] for x in expected_aliases if x['name']=='.hash'),None),
      },
    }
    (out/'section_facts.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    with (out/'sections.tsv').open('w',encoding='utf-8') as f:
        f.write('name\taddr\toffset\tsize\tconfidence\tnote\n')
        for r in facts:
            f.write(f"{r['name']}\t{'' if r['addr'] is None else hex(r['addr'])}\t{'' if r['offset'] is None else hex(r['offset'])}\t{hex(r['size'])}\t{r['confidence']}\t{r['note']}\n")
    print(f'[+] shstrtab   off=0x{shstr_off:x} size=0x{len(shstr):x}')
    print(f'[+] shdr tail  off=0x{shoff:x} size=0x{tail:x} -> {shnum} Elf64_Shdr slots')
    print(f'[+] names      {len(full)} full + {len(expected_aliases)} suffix aliases + NULL = {len(candidate_names)}')
    print(f'[+] match      names == shnum: {len(candidate_names)==shnum}')
    print(f'[+] .eh_frame  0x{eh_frame_start:x}..0x{eh_frame_end:x}; .text 0x{text_start:x}..0x{plt_start:x}; .plt 0x{plt_start:x}..0x{plt_end:x}')
    print(f'[+] .got       0x{got_start:x}..0x{gotplt_start:x}; .got.plt 0x{gotplt_start:x}..0x{load2_file_end_va:x}')
    print(f'[+] .data      0x{load3["p_vaddr"]:x}..0x{data_end:x}; .bss 0x{data_end:x}..0x{bss_end:x}')
    print(f'[+] wrote      {out}')
    return 0
if __name__=='__main__': raise SystemExit(main())
