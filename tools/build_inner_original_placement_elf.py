#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, struct
from pathlib import Path

ET_DYN=3; EM_AARCH64=183; EV_CURRENT=1
SHT_NULL=0; SHT_PROGBITS=1; SHT_STRTAB=3; SHT_RELA=4; SHT_HASH=5; SHT_DYNAMIC=6; SHT_NOTE=7; SHT_NOBITS=8; SHT_DYNSYM=11; SHT_INIT_ARRAY=14; SHT_FINI_ARRAY=15
SHT_GNU_HASH=0x6ffffff6; SHT_GNU_VERNEED=0x6ffffffe; SHT_GNU_VERSYM=0x6fffffff
SHF_WRITE=1; SHF_ALLOC=2; SHF_EXECINSTR=4; SHF_MERGE=0x10; SHF_STRINGS=0x20; SHF_INFO_LINK=0x40
DT_NULL=0; DT_NEEDED=1; DT_PLTRELSZ=2; DT_PLTGOT=3; DT_HASH=4; DT_STRTAB=5; DT_SYMTAB=6; DT_RELA=7; DT_RELASZ=8; DT_RELAENT=9; DT_STRSZ=10; DT_SYMENT=11; DT_SONAME=14
DT_PLTREL=20; DT_JMPREL=23; DT_INIT_ARRAY=25; DT_FINI_ARRAY=26; DT_INIT_ARRAYSZ=27; DT_FINI_ARRAYSZ=28
DT_GNU_HASH=0x6ffffef5; DT_VERSYM=0x6ffffff0; DT_RELACOUNT=0x6ffffff9; DT_VERNEED=0x6ffffffe; DT_VERNEEDNUM=0x6fffffff

def align(v,a): return (v+a-1)&~(a-1)
def cstr(buf,off):
    e=buf.find(b'\0',off); return buf[off:e]
def gnu_hash(name):
    h=5381
    for c in name: h=(h*33+c)&0xffffffff
    return h

def build_gnu_hash(dynsym,dynstr,nb,symoff,bloom_size,bloom_shift):
    n=len(dynsym)//24; bits=64
    bloom=[0]*bloom_size; buckets=[0]*nb; chains=[0]*(n-symoff); seen=set(); last=None
    for i in range(symoff,n):
        st_name=struct.unpack_from('<I',dynsym,i*24)[0]; name=cstr(dynstr,st_name); h=gnu_hash(name); b=h%nb
        if b!=last:
            if b in seen: raise ValueError('dynsym order is not GNU-hash bucket contiguous')
            seen.add(b); last=b
            if buckets[b]==0: buckets[b]=i
        word=(h//bits)%bloom_size; bloom[word]|=(1<<(h%bits))|(1<<((h>>bloom_shift)%bits)); chains[i-symoff]=h&0xfffffffe
    for i in range(symoff,n):
        h=gnu_hash(cstr(dynstr,struct.unpack_from('<I',dynsym,i*24)[0])); b=h%nb
        if i==n-1:
            chains[i-symoff]|=1
        else:
            h2=gnu_hash(cstr(dynstr,struct.unpack_from('<I',dynsym,(i+1)*24)[0]))
            if h2%nb!=b: chains[i-symoff]|=1
    return struct.pack('<IIII',nb,symoff,bloom_size,bloom_shift)+struct.pack(f'<{bloom_size}Q',*bloom)+struct.pack(f'<{nb}I',*buckets)+struct.pack(f'<{len(chains)}I',*chains)

def pack_ehdr(phoff,phnum,shoff,shnum,shstrndx):
    ident=bytearray(16); ident[:4]=b'\x7fELF'; ident[4]=2; ident[5]=1; ident[6]=1
    return bytes(ident)+struct.pack('<HHIQQQIHHHHHH',ET_DYN,EM_AARCH64,EV_CURRENT,0,phoff,shoff,0,64,56,phnum,64,shnum,shstrndx)
def pack_phdr(r):
    return struct.pack('<IIQQQQQQ',r['p_type'],r['p_flags'],r['p_offset'],r['p_vaddr'],r['p_paddr_inferred'],r['p_filesz'],r['p_memsz'],r['p_align_inferred'])
def pack_shdr(name,typ,flags,addr,off,size,link=0,info=0,alignv=1,entsize=0):
    return struct.pack('<IIQQQQIIQQ',name,typ,flags,addr,off,size,link,info,alignv,entsize)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('inner_raw',type=Path); ap.add_argument('output',type=Path)
    ap.add_argument('--metadata-dir',type=Path,required=True); ap.add_argument('--aux-dir',type=Path,required=True)
    ap.add_argument('--phdr-manifest',type=Path,required=True); ap.add_argument('--layout-manifest',type=Path,required=True)
    args=ap.parse_args()
    raw=bytearray(args.inner_raw.read_bytes()); md=args.metadata_dir
    dynsym=(md/'dynsym.bin').read_bytes(); dynstr=(md/'dynstr.bin').read_bytes(); rela_sym=(md/'rela.dyn.bin').read_bytes(); rela_rel=(md/'rela.relative.bin').read_bytes(); rela_plt=(md/'rela.plt.bin').read_bytes()
    needed=[x.strip() for x in (md/'needed.txt').read_text().splitlines() if x.strip()]
    hsys=(args.aux_dir/'hash.sysv.bin').read_bytes(); aux=json.loads((args.aux_dir/'aux_metadata.json').read_text())
    ph=json.loads(args.phdr_manifest.read_text()); layout=json.loads(args.layout_manifest.read_text()); sec={x['name']:x for x in layout['sections']}
    gh=layout['gnu_hash_header']; ghash=build_gnu_hash(dynsym,dynstr,gh['nbucket'],gh['symoffset'],gh['bloom_size'],gh['bloom_shift']); rela_dyn=rela_rel+rela_sym
    replacements={'.dynsym':dynsym,'.gnu.hash':ghash,'.hash':hsys,'.dynstr':dynstr,'.rela.dyn':rela_dyn,'.rela.plt':rela_plt}
    for name,blob in replacements.items():
        s=sec[name]
        if len(blob)!=s['size']: raise SystemExit(f'{name} size mismatch')
        raw[s['start']:s['end']]=blob
    def doff(s):
        p=dynstr.find(s.encode()+b'\0')
        if p<0: raise SystemExit('missing dynstr '+s)
        return p
    dynamic=[]
    for lib in needed: dynamic.append((DT_NEEDED,doff(lib)))
    dynamic += [(DT_SONAME,doff('libysmteam.so')),(DT_HASH,sec['.hash']['start']),(DT_GNU_HASH,sec['.gnu.hash']['start']),(DT_STRTAB,sec['.dynstr']['start']),(DT_STRSZ,len(dynstr)),(DT_SYMTAB,sec['.dynsym']['start']),(DT_SYMENT,24),(DT_VERSYM,sec['.gnu.version']['start']),(DT_VERNEED,sec['.gnu.version_r']['start']),(DT_VERNEEDNUM,len(layout['verneed_entries'])),(DT_RELA,sec['.rela.dyn']['start']),(DT_RELASZ,len(rela_dyn)),(DT_RELAENT,24),(DT_RELACOUNT,len(rela_rel)//24),(DT_PLTGOT,0x50A6B8),(DT_PLTRELSZ,len(rela_plt)),(DT_PLTREL,DT_RELA),(DT_JMPREL,sec['.rela.plt']['start']),(DT_FINI_ARRAY,aux['fini_array']['va']),(DT_FINI_ARRAYSZ,aux['fini_array']['byte_size']),(DT_INIT_ARRAY,aux['init_array']['va']),(DT_INIT_ARRAYSZ,aux['init_array']['byte_size']),(DT_NULL,0)]
    dynrec=next(x for x in ph['program_headers'] if x['p_type']==2); dynblob=b''.join(struct.pack('<qQ',t,v) for t,v in dynamic)
    if len(dynblob)>dynrec['p_filesz']: raise SystemExit('dynamic too large')
    raw[dynrec['p_offset']:dynrec['p_offset']+dynrec['p_filesz']]=dynblob+b'\0'*(dynrec['p_filesz']-len(dynblob))

    phoff=ph['elf_header_facts']['e_phoff']; phnum=ph['elf_header_facts']['e_phnum']; phblob=b''.join(pack_phdr(r) for r in ph['program_headers'])
    shstr={'start':0x52F8AA,'end':0x52F9AA,'size':0x100}; shstr_bytes=bytes(raw[shstr['start']:shstr['end']]); shoff=align(shstr['end'],8)
    names=['','.note.android.ident','.dynsym','.gnu.version','.gnu.version_r','.gnu.hash','.hash','.dynstr','.rela.dyn','.rela.plt','.gcc_except_table','.rodata','.eh_frame_hdr','.eh_frame','.text','.plt','.data.rel.ro','.fini_array','.init_array','.dynamic','.got','.got.plt','.relro_padding','.data','.bss','.comment','.shstrtab']
    noff={'':0}
    for name in names[1:]:
        p=shstr_bytes.find(name.encode()+b'\0')
        if p<0: raise SystemExit('section name missing '+name)
        noff[name]=p
    idx={n:i for i,n in enumerate(names)}
    later={'.gcc_except_table':(0xed3b0,0xed3b0,0x8b00),'.rodata':(0xf5eb0,0xf5eb0,0x109c4c),'.eh_frame_hdr':(0x1ffafc,0x1ffafc,0x12af4),'.eh_frame':(0x2125f0,0x2125f0,0x4bce4),'.text':(0x25e2e0,0x25e2e0,0x278530),'.plt':(0x4d6810,0x4d6810,0xc1b0),'.data.rel.ro':(0x4e69c0,0x4e29c0,0x22b70),'.fini_array':(0x509530,0x505530,0x10),'.init_array':(0x509540,0x505540,0x30),'.dynamic':(0x509570,0x505570,0x230),'.got':(0x5097a0,0x5057a0,0xf18),'.got.plt':(0x50a6b8,0x5066b8,0x60e0),'.relro_padding':(0x510798,0x50c798,0x868),'.data':(0x5147a0,0x50c7a0,0x22dc0),'.bss':(0x537560,0x52f560,0x10b431),'.comment':(0,0x52f560,0x34a),'.shstrtab':(0,shstr['start'],shstr['size'])}
    sh=[pack_shdr(0,SHT_NULL,0,0,0,0)]
    lowtypes={'.note.android.ident':(SHT_NOTE,SHF_ALLOC,4,0),'.dynsym':(SHT_DYNSYM,SHF_ALLOC,8,24),'.gnu.version':(SHT_GNU_VERSYM,SHF_ALLOC,2,2),'.gnu.version_r':(SHT_GNU_VERNEED,SHF_ALLOC,4,0),'.gnu.hash':(SHT_GNU_HASH,SHF_ALLOC,8,0),'.hash':(SHT_HASH,SHF_ALLOC,4,4),'.dynstr':(SHT_STRTAB,SHF_ALLOC,1,0),'.rela.dyn':(SHT_RELA,SHF_ALLOC,8,24),'.rela.plt':(SHT_RELA,SHF_ALLOC|SHF_INFO_LINK,8,24)}
    for name in names[1:10]:
        s=sec[name]; typ,flags,al,en=lowtypes[name]; link=info=0
        if name=='.dynsym': link=idx['.dynstr']; info=1
        elif name in ('.gnu.hash','.hash','.rela.dyn','.rela.plt'): link=idx['.dynsym']
        elif name=='.gnu.version': link=idx['.dynsym']
        elif name=='.gnu.version_r': link=idx['.dynstr']; info=len(layout['verneed_entries'])
        if name=='.rela.plt': info=idx['.got.plt']
        sh.append(pack_shdr(noff[name],typ,flags,s['start'],s['start'],s['size'],link,info,al,en))
    specs={'.gcc_except_table':(SHT_PROGBITS,SHF_ALLOC,4,0,0,0),'.rodata':(SHT_PROGBITS,SHF_ALLOC,16,0,0,0),'.eh_frame_hdr':(SHT_PROGBITS,SHF_ALLOC,4,0,0,0),'.eh_frame':(SHT_PROGBITS,SHF_ALLOC,8,0,0,0),'.text':(SHT_PROGBITS,SHF_ALLOC|SHF_EXECINSTR,16,0,0,0),'.plt':(SHT_PROGBITS,SHF_ALLOC|SHF_EXECINSTR,16,16,0,0),'.data.rel.ro':(SHT_PROGBITS,SHF_ALLOC|SHF_WRITE,8,0,0,0),'.fini_array':(SHT_FINI_ARRAY,SHF_ALLOC|SHF_WRITE,8,8,0,0),'.init_array':(SHT_INIT_ARRAY,SHF_ALLOC|SHF_WRITE,8,8,0,0),'.dynamic':(SHT_DYNAMIC,SHF_ALLOC|SHF_WRITE,8,16,idx['.dynstr'],0),'.got':(SHT_PROGBITS,SHF_ALLOC|SHF_WRITE,8,8,0,0),'.got.plt':(SHT_PROGBITS,SHF_ALLOC|SHF_WRITE,8,8,0,0),'.relro_padding':(SHT_NOBITS,SHF_ALLOC|SHF_WRITE,1,0,0,0),'.data':(SHT_PROGBITS,SHF_ALLOC|SHF_WRITE,16,0,0,0),'.bss':(SHT_NOBITS,SHF_ALLOC|SHF_WRITE,16,0,0,0),'.comment':(SHT_PROGBITS,SHF_MERGE|SHF_STRINGS,1,1,0,0),'.shstrtab':(SHT_STRTAB,0,1,0,0,0)}
    for name in names[10:]:
        addr,off,size=later[name]; typ,flags,al,en,link,info=specs[name]; sh.append(pack_shdr(noff[name],typ,flags,addr,off,size,link,info,al,en))
    shblob=b''.join(sh)
    if len(shblob)!=0x6c0 or shoff+len(shblob)!=len(raw): raise SystemExit('section-header extent mismatch')
    raw[:64]=pack_ehdr(phoff,phnum,shoff,len(names),idx['.shstrtab']); raw[phoff:phoff+len(phblob)]=phblob; raw[shoff:]=shblob
    args.output.write_bytes(raw)
    args.output.with_suffix(args.output.suffix+'.json').write_text(json.dumps({'kind':'original-placement semantic reconstruction','size':len(raw),'e_shoff':shoff,'e_shnum':27,'e_shstrndx':idx['.shstrtab'],'dynamic_entries':len(dynamic),'gnu_hash_header':gh},indent=2))
    print('[+] wrote',args.output)
    print(f'    size remains      : 0x{len(raw):x}')
    print(f'    e_shoff/e_shnum   : 0x{shoff:x} / {len(names)}')
    print(f'    dynsym/dynstr     : 0x{sec[".dynsym"]["start"]:x} / 0x{sec[".dynstr"]["start"]:x}')
    print(f'    GNU hash / SysV   : 0x{sec[".gnu.hash"]["start"]:x} / 0x{sec[".hash"]["start"]:x}')
    print(f'    RELA dyn/plt      : 0x{sec[".rela.dyn"]["start"]:x} / 0x{sec[".rela.plt"]["start"]:x}')

if __name__=='__main__': main()
