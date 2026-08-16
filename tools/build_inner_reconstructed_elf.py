#!/usr/bin/env python3
import argparse
import csv
import struct
from pathlib import Path

ET_DYN=3; EM_AARCH64=183; EV_CURRENT=1
PT_LOAD=1; PT_DYNAMIC=2
PF_X=1; PF_W=2; PF_R=4
SHT_NULL=0; SHT_PROGBITS=1; SHT_SYMTAB=2; SHT_STRTAB=3; SHT_RELA=4; SHT_HASH=5; SHT_DYNAMIC=6; SHT_NOBITS=8; SHT_DYNSYM=11
SHF_WRITE=1; SHF_ALLOC=2; SHF_EXECINSTR=4
STB_GLOBAL=1; STT_NOTYPE=0; STT_OBJECT=1; STT_FUNC=2

DT_NULL=0; DT_NEEDED=1; DT_PLTRELSZ=2; DT_PLTGOT=3; DT_HASH=4; DT_STRTAB=5; DT_SYMTAB=6
DT_RELA=7; DT_RELASZ=8; DT_RELAENT=9; DT_STRSZ=10; DT_SYMENT=11; DT_SONAME=14
DT_PLTREL=20; DT_JMPREL=23; DT_RELACOUNT=0x6ffffff9

PAYLOAD_OFF=0x1000
RO_END=0x25E2E0; TEXT_END=0x4D6810; PLT_END=0x4E29C0
GOT_START=0x5097A0; GOTPLT_START=0x50A6D0; GOTPLT_END=0x510798
FILE_END=0x530070; MEM_END=0x643000
META_VA=0x650000

KNOWN_SYMBOLS=[
 ('inner_code_start',0x25E2E0,0,STT_FUNC,'text'),
 ('menu_renderer',0x27CAEC,0,STT_FUNC,'text'),
 ('key_input_callsite',0x27CFFC,0,STT_NOTYPE,'text'),
 ('auto_login_worker',0x2948DC,0,STT_FUNC,'text'),
 ('login_worker',0x29527C,0,STT_FUNC,'text'),
 ('auth_core',0x298B94,0,STT_FUNC,'text'),
 ('plt0',0x4D6810,0x20,STT_FUNC,'plt'),
 ('plt_entries',0x4D6830,PLT_END-0x4D6830,STT_NOTYPE,'plt'),
 ('login_status',0x537730,0,STT_OBJECT,'bss'),
 ('save_key_flag',0x5390F8,1,STT_OBJECT,'bss'),
 ('auto_login_flag',0x5390F9,1,STT_OBJECT,'bss'),
 ('saved_key',0x539100,0,STT_OBJECT,'bss'),
 ('key_buffer',0x53912C,0x100,STT_OBJECT,'bss'),
 ('auth_busy',0x5392A0,1,STT_OBJECT,'bss'),
]

def align(v,a): return (v+a-1)&~(a-1)

def pack_ehdr(phoff,shoff,phnum,shnum,shstrndx):
    ident=bytearray(16); ident[:4]=b'\x7fELF'; ident[4]=2; ident[5]=1; ident[6]=1
    return bytes(ident)+struct.pack('<HHIQQQIHHHHHH',ET_DYN,EM_AARCH64,EV_CURRENT,0,phoff,shoff,0,64,56,phnum,64,shnum,shstrndx)

def pack_phdr(ptype,flags,off,va,filesz,memsz,alignv=0x1000):
    return struct.pack('<IIQQQQQQ',ptype,flags,off,va,va,filesz,memsz,alignv)

def pack_shdr(name,typ,flags,addr,off,size,link=0,info=0,addralign=1,entsize=0):
    return struct.pack('<IIQQQQIIQQ',name,typ,flags,addr,off,size,link,info,addralign,entsize)

def section_key(value):
    if 0<=value<RO_END:return 'blob'
    if RO_END<=value<TEXT_END:return 'text'
    if TEXT_END<=value<PLT_END:return 'plt'
    if PLT_END<=value<GOT_START:return 'data'
    if GOT_START<=value<GOTPLT_START:return 'got'
    if GOTPLT_START<=value<GOTPLT_END:return 'gotplt'
    if GOTPLT_END<=value<FILE_END:return 'data_tail'
    if FILE_END<=value<MEM_END:return 'bss'
    return None

def load_metadata(d):
    required=['dynstr.bin','dynsym.bin','rela.dyn.bin','rela.plt.bin','dynsym.tsv','plt.tsv']
    for n in required:
        if not (d/n).exists(): raise SystemExit(f'missing metadata file: {d/n}')
    rela_symbolic=(d/'rela.dyn.bin').read_bytes()
    rela_relative=(d/'rela.relative.bin').read_bytes() if (d/'rela.relative.bin').exists() else b''
    needed=None
    if (d/'needed.txt').exists():
        needed=[x.strip() for x in (d/'needed.txt').read_text(encoding='utf-8').splitlines() if x.strip()]
    return ((d/'dynstr.bin').read_bytes(),(d/'dynsym.bin').read_bytes(),rela_relative+rela_symbolic,(d/'rela.plt.bin').read_bytes(),
      list(csv.DictReader((d/'dynsym.tsv').open(encoding='utf-8'),delimiter='\t')),
      list(csv.DictReader((d/'plt.tsv').open(encoding='utf-8'),delimiter='\t')),
      len(rela_relative)//24, needed)

def iter_cstrings(buf):
    pos=0
    while pos<len(buf):
        end=buf.find(b'\0',pos)
        if end<0:end=len(buf)
        if end>pos:
            try:s=buf[pos:end].decode('utf-8')
            except UnicodeDecodeError:s=''
            if s: yield pos,s
        pos=end+1

def sysv_hash(name:bytes):
    h=0
    for c in name:
        h=(h<<4)+c
        g=h&0xF0000000
        if g:h^=g>>24
        h&=~g
    return h & 0xffffffff

def build_sysv_hash(dynsym:bytes,dynstr:bytes):
    nchain=len(dynsym)//24
    nbucket=max(1,nchain//4)
    buckets=[0]*nbucket; chains=[0]*nchain
    for i in range(1,nchain):
        st_name=struct.unpack_from('<I',dynsym,i*24)[0]
        if st_name>=len(dynstr):continue
        end=dynstr.find(b'\0',st_name)
        if end<0:end=len(dynstr)
        name=dynstr[st_name:end]
        if not name:continue
        b=sysv_hash(name)%nbucket
        if buckets[b]==0:buckets[b]=i
        else:
            j=buckets[b]
            while chains[j]!=0:j=chains[j]
            chains[j]=i
    return struct.pack('<II',nbucket,nchain)+struct.pack('<%dI'%nbucket,*buckets)+struct.pack('<%dI'%nchain,*chains)

def find_dynstr_offset(dynstr,name):
    needle=name.encode()+b'\0'; p=dynstr.find(needle)
    if p<0: raise SystemExit(f'missing dynstr string: {name}')
    return p

def main():
    ap=argparse.ArgumentParser(description='Build a synthetic but loader-shaped AArch64 ELF from recovered YSM inner image + metadata.')
    ap.add_argument('input'); ap.add_argument('output'); ap.add_argument('--metadata-dir',required=True)
    args=ap.parse_args(); payload=Path(args.input).read_bytes(); md=Path(args.metadata_dir)
    if len(payload)!=FILE_END: print(f'[!] warning expected inner size 0x{FILE_END:x}, got 0x{len(payload):x}')
    dynstr,raw_dynsym,rela_dyn,rela_plt,dynrows,pltrows,relative_count,recovered_needed=load_metadata(md)
    if len(raw_dynsym)%24: raise SystemExit('bad dynsym size')

    section_names=['','blob','text','plt','data','got','gotplt','data_tail','bss','dynstr','dynsym','hash','rela_dyn','rela_plt','dynamic','strtab','symtab','shstrtab']
    dotted={k:('.'+k.replace('_','.') if k else '') for k in section_names}; dotted['gotplt']='.got.plt'; dotted['data_tail']='.data.tail'; dotted['rela_dyn']='.rela.dyn'; dotted['rela_plt']='.rela.plt'
    shstr=bytearray(b'\0'); nameoff={'':0}
    for k in section_names[1:]: nameoff[k]=len(shstr); shstr+=dotted[k].encode()+b'\0'
    sidx={k:i for i,k in enumerate(section_names)}

    dynsym=bytearray(raw_dynsym)
    for i,row in enumerate(dynrows):
        if i*24+24>len(dynsym):break
        value=int(row['value'],16); old=int(row['shndx']); new=0
        if old!=0 and value!=0:
            k=section_key(value); new=sidx[k] if k else 0
        struct.pack_into('<H',dynsym,i*24+6,new)
    dynsym=bytes(dynsym)
    hash_blob=build_sysv_hash(dynsym,dynstr)

    so_strings=[(off,s) for off,s in iter_cstrings(dynstr) if s.startswith('lib') and s.endswith('.so')]
    soname='libysmteam.so' if any(s=='libysmteam.so' for _,s in so_strings) else (so_strings[-1][1] if so_strings else None)
    needed=recovered_needed if recovered_needed is not None else [s for _,s in so_strings if s!=soname]

    strtab=bytearray(b'\0'); string_offsets={}
    def intern(n):
        if n not in string_offsets:
            string_offsets[n]=len(strtab); strtab.extend(n.encode(errors='replace')+b'\0')
        return string_offsets[n]
    symbols=[b'\0'*24]
    for name,value,size,typ,key in KNOWN_SYMBOLS:
        symbols.append(struct.pack('<IBBHQQ',intern(name),(STB_GLOBAL<<4)|typ,0,sidx[key],value,size))
    for row in pltrows:
        n=row['symbol_name']; value=int(row['plt_address'],16)
        if n: symbols.append(struct.pack('<IBBHQQ',intern('plt.'+n),(STB_GLOBAL<<4)|STT_FUNC,0,sidx['plt'],value,0x10))
    symtab=b''.join(symbols)

    data=bytearray(PAYLOAD_OFF); data+=payload
    meta_off=align(len(data),0x1000); data.extend(b'\0'*(meta_off-len(data)))
    def append_alloc(blob,alignment=8):
        off=align(len(data),alignment); data.extend(b'\0'*(off-len(data))); va=META_VA+(off-meta_off); data.extend(blob); return off,va
    dynstr_off,dynstr_va=append_alloc(dynstr,1)
    dynsym_off,dynsym_va=append_alloc(dynsym,8)
    hash_off,hash_va=append_alloc(hash_blob,8)
    rela_dyn_off,rela_dyn_va=append_alloc(rela_dyn,8)
    rela_plt_off,rela_plt_va=append_alloc(rela_plt,8)

    dynamic_entries=[]
    for n in needed: dynamic_entries.append((DT_NEEDED,find_dynstr_offset(dynstr,n)))
    dynamic_entries += [(DT_HASH,hash_va),(DT_STRTAB,dynstr_va),(DT_SYMTAB,dynsym_va),(DT_STRSZ,len(dynstr)),(DT_SYMENT,24),
      (DT_RELA,rela_dyn_va),(DT_RELASZ,len(rela_dyn)),(DT_RELAENT,24),(DT_PLTGOT,GOTPLT_START),(DT_PLTRELSZ,len(rela_plt)),(DT_PLTREL,DT_RELA),(DT_JMPREL,rela_plt_va)]
    if relative_count: dynamic_entries.append((DT_RELACOUNT,relative_count))
    if soname: dynamic_entries.append((DT_SONAME,find_dynstr_offset(dynstr,soname)))
    dynamic_entries.append((DT_NULL,0))
    dynamic_blob=b''.join(struct.pack('<qQ',tag,val) for tag,val in dynamic_entries)
    dynamic_off,dynamic_va=append_alloc(dynamic_blob,8)
    meta_end=align(len(data),0x1000); data.extend(b'\0'*(meta_end-len(data)))

    def append_nonalloc(blob,alignment=8):
        off=align(len(data),alignment); data.extend(b'\0'*(off-len(data))); data.extend(blob); return off
    strtab_off=append_nonalloc(bytes(strtab),1); symtab_off=append_nonalloc(symtab,8); shstr_off=append_nonalloc(bytes(shstr),1)
    shoff=align(len(data),8); data.extend(b'\0'*(shoff-len(data)))

    sections=[pack_shdr(0,SHT_NULL,0,0,0,0)]
    def add_prog(key,start,end,flags,alignment=16,entsize=0): sections.append(pack_shdr(nameoff[key],SHT_PROGBITS,flags,start,PAYLOAD_OFF+start,end-start,addralign=alignment,entsize=entsize))
    add_prog('blob',0,RO_END,SHF_ALLOC); add_prog('text',RO_END,TEXT_END,SHF_ALLOC|SHF_EXECINSTR); add_prog('plt',TEXT_END,PLT_END,SHF_ALLOC|SHF_EXECINSTR,16,16)
    add_prog('data',PLT_END,GOT_START,SHF_ALLOC|SHF_WRITE); add_prog('got',GOT_START,GOTPLT_START,SHF_ALLOC|SHF_WRITE,8,8); add_prog('gotplt',GOTPLT_START,GOTPLT_END,SHF_ALLOC|SHF_WRITE,8,8); add_prog('data_tail',GOTPLT_END,FILE_END,SHF_ALLOC|SHF_WRITE)
    sections.append(pack_shdr(nameoff['bss'],SHT_NOBITS,SHF_ALLOC|SHF_WRITE,FILE_END,PAYLOAD_OFF+FILE_END,MEM_END-FILE_END,addralign=16))
    sections.append(pack_shdr(nameoff['dynstr'],SHT_STRTAB,SHF_ALLOC,dynstr_va,dynstr_off,len(dynstr),addralign=1))
    sections.append(pack_shdr(nameoff['dynsym'],SHT_DYNSYM,SHF_ALLOC,dynsym_va,dynsym_off,len(dynsym),link=sidx['dynstr'],info=1,addralign=8,entsize=24))
    sections.append(pack_shdr(nameoff['hash'],SHT_HASH,SHF_ALLOC,hash_va,hash_off,len(hash_blob),link=sidx['dynsym'],addralign=4,entsize=4))
    sections.append(pack_shdr(nameoff['rela_dyn'],SHT_RELA,SHF_ALLOC,rela_dyn_va,rela_dyn_off,len(rela_dyn),link=sidx['dynsym'],addralign=8,entsize=24))
    sections.append(pack_shdr(nameoff['rela_plt'],SHT_RELA,SHF_ALLOC,rela_plt_va,rela_plt_off,len(rela_plt),link=sidx['dynsym'],info=sidx['gotplt'],addralign=8,entsize=24))
    sections.append(pack_shdr(nameoff['dynamic'],SHT_DYNAMIC,SHF_ALLOC|SHF_WRITE,dynamic_va,dynamic_off,len(dynamic_blob),link=sidx['dynstr'],addralign=8,entsize=16))
    sections.append(pack_shdr(nameoff['strtab'],SHT_STRTAB,0,0,strtab_off,len(strtab),addralign=1))
    sections.append(pack_shdr(nameoff['symtab'],SHT_SYMTAB,0,0,symtab_off,len(symtab),link=sidx['strtab'],info=1,addralign=8,entsize=24))
    sections.append(pack_shdr(nameoff['shstrtab'],SHT_STRTAB,0,0,shstr_off,len(shstr),addralign=1))
    for s in sections:data+=s

    phoff=64
    phdrs=[
      pack_phdr(PT_LOAD,PF_R,PAYLOAD_OFF,0,RO_END,RO_END),
      pack_phdr(PT_LOAD,PF_R|PF_X,PAYLOAD_OFF+RO_END,RO_END,PLT_END-RO_END,PLT_END-RO_END),
      pack_phdr(PT_LOAD,PF_R|PF_W,PAYLOAD_OFF+PLT_END,PLT_END,FILE_END-PLT_END,MEM_END-PLT_END),
      pack_phdr(PT_LOAD,PF_R|PF_W,meta_off,META_VA,meta_end-meta_off,meta_end-meta_off),
      pack_phdr(PT_DYNAMIC,PF_R|PF_W,dynamic_off,dynamic_va,len(dynamic_blob),len(dynamic_blob),8),
    ]
    data[:64]=pack_ehdr(phoff,shoff,len(phdrs),len(sections),sidx['shstrtab'])
    pos=phoff
    for p in phdrs:data[pos:pos+56]=p; pos+=56
    Path(args.output).write_bytes(data)
    print(f'[+] wrote {args.output}')
    print(f'    dynsym        : {len(dynsym)//24} entries')
    print(f'    rela.dyn      : {len(rela_dyn)//24} entries ({relative_count} synthetic RELATIVE first)')
    print(f'    rela.plt      : {len(rela_plt)//24} entries')
    print(f'    DT_NEEDED     : {len(needed)} ({", ".join(needed)})')
    print(f'    SONAME        : {soname}')
    print(f'    metadata LOAD : file 0x{meta_off:x} -> VA 0x{META_VA:x}')
    print('[!] program headers / metadata VA are synthetic analysis reconstruction, not claimed original')
if __name__=='__main__':main()
