#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, struct
from pathlib import Path

SAMPLE_SHA256='acdd435cad4a6c55ee47babd8d3fb6da4bc99ef8f1be6f573921a9b95d8bb5ca'
LOADS=((0x000000,0x000000,0x390D84),(0x391780,0x3A1780,0x38B660),(0x71E000,0xD73000,0x29F4))
SEED_K_VA=0x0B9760; SEED_TABLE_VA=0x31E790
RELATIVE_TABLE_VA=0x3D73D0; RELATIVE_TABLE_SIZE=0x36480; RELATIVE_SEED_INDEX=10
DEPENDENCY_PTR_TABLE_VA=0x72CD20; DEPENDENCY_COUNT=10
R_AARCH64_RELATIVE=0x403
MEM_END=0x643000

def sha256(b): return hashlib.sha256(b).hexdigest()
def va_to_offset(va):
    for fo,sv,sz in LOADS:
        if sv<=va<sv+sz:return fo+(va-sv)
    raise ValueError(f'VA 0x{va:x} outside known LOAD ranges')
def read_va(image,va,n):
    off=va_to_offset(va); return image[off:off+n]
def cstring_va(image,va):
    off=va_to_offset(va); end=image.find(b'\0',off)
    if end<0: raise ValueError(f'unterminated string at VA 0x{va:x}')
    return image[off:end].decode('utf-8',errors='replace')
def derive_seed16(image):
    k=read_va(image,SEED_K_VA,16); t=read_va(image,SEED_TABLE_VA,64)
    a,b,c,d=t[0::4],t[1::4],t[2::4],t[3::4]
    return bytes((d[i]+c[i]+k[i]*b[i]+k[i]*k[i]*a[i])&0xff for i in range(16))
def cb1d8(data,seed):
    out=bytearray(data); state=seed&0xffffffff; prev=0
    for i,old in enumerate(data):
        state=(state*0x41C64E6D+0x3039)&0xffffffff
        state^=(prev<<8)&0xffffffff; state^=i&0xffffffff
        out[i]=old^((state>>16)&0xff); prev=old
    return bytes(out)

def iter_outer_rela(image):
    if image[:4]!=b'\x7fELF' or image[4]!=2 or image[5]!=1: raise ValueError('expected ELF64 LE')
    e_shoff=struct.unpack_from('<Q',image,0x28)[0]
    e_shentsize=struct.unpack_from('<H',image,0x3a)[0]
    e_shnum=struct.unpack_from('<H',image,0x3c)[0]
    for i in range(e_shnum):
        off=e_shoff+i*e_shentsize
        sh_type=struct.unpack_from('<I',image,off+4)[0]
        if sh_type!=4: continue
        sh_offset=struct.unpack_from('<Q',image,off+0x18)[0]
        sh_size=struct.unpack_from('<Q',image,off+0x20)[0]
        sh_entsize=struct.unpack_from('<Q',image,off+0x38)[0] or 24
        for p in range(sh_offset,sh_offset+sh_size,sh_entsize):
            r_offset,r_info,r_addend=struct.unpack_from('<QQq',image,p)
            yield r_offset,r_info,r_addend

def recover_dependencies(image):
    relas={off:(info,add) for off,info,add in iter_outer_rela(image)}
    out=[]
    for i in range(DEPENDENCY_COUNT):
        slot=DEPENDENCY_PTR_TABLE_VA+i*8
        if slot not in relas: raise ValueError(f'no outer RELA for dependency slot 0x{slot:x}')
        info,add=relas[slot]
        rtype=info&0xffffffff
        if rtype!=R_AARCH64_RELATIVE: raise ValueError(f'dep slot 0x{slot:x} type 0x{rtype:x}')
        out.append({'index':i,'slot_va':slot,'string_va':add,'name':cstring_va(image,add)})
    return out

def main():
    ap=argparse.ArgumentParser(description='Recover YSM loader dependency order and 16-byte relative-fixup table.')
    ap.add_argument('outer_so',type=Path); ap.add_argument('output_dir',type=Path); ap.add_argument('--strict-hash',action='store_true')
    args=ap.parse_args(); image=args.outer_so.read_bytes(); digest=sha256(image)
    if digest!=SAMPLE_SHA256:
        msg=f'input SHA-256 differs from mapped sample: {digest}'
        if args.strict_hash: raise SystemExit('[!] '+msg)
        print('[!] warning:',msg)
    seed16=derive_seed16(image)
    if seed16.hex()!='9a0d6d36ed21f793e953996ea264e885': raise SystemExit(f'unexpected seed {seed16.hex()}')
    dec=cb1d8(read_va(image,RELATIVE_TABLE_VA,RELATIVE_TABLE_SIZE),seed16[RELATIVE_SEED_INDEX])
    if len(dec)%16: raise SystemExit('relative table not 16-byte aligned')
    fixups=[]
    for i in range(0,len(dec),16):
        target,addend=struct.unpack_from('<QQ',dec,i)
        fixups.append((target,addend))
    if not all(t%8==0 for t,a in fixups): raise SystemExit('unaligned relative target')
    if not all(fixups[i][0]<fixups[i+1][0] for i in range(len(fixups)-1)): raise SystemExit('targets not strictly increasing')
    deps=recover_dependencies(image)
    args.output_dir.mkdir(parents=True,exist_ok=True)
    with (args.output_dir/'relative_fixups.tsv').open('w',encoding='utf-8') as f:
        f.write('index\ttarget_offset\tzero_base_addend\n')
        for i,(t,a) in enumerate(fixups): f.write(f'{i}\t0x{t:x}\t0x{a:x}\n')
    rela=b''.join(struct.pack('<QQq',t,R_AARCH64_RELATIVE,(a if a<1<<63 else a-(1<<64))) for t,a in fixups)
    (args.output_dir/'rela.relative.bin').write_bytes(rela)
    (args.output_dir/'needed.txt').write_text('\n'.join(d['name'] for d in deps)+'\n',encoding='utf-8')
    (args.output_dir/'dependencies.json').write_text(json.dumps(deps,indent=2),encoding='utf-8')
    manifest={
      'input_sha256':digest,'seed16':seed16.hex(),
      'relative_fixups':{'va':RELATIVE_TABLE_VA,'bytes':RELATIVE_TABLE_SIZE,'count':len(fixups),'seed_index':RELATIVE_SEED_INDEX,'decrypted_sha256':sha256(dec),'target_min':min(t for t,a in fixups),'target_max':max(t for t,a in fixups),'all_targets_8_aligned':True,'strictly_increasing':True},
      'dependencies':deps,
      'normalization_note':'rela.relative.bin is the exact custom C8DBC write semantics expressed as R_AARCH64_RELATIVE for a zero-based synthetic mapping (map_base == load_bias). It is not a claim about the producer original PT_LOAD minimum vaddr.'
    }
    (args.output_dir/'runtime_metadata.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    print(f'[+] relative fixups {len(fixups)} target 0x{min(t for t,a in fixups):x}..0x{max(t for t,a in fixups):x}')
    print(f'[+] decrypted sha256 {sha256(dec)}')
    print('[+] exact dependency order:')
    for d in deps: print(f"    {d['index']:2d}: {d['name']} (outer string VA 0x{d['string_va']:x})")
    print(f'[+] wrote {args.output_dir}')
if __name__=='__main__': main()
