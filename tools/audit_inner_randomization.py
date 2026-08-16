#!/usr/bin/env python3
"""Audit destructively randomized regions in the recovered YSM inner raw file.

This distinguishes metadata that survived in-place from metadata that the protector
removed/replaced with 7-bit filler. Where an exact redundant copy exists in the
outer loader metadata, the tool compares the raw bytes with that recovered copy.
"""
from __future__ import annotations
import argparse, json, math, struct
from collections import Counter
from pathlib import Path

SAMPLE_SIZE = 0x530070
REGIONS = {
    'elf_header_phdr': (0x000000, 0x000238),
    'dynsym':          (0x0002D0, 0x0283C8),
    'dynstr':          (0x044E50, 0x073B1D),
    'rela_dyn':        (0x073B20, 0x0DB158),
    'rela_plt':        (0x0DB158, 0x0ED3B0),
    'dynamic':         (0x505570, 0x5057A0),
    'section_headers': (0x52F9B0, 0x530070),
}
GNU_HASH = (0x02B998, 0x0378A0)
SYSV_HASH = (0x0378A0, 0x044E50)

def entropy(data: bytes) -> float:
    if not data: return 0.0
    n=len(data); c=Counter(data)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

def cstr(buf: bytes, off: int) -> bytes:
    if not 0 <= off < len(buf): return b''
    e=buf.find(b'\0',off)
    return buf[off:e if e >= 0 else len(buf)]

def gnu_hash(name: bytes) -> int:
    h=5381
    for ch in name: h=((h*33)+ch)&0xffffffff
    return h

def build_gnu_hash(dynsym: bytes, dynstr: bytes, nb: int, symoff: int, bloom_size: int, bloom_shift: int) -> bytes:
    n=len(dynsym)//24; bloom=[0]*bloom_size; buckets=[0]*nb; chains=[0]*(n-symoff)
    hashes=[]
    for i in range(n):
        no=struct.unpack_from('<I',dynsym,i*24)[0]
        hashes.append(gnu_hash(cstr(dynstr,no)))
    seen=set(); last=None
    for i in range(symoff,n):
        h=hashes[i]; b=h%nb
        if b != last:
            if b in seen: raise ValueError('dynsym GNU-hash order is not bucket-contiguous')
            seen.add(b); last=b
            if buckets[b] == 0: buckets[b]=i
        word=(h//64)%bloom_size
        bloom[word] |= (1<<(h%64)) | (1<<((h>>bloom_shift)%64))
        chains[i-symoff]=h & 0xfffffffe
    for i in range(symoff,n):
        b=hashes[i]%nb
        if i==n-1 or hashes[i+1]%nb != b: chains[i-symoff] |= 1
    return (struct.pack('<IIII',nb,symoff,bloom_size,bloom_shift)
            + struct.pack(f'<{bloom_size}Q',*bloom)
            + struct.pack(f'<{nb}I',*buckets)
            + struct.pack(f'<{len(chains)}I',*chains))

def stats(raw: bytes, start: int, end: int, expected: bytes|None=None) -> dict:
    d=raw[start:end]
    out={'start':start,'end':end,'size':len(d),'entropy':entropy(d),
         'max_byte':max(d) if d else None,'bytes_ge_0x80':sum(x>=0x80 for x in d),
         'all_7bit':all(x<0x80 for x in d)}
    if expected is not None:
        if len(expected)!=len(d): raise ValueError(f'expected length mismatch at 0x{start:x}')
        eq=sum(a==b for a,b in zip(d,expected))
        low7=sum((a&0x7f)==(b&0x7f) for a,b in zip(d,expected))
        lost=sum((b>=0x80 and a<0x80) for a,b in zip(d,expected))
        out.update({'exact_match_bytes':eq,'exact_match_ratio':eq/len(d),
                    'low7_match_ratio':low7/len(d),'known_highbit_bytes_lost':lost})
    return out

def main() -> int:
    ap=argparse.ArgumentParser()
    ap.add_argument('inner_raw',type=Path)
    ap.add_argument('--metadata-dir',type=Path,required=True)
    ap.add_argument('--aux-dir',type=Path,required=True)
    ap.add_argument('--json',type=Path)
    a=ap.parse_args(); raw=a.inner_raw.read_bytes()
    if len(raw)!=SAMPLE_SIZE: raise SystemExit(f'unexpected inner size 0x{len(raw):x}')
    md=a.metadata_dir; aux=a.aux_dir
    dynsym=(md/'dynsym.bin').read_bytes(); dynstr=(md/'dynstr.bin').read_bytes()
    rela_dyn=(md/'rela.relative.bin').read_bytes()+(md/'rela.dyn.bin').read_bytes()
    rela_plt=(md/'rela.plt.bin').read_bytes(); sysv=(aux/'hash.sysv.bin').read_bytes()

    gs,ge=GNU_HASH; gh=raw[gs:ge]
    nb,symoff,bloom_size,bloom_shift=struct.unpack_from('<IIII',gh,0)
    gnu_exact=build_gnu_hash(dynsym,dynstr,nb,symoff,bloom_size,bloom_shift)
    if len(gnu_exact)!=len(gh): raise SystemExit('GNU hash size mismatch')
    bloom_end=16+bloom_size*8; buckets_end=bloom_end+nb*4
    chain_count=(len(gh)-buckets_end)//4
    exact_chain=[]
    for i in range(chain_count):
        if gh[buckets_end+i*4:buckets_end+(i+1)*4] == gnu_exact[buckets_end+i*4:buckets_end+(i+1)*4]: exact_chain.append(i)
    exact_chain_set=set(exact_chain); suffix=0
    for i in range(chain_count-1,-1,-1):
        if i in exact_chain_set: suffix+=1
        else: break

    expected={'dynsym':dynsym,'dynstr':dynstr,'rela_dyn':rela_dyn,'rela_plt':rela_plt}
    report={'sample_size':len(raw),'regions':{}}
    for name,(s,e) in REGIONS.items(): report['regions'][name]=stats(raw,s,e,expected.get(name))
    report['regions']['gnu_hash']=stats(raw,gs,ge,gnu_exact)
    hs,he=SYSV_HASH; report['regions']['sysv_hash']=stats(raw,hs,he,sysv)
    report['gnu_hash_evidence']={
        'nbuckets':nb,'symoffset':symoff,'bloom_size':bloom_size,'bloom_shift':bloom_shift,
        'header_exact':gh[:16]==gnu_exact[:16],
        'bloom_exact':gh[16:bloom_end]==gnu_exact[16:bloom_end],
        'bucket_words_exact':sum(gh[bloom_end+i*4:bloom_end+(i+1)*4]==gnu_exact[bloom_end+i*4:bloom_end+(i+1)*4] for i in range(nb)),
        'chain_words_exact':len(exact_chain),'chain_words_total':chain_count,
        'exact_chain_suffix_entries':suffix,
        'exact_chain_suffix_symbol_start':(len(dynsym)//24)-suffix if suffix else None,
    }
    report['conclusion']='Core stripped regions are destructive 7-bit filler rather than ordinary recoverable ciphertext. Exact reconstruction is possible where the outer loader preserved redundant metadata. The original GNU-hash header and bloom filter survive in place; regenerated buckets/chains are constrained by the recovered dynsym order and surviving chain suffix.'
    print('[+] destructive-region audit')
    for n,r in report['regions'].items():
        extra=''
        if 'exact_match_ratio' in r: extra=f" match={r['exact_match_ratio']:.3%} lost_hi={r['known_highbit_bytes_lost']}"
        print(f"    {n:<16} 0x{r['start']:06x}..0x{r['end']:06x} 7bit={r['all_7bit']} H={r['entropy']:.3f}{extra}")
    g=report['gnu_hash_evidence']
    print(f"[+] GNU hash header/bloom exact: {g['header_exact']}/{g['bloom_exact']}")
    print(f"    exact bucket words : {g['bucket_words_exact']}/{g['nbuckets']}")
    print(f"    exact chain suffix : {g['exact_chain_suffix_entries']} entries (symbols {g['exact_chain_suffix_symbol_start']}..{len(dynsym)//24-1})")
    if a.json:
        a.json.write_text(json.dumps(report,indent=2),encoding='utf-8'); print('[+] wrote',a.json)
    return 0
if __name__=='__main__': raise SystemExit(main())
