#!/usr/bin/env python3
"""Recover .gcc_except_table/.rodata boundary from surviving ARM64 EH metadata."""
from __future__ import annotations
import argparse, json, struct
from pathlib import Path

EH_FRAME_HDR = 0x1FFAFC
EH_FRAME = 0x2125F0


def uleb(b,p):
    v=s=0
    while True:
        x=b[p]; p+=1; v|=(x&0x7f)<<s
        if not x&0x80:return v,p
        s+=7

def sleb(b,p):
    v=s=0
    while True:
        x=b[p];p+=1;v|=(x&0x7f)<<s;s+=7
        if not x&0x80:
            if x&0x40:v|=-(1<<s)
            return v,p

def decptr(b,p,enc,field):
    fmt=enc&0x0f; app=enc&0x70
    if fmt==0x03:v=struct.unpack_from('<I',b,p)[0];p+=4
    elif fmt==0x0b:v=struct.unpack_from('<i',b,p)[0];p+=4
    elif fmt==0x04:v=struct.unpack_from('<Q',b,p)[0];p+=8
    elif fmt==0x0c:v=struct.unpack_from('<q',b,p)[0];p+=8
    elif fmt==0x01:v,p=uleb(b,p)
    elif fmt==0x09:v,p=sleb(b,p)
    else: raise ValueError(f'unsupported DW_EH_PE 0x{enc:x}')
    if app==0x10:v+=field
    elif app:raise ValueError(f'unsupported DW_EH_PE application 0x{enc:x}')
    return v,p

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('inner',type=Path)
    ap.add_argument('--json',type=Path)
    a=ap.parse_args(); b=a.inner.read_bytes()

    hdr=b[EH_FRAME_HDR:EH_FRAME_HDR+12]
    if hdr[:4]!=bytes([1,0x1b,0x03,0x3b]):raise SystemExit('unexpected .eh_frame_hdr encoding')
    advertised=struct.unpack_from('<I',hdr,8)[0]

    cies={}; off=EH_FRAME; fdes=0
    while True:
        n=struct.unpack_from('<I',b,off)[0]
        if n==0:break
        c=off+4; end=c+n; cid=struct.unpack_from('<I',b,c)[0]
        if cid==0:
            p=c+5; z=b.index(0,p,end); aug=b[p:z].decode();p=z+1
            _,p=uleb(b,p);_,p=sleb(b,p);_,p=uleb(b,p);_,p=uleb(b,p); q=p
            cfg={'R':None,'L':None}
            for ch in aug[1:]:
                if ch=='P':
                    enc=b[q];q+=1;_,q=decptr(b,q,enc,q)
                elif ch=='L':cfg['L']=b[q];q+=1
                elif ch=='R':cfg['R']=b[q];q+=1
            cies[off]=cfg
        else:fdes+=1
        off=end
    if fdes!=advertised:raise SystemExit(f'FDE count mismatch {fdes} != {advertised}')

    lsdas=[]; off=EH_FRAME
    while True:
        n=struct.unpack_from('<I',b,off)[0]
        if n==0:break
        c=off+4;end=c+n;cid=struct.unpack_from('<I',b,c)[0]
        if cid:
            cfg=cies.get(c-cid)
            if cfg and cfg['L'] is not None:
                p=c+4;_,p=decptr(b,p,cfg['R'],p)
                fmt=cfg['R']&0xf
                p += 4 if fmt in (3,0xb) else 8
                alen,p=uleb(b,p)
                if alen:
                    lsda,_=decptr(b,p,cfg['L'],p);lsdas.append(lsda)
        off=end

    ends=[]
    for x in sorted(set(lsdas)):
        p=x; lp=b[p];p+=1
        if lp!=0xff:_,p=decptr(b,p,lp,p)
        te=b[p];p+=1
        if te!=0xff:
            d,p=uleb(b,p);ends.append(p+d)
        ce=b[p];p+=1;cl,p=uleb(b,p)
        if te==0xff:ends.append(p+cl)
    gcc_start=min(lsdas); gcc_end=max(ends); ro_end=EH_FRAME_HDR
    out={
        'fde_count':fdes,'distinct_lsda_count':len(set(lsdas)),
        'gcc_except_table':{'addr':gcc_start,'offset':gcc_start,'size':gcc_end-gcc_start,'end':gcc_end},
        'rodata':{'addr':gcc_end,'offset':gcc_end,'size':ro_end-gcc_end,'end':ro_end},
    }
    print(f"[+] FDEs              {fdes}")
    print(f"[+] distinct LSDAs    {len(set(lsdas))}")
    print(f"[+] .gcc_except_table 0x{gcc_start:x}..0x{gcc_end:x} size=0x{gcc_end-gcc_start:x}")
    print(f"[+] .rodata           0x{gcc_end:x}..0x{ro_end:x} size=0x{ro_end-gcc_end:x}")
    if a.json:
        a.json.write_text(json.dumps(out,indent=2));print(f'[+] wrote {a.json}')
    return 0

if __name__=='__main__':raise SystemExit(main())
