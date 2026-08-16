#!/usr/bin/env python3
import argparse
import csv
import struct
from pathlib import Path

ET_DYN = 3
EM_AARCH64 = 183
EV_CURRENT = 1
PT_LOAD = 1
PF_X = 1
PF_W = 2
PF_R = 4
SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_NOBITS = 8
SHT_DYNSYM = 11
SHF_WRITE = 1
SHF_ALLOC = 2
SHF_EXECINSTR = 4
STB_GLOBAL = 1
STT_NOTYPE = 0
STT_OBJECT = 1
STT_FUNC = 2

PAYLOAD_OFF = 0x1000
RO_END = 0x25E2E0
TEXT_END = 0x4D6810
PLT_END = 0x4E29C0
GOT_START = 0x5097A0
GOTPLT_START = 0x50A6D0
GOTPLT_END = 0x510798
FILE_END = 0x530070
MEM_END = 0x643000

KNOWN_SYMBOLS = [
    ("inner_code_start", 0x25E2E0, 0, STT_FUNC, "text"),
    ("menu_renderer", 0x27CAEC, 0, STT_FUNC, "text"),
    ("key_input_callsite", 0x27CFFC, 0, STT_NOTYPE, "text"),
    ("auto_login_worker", 0x2948DC, 0, STT_FUNC, "text"),
    ("login_worker", 0x29527C, 0, STT_FUNC, "text"),
    ("auth_core", 0x298B94, 0, STT_FUNC, "text"),
    ("plt0", 0x4D6810, 0x20, STT_FUNC, "plt"),
    ("plt_entries", 0x4D6830, PLT_END - 0x4D6830, STT_NOTYPE, "plt"),
    ("login_status", 0x537730, 0, STT_OBJECT, "bss"),
    ("save_key_flag", 0x5390F8, 1, STT_OBJECT, "bss"),
    ("auto_login_flag", 0x5390F9, 1, STT_OBJECT, "bss"),
    ("saved_key", 0x539100, 0, STT_OBJECT, "bss"),
    ("key_buffer", 0x53912C, 0x100, STT_OBJECT, "bss"),
    ("auth_busy", 0x5392A0, 1, STT_OBJECT, "bss"),
]


def align(v, a):
    return (v + a - 1) & ~(a - 1)


def pack_ehdr(phoff, shoff, phnum, shnum, shstrndx):
    ident = bytearray(16)
    ident[:4] = b"\x7fELF"
    ident[4] = 2
    ident[5] = 1
    ident[6] = 1
    return bytes(ident) + struct.pack(
        "<HHIQQQIHHHHHH",
        ET_DYN,
        EM_AARCH64,
        EV_CURRENT,
        0,
        phoff,
        shoff,
        0,
        64,
        56,
        phnum,
        64,
        shnum,
        shstrndx,
    )


def pack_phdr(flags, off, va, filesz, memsz, align_value=0x1000):
    return struct.pack("<IIQQQQQQ", PT_LOAD, flags, off, va, va, filesz, memsz, align_value)


def pack_shdr(name, typ, flags, addr, off, size, link=0, info=0, addralign=1, entsize=0):
    return struct.pack(
        "<IIQQQQIIQQ", name, typ, flags, addr, off, size, link, info, addralign, entsize
    )


def section_key(value):
    if 0 <= value < RO_END:
        return "blob"
    if RO_END <= value < TEXT_END:
        return "text"
    if TEXT_END <= value < PLT_END:
        return "plt"
    if PLT_END <= value < GOT_START:
        return "data"
    if GOT_START <= value < GOTPLT_START:
        return "got"
    if GOTPLT_START <= value < GOTPLT_END:
        return "gotplt"
    if GOTPLT_END <= value < FILE_END:
        return "data_tail"
    if FILE_END <= value < MEM_END:
        return "bss"
    return None


def load_metadata(metadata_dir: Path):
    required = [
        "dynstr.bin",
        "dynsym.bin",
        "rela.dyn.bin",
        "rela.plt.bin",
        "dynsym.tsv",
        "plt.tsv",
    ]
    for name in required:
        if not (metadata_dir / name).exists():
            raise SystemExit(f"missing metadata file: {metadata_dir / name}")

    dynstr = (metadata_dir / "dynstr.bin").read_bytes()
    raw_dynsym = (metadata_dir / "dynsym.bin").read_bytes()
    rela_dyn = (metadata_dir / "rela.dyn.bin").read_bytes()
    rela_plt = (metadata_dir / "rela.plt.bin").read_bytes()
    dynrows = list(
        csv.DictReader((metadata_dir / "dynsym.tsv").open(encoding="utf-8"), delimiter="\t")
    )
    pltrows = list(
        csv.DictReader((metadata_dir / "plt.tsv").open(encoding="utf-8"), delimiter="\t")
    )
    return dynstr, raw_dynsym, rela_dyn, rela_plt, dynrows, pltrows


def main():
    ap = argparse.ArgumentParser(
        description="Build synthetic AArch64 analysis ELF with recovered dynsym and normalized RELA sections."
    )
    ap.add_argument("input")
    ap.add_argument("output")
    ap.add_argument("--metadata-dir", required=True)
    args = ap.parse_args()

    payload = Path(args.input).read_bytes()
    metadata_dir = Path(args.metadata_dir)
    if len(payload) != FILE_END:
        print(f"[!] warning expected 0x{FILE_END:x}, got 0x{len(payload):x}")

    dynstr, raw_dynsym, rela_dyn, rela_plt, dynrows, pltrows = load_metadata(metadata_dir)

    section_names = [
        "",
        "blob",
        "text",
        "plt",
        "data",
        "got",
        "gotplt",
        "data_tail",
        "bss",
        "dynstr",
        "dynsym",
        "rela_dyn",
        "rela_plt",
        "strtab",
        "symtab",
        "shstrtab",
    ]
    dotted = {key: "." + key.replace("_", ".") if key else "" for key in section_names}
    dotted["gotplt"] = ".got.plt"
    dotted["data_tail"] = ".data.tail"
    dotted["rela_dyn"] = ".rela.dyn"
    dotted["rela_plt"] = ".rela.plt"

    shstr = bytearray(b"\0")
    name_offset = {"": 0}
    for key in section_names[1:]:
        name_offset[key] = len(shstr)
        shstr += dotted[key].encode() + b"\0"
    section_index = {key: i for i, key in enumerate(section_names)}

    if len(raw_dynsym) % 24:
        raise SystemExit("bad dynsym size")
    dynsym = bytearray(raw_dynsym)
    for i, row in enumerate(dynrows):
        if i * 24 + 24 > len(dynsym):
            break
        value = int(row["value"], 16)
        old_shndx = int(row["shndx"])
        new_shndx = 0
        if old_shndx != 0 and value != 0:
            key = section_key(value)
            new_shndx = section_index[key] if key else 0
        struct.pack_into("<H", dynsym, i * 24 + 6, new_shndx)

    strtab = bytearray(b"\0")
    string_offsets = {}

    def intern(name):
        if name not in string_offsets:
            string_offsets[name] = len(strtab)
            strtab.extend(name.encode(errors="replace") + b"\0")
        return string_offsets[name]

    symbols = [b"\0" * 24]
    for name, value, size, typ, key in KNOWN_SYMBOLS:
        symbols.append(
            struct.pack(
                "<IBBHQQ",
                intern(name),
                (STB_GLOBAL << 4) | typ,
                0,
                section_index[key],
                value,
                size,
            )
        )
    for row in pltrows:
        name = row["symbol_name"]
        value = int(row["plt_address"], 16)
        if name:
            symbols.append(
                struct.pack(
                    "<IBBHQQ",
                    intern("plt." + name),
                    (STB_GLOBAL << 4) | STT_FUNC,
                    0,
                    section_index["plt"],
                    value,
                    0x10,
                )
            )
    symtab = b"".join(symbols)

    data = bytearray(PAYLOAD_OFF)
    data += payload

    def append_blob(blob, alignment=8):
        off = align(len(data), alignment)
        data.extend(b"\0" * (off - len(data)))
        data.extend(blob)
        return off

    dynstr_off = append_blob(dynstr, 1)
    dynsym_off = append_blob(bytes(dynsym), 8)
    rela_dyn_off = append_blob(rela_dyn, 8)
    rela_plt_off = append_blob(rela_plt, 8)
    strtab_off = append_blob(bytes(strtab), 1)
    symtab_off = append_blob(symtab, 8)
    shstr_off = append_blob(bytes(shstr), 1)
    shoff = align(len(data), 8)
    data.extend(b"\0" * (shoff - len(data)))

    sections = [pack_shdr(0, SHT_NULL, 0, 0, 0, 0)]

    def add_prog(key, start, end, flags, alignment=16, entsize=0):
        sections.append(
            pack_shdr(
                name_offset[key],
                SHT_PROGBITS,
                flags,
                start,
                PAYLOAD_OFF + start,
                end - start,
                addralign=alignment,
                entsize=entsize,
            )
        )

    add_prog("blob", 0, RO_END, SHF_ALLOC)
    add_prog("text", RO_END, TEXT_END, SHF_ALLOC | SHF_EXECINSTR)
    add_prog("plt", TEXT_END, PLT_END, SHF_ALLOC | SHF_EXECINSTR, 16, 16)
    add_prog("data", PLT_END, GOT_START, SHF_ALLOC | SHF_WRITE)
    add_prog("got", GOT_START, GOTPLT_START, SHF_ALLOC | SHF_WRITE, 8, 8)
    add_prog("gotplt", GOTPLT_START, GOTPLT_END, SHF_ALLOC | SHF_WRITE, 8, 8)
    add_prog("data_tail", GOTPLT_END, FILE_END, SHF_ALLOC | SHF_WRITE)
    sections.append(
        pack_shdr(
            name_offset["bss"],
            SHT_NOBITS,
            SHF_ALLOC | SHF_WRITE,
            FILE_END,
            PAYLOAD_OFF + FILE_END,
            MEM_END - FILE_END,
            addralign=16,
        )
    )
    sections.append(
        pack_shdr(name_offset["dynstr"], SHT_STRTAB, 0, 0, dynstr_off, len(dynstr), addralign=1)
    )
    sections.append(
        pack_shdr(
            name_offset["dynsym"],
            SHT_DYNSYM,
            0,
            0,
            dynsym_off,
            len(dynsym),
            link=section_index["dynstr"],
            info=1,
            addralign=8,
            entsize=24,
        )
    )
    sections.append(
        pack_shdr(
            name_offset["rela_dyn"],
            SHT_RELA,
            0,
            0,
            rela_dyn_off,
            len(rela_dyn),
            link=section_index["dynsym"],
            info=0,
            addralign=8,
            entsize=24,
        )
    )
    sections.append(
        pack_shdr(
            name_offset["rela_plt"],
            SHT_RELA,
            0,
            0,
            rela_plt_off,
            len(rela_plt),
            link=section_index["dynsym"],
            info=section_index["gotplt"],
            addralign=8,
            entsize=24,
        )
    )
    sections.append(
        pack_shdr(name_offset["strtab"], SHT_STRTAB, 0, 0, strtab_off, len(strtab), addralign=1)
    )
    sections.append(
        pack_shdr(
            name_offset["symtab"],
            SHT_SYMTAB,
            0,
            0,
            symtab_off,
            len(symtab),
            link=section_index["strtab"],
            info=1,
            addralign=8,
            entsize=24,
        )
    )
    sections.append(
        pack_shdr(
            name_offset["shstrtab"], SHT_STRTAB, 0, 0, shstr_off, len(shstr), addralign=1
        )
    )
    for section in sections:
        data += section

    phoff = 64
    phdrs = [
        pack_phdr(PF_R, PAYLOAD_OFF, 0, RO_END, RO_END),
        pack_phdr(
            PF_R | PF_X,
            PAYLOAD_OFF + RO_END,
            RO_END,
            PLT_END - RO_END,
            PLT_END - RO_END,
        ),
        pack_phdr(
            PF_R | PF_W,
            PAYLOAD_OFF + PLT_END,
            PLT_END,
            FILE_END - PLT_END,
            MEM_END - PLT_END,
        ),
    ]
    data[:64] = pack_ehdr(
        phoff, shoff, len(phdrs), len(sections), section_index["shstrtab"]
    )
    pos = phoff
    for header in phdrs:
        data[pos : pos + 56] = header
        pos += 56

    Path(args.output).write_bytes(data)
    print(f"[+] wrote {args.output}")
    print(f"    .dynsym entries : {len(dynsym) // 24}")
    print(f"    .rela.dyn       : {len(rela_dyn) // 24}")
    print(f"    .rela.plt       : {len(rela_plt) // 24}")
    print(f"    .got            : 0x{GOT_START:x}..0x{GOTPLT_START:x}")
    print(f"    .got.plt        : 0x{GOTPLT_START:x}..0x{GOTPLT_END:x}")


if __name__ == "__main__":
    main()
