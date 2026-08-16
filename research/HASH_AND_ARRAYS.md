# Custom SysV hash and constructor-array metadata

This checkpoint maps three previously unidentified CB1D8-encrypted buffers from the processed inner-loader metadata object.

## `0xC8920` proves the hash algorithm

The inner symbol resolver at outer VA `0xC8920` computes the classic SysV ELF hash:

```c
h = 0;
for (byte c : name) {
    h = (h << 4) + c;
    g = h & 0xF0000000;
    h ^= g;
    h ^= g >> 24;
}
```

When the hash-enabled flag at runtime-context `+0xC0` is set, lookup is:

```text
bucket_index = hash(name) % nbucket
symbol_index = buckets[bucket_index]

while (symbol_index != 0):
    compare dynstr[dynsym[symbol_index].st_name] with requested name
    symbol_index = chains[symbol_index]
```

`0xC8AD4` populates the relevant runtime fields from metadata helpers:

```text
runtime +0xC8 = nbucket
runtime +0xD8 = CA744(...) -> bucket array
runtime +0xE0 = CA78C(...) -> chain array
runtime +0xA8 = dynstr
runtime +0xB0 = dynsym
```

For the mapped sample:

```text
nbucket = 6837
nchain  = 6837
```

## Exact encrypted bucket/chain sources

The two arrays are separate in the outer SO:

```text
buckets:
  encrypted VA = 0x40D850
  bytes        = 0x6AD4 = 6837 * 4
  seed         = seed16[0] = 0x9A

chains:
  encrypted VA = 0x3A5410
  bytes        = 0x6AD4 = 6837 * 4
  seed         = seed16[1] = 0x0D
```

Both decrypt with the already-recovered `CB1D8` stream transform.

The exact standard SysV-style blob:

```text
uint32 nbucket
uint32 nchain
uint32 buckets[6837]
uint32 chains[6837]
```

has:

```text
size    = 0xD5B0
SHA-256 = b1b7604e37c57fb53edd78a3db620ef4fd4bdb34b34d57784670cf0e2a195380
```

### Independent validation against all 6837 dynsym entries

The stored tables match the resolver exactly when each symbol is inserted by prepending:

```c
bucket = elf_hash(name) % nbucket;
chains[i] = buckets[bucket];
buckets[bucket] = i;
```

Rebuilding the full arrays from recovered `dynstr` + `dynsym` gives an exact byte-for-byte match for both 6837-entry arrays.

This also explains why an earlier forward/append-style SysV-hash regeneration had the correct occupancy counts but different indices.

## Important distinction from the producer's original GNU hash

The surviving inner section-name string table contains:

```text
.gnu.hash
.gnu.version
.gnu.version_r
```

and does **not** contain a `.hash` name.

Therefore the exact SysV buckets/chains above are best understood as **protector/custom-loader resolver metadata**. They can be used to create a semantically valid `DT_HASH` for a reconstructed ELF, but they are not proof that the producer's original file used a SysV `.hash` section.

The original `.gnu.hash` bytes are not present plaintext in the recovered raw inner image; a full scan using the recovered 6837 dynsym names did not find a valid GNU-hash table. The custom loader also does not preserve a GNU-hash buffer through the mapped CB1D8 metadata helpers. At this checkpoint, original GNU-hash bytes should be treated as stripped/not recovered.

## Constructor arrays

A third CB1D8 helper is `CA7D4`:

```text
encrypted VA = 0x443170
bytes        = 0x30
seed         = seed16[2] = 0x6D
```

It decrypts six qword addends:

```text
0x27C3EC
0x29734C
0x2CBBF4
0x2E0B2C
0x35B388
0x4D64C4
```

The processed metadata also stores:

```text
.init_array VA    = 0x509540
.init_array count = 6

.fini_array VA    = 0x509530
.fini_array count = 2
```

The independently recovered runtime `R_AARCH64_RELATIVE` fixups target exactly these slots:

```text
0x509530 <- 0x25E2F8
0x509538 <- 0x25E2E0

0x509540 <- 0x27C3EC
0x509548 <- 0x29734C
0x509550 <- 0x2CBBF4
0x509558 <- 0x2E0B2C
0x509560 <- 0x35B388
0x509568 <- 0x4D64C4
```

This gives exact reconstructed dynamic tags:

```text
DT_FINI_ARRAY   = 0x509530
DT_FINI_ARRAYSZ = 0x10
DT_INIT_ARRAY   = 0x509540
DT_INIT_ARRAYSZ = 0x30
```

The file-backed array slots are zero before relocation, matching RELA-style initialization.

## Section-table tail observation

The raw inner image still contains a plaintext section-name string table beginning around raw offset `0x52F8AA` and ending just before `0x52F9B0`.

The final range:

```text
0x52F9B0 .. 0x530070
size = 0x6C0
```

is high-entropy/scrambled. `0x6C0` happens to equal `27 * sizeof(Elf64_Shdr)` (`27 * 0x40`), making a destroyed/protected section-header table a strong lead. This is **not yet proof** of `e_shnum == 27`; the tail still needs a concrete decoding rule before those bytes can be called original section headers.

## Tool

```bash
python tools/recover_inner_aux_metadata.py \
  libysmteam.so \
  inner_aux \
  --metadata-dir inner_meta \
  --strict-hash
```

Outputs:

```text
inner_aux/hash.sysv.bin
inner_aux/hash.buckets.bin
inner_aux/hash.chains.bin
inner_aux/init_array.tsv
inner_aux/aux_metadata.json
```

Next target: use the exact init/fini metadata in the near-original builder, then investigate whether the scrambled `0x6C0` tail can be related to a specific protector transform or whether section headers must be reconstructed from surviving section names and recovered dynamic/segment boundaries.
