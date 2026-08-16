# Destructive stripping audit

The protected inner file does not merely encrypt several removed ELF metadata regions. For the mapped sample, the protector replaces large metadata ranges with high-entropy **7-bit filler** (`0x00..0x7f`). This changes the reconstruction goal: bytes that were destructively replaced cannot be recovered from the raw inner file alone; exact recovery is possible only where equivalent metadata survives elsewhere in the outer loader.

## Measured stripped regions

```text
ELF header + PHDR   0x000000 .. 0x000238  all bytes <= 0x7f
dynsym              0x0002D0 .. 0x0283C8  all bytes <= 0x7f
most dynstr         0x044E50 .. 0x073B1D  all bytes <= 0x7f
rela.dyn            0x073B20 .. 0x0DB158  all bytes <= 0x7f
rela.plt            0x0DB158 .. 0x0ED3B0  all bytes <= 0x7f
PT_DYNAMIC          0x505570 .. 0x5057A0  all bytes <= 0x7f
section headers     0x52F9B0 .. 0x530070  all bytes <= 0x7f
```

The large randomized ranges have entropy very close to the maximum for a 7-bit alphabet (~7 bits/byte). For example, raw `dynsym`, `rela.dyn` and `rela.plt` measure about `6.999..7.000` bits/byte.

Recovered exact plaintext copies contain many bytes with bit 7 set, while the corresponding raw stripped ranges never contain such bytes. The original high bit is therefore absent from the raw representation. Treating these ranges as ordinary reversible XOR/stream ciphertext is incorrect.

## GNU hash is only partially destroyed

Original placement:

```text
.gnu.hash  0x02B998 .. 0x0378A0
```

The original header survives:

```text
nbuckets    = 1625
symoffset   = 336
bloom_size  = 2048
bloom_shift = 26
```

The entire `2048 * 8 = 0x4000` byte bloom filter also survives byte-for-byte.

Comparing the raw file with a GNU-hash table regenerated from recovered `dynsym` + `dynstr` gives:

```text
header                  exact
bloom filter            exact
bucket words            0 / 1625 exact (destroyed)
chain suffix            last 336 entries exact
surviving chain symbols 6501 .. 6836
```

The dynsym order is GNU-hash bucket-contiguous, so missing bucket and chain values are deterministic once the surviving header parameters and recovered names are known. The regenerated table is therefore constrained by the exact header, exact bloom filter, symbol order and exact trailing chain entries.

## SysV hash

The original `.hash` header survives at `0x378A0`:

```text
nbucket = 6837
nchain  = 6837
```

The outer custom resolver separately preserves the full 6837-entry bucket and chain arrays through encrypted metadata helpers. `inner_aux/hash.sysv.bin` comes from those recovered arrays rather than guessing from the randomized raw bytes.

## Consequence for section headers

The `0x6c0` section-header tail has the same 7-bit destructive-filler signature as removed dynsym/RELA/dynamic regions. It is not a hidden `CB1D8` or `B1E90` stream waiting to be decrypted. The 27 section headers must be reconstructed from independently recovered layout facts.

## Tool

```bash
python tools/audit_inner_randomization.py \
  ysm_inner_payload.bin \
  --metadata-dir inner_meta \
  --aux-dir inner_aux \
  --json randomization_audit.json
```
