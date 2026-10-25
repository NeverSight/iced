# Capstone compatibility boundary

This crate belongs to the [NeverSight iced fork](https://github.com/NeverSight/iced).
It exposes bounded, allocation-free per-instruction C calls after iced's shared
decoder tables initialize. `iced_capstone_create` owns a per-consumer scratch
decoder; `iced_capstone_scan_with_state` reuses its mode and dispatch tables.
`DecoderScratch` borrows each window only for the call, uses the existing checked
read helpers, and clears all input pointers on return or unwind. Its stream
decoder remains private and no reference lifetime is extended.
`iced_capstone_scan` is the stateless alternative and returns the pinned iced code
and length. `iced_capstone_decode` provides operands without formatting and
normalizes UD1 to Intel's r32/rm32 form. Invalid, empty and unsupported inputs
return zero; the caller retains its existing decoder fallback. No caller memory
is retained. The input pointer must cover at least `min(length, 15)` bytes.

The ABI header and Rust `repr(C)` record are versioned together. Code, Register
and OpKind discriminants belong to this pinned iced source revision; callers
must generate mappings from that same source. This is a private integration
boundary, not an implementation of the public `cs_*` API. Detailed access,
implicit registers, groups, printed text and Capstone IDs remain the caller's
responsibility. NeverD's opt-in route currently admits 96 VEX/EVEX encodings
from 14 vector move, XOR and FMA families; scalar, full-detail and remaining
instruction forms use Capstone. The default remains off pending broader
performance and platform qualification.

## Regression audit

The tests replay bug classes from the Capstone fork's history, with independent
expected architectural fields. They do not equate every field of two different
public APIs. Run `cargo test --release --locked` from this directory.

| Capstone fix | iced/profile result |
| --- | --- |
| `67a648f9` LOCK, MOV CS, UD1 | Illegal LOCK/MOV CS already rejected. Full UD1 extent already decoded. Profile corrects 16/64-bit UD1 register/memory metadata to r32/rm32, preserving effective addresses and rejection. |
| `65c42d75`, `20012621` address overrides and consumed displacement widths | Existing iced decoder passes the mode/prefix/offset regression matrix. |
| `5e86f277`, `be5d4c14` far immediates | Both immediate extents and truncated tails pass. iced has separate offset/selector fields; consumers must preserve both. |
| `9f3333d1`, `4a525faf`, `619d1231` repeated/cancelled prefixes | Last FS/GS and cancelled REX cases pass; new APX forms remain unsupported. |
| `aa7aa4e5`, `a76fc6e0` prefixes before vector escapes | Existing invalid checks reject illegal legacy/REX prefixes. |
| `16211ee3`, `52296896` gather and EVEX legality | Existing checks reject overlapping gathers and reserved fields; the APX extended-address form is outside this iced version. |
| `00320ca9`, `b871849b`, `88fd72d1` control-transfer width | Intel/AMD selection is explicit in iced. NeverD's default Capstone profile differs for some prefixed branches; these remain in fallback. |
| `454ed84b` SSE predicates | All 256 immediate values retain the base comparison family; predicate formatting aliases are a separate interface choice. |
| `4d895799`, `e1a71eb2`, `0083ee78` access/flags | Conversion destinations, SHLD/SHRD reads/writes and TEST memory/flags pass. |
| `fa4f7359`, `9c990989`, `78f54093` mask/GFNI detail | iced's mask reads, scalar broadcast size and scaled displacement pass; Capstone vector-size/access conventions require translation. |
| `e0cc2636` LES/LDS/BOUND | Legacy 32-bit forms pass without being stolen by vector escape handling. |
| `ec7f06fc` x87 environment | iced agrees with XED: effective REX.W selects 28/108-byte images even with 66. The Capstone regression incorrectly expected 14/94 bytes; do not copy that expectation into iced. |
| `c92df86a`, `020b8ccf` normalization/lookahead | LLIG, segment-prefixed scalar vector forms and following-instruction boundaries pass; legacy INC/BOUND retain their own extents outside long mode. |
| `196df3fd`, `c7e6a51b`, `c00aa8ae` comparison lengths/SAE | Scalar/packed L'L, register SAE, invalid memory SAE and reserved-length cases pass without rewriting the input. |
| `90c5efcb` VP4DPW masks | iced keeps the 64-byte destination, 16-byte memory tuple and mask read distinct. Translating effective mask-byte widths remains a consumer responsibility. |
| `41953823`, `64edab73`, `3a8d30a6` implicit operands/access | CL shift operands, sign-extended immediates, VMOVUPS memory writes and address-size-selected LOOP counters pass. AT&T operand ordering/rendering remains a separate API layer. |
| `511ba599` MOVSXD | iced and XED decode 66 MOVSXD with a 16-bit source and accept 67-prefixed non-REX.W forms. Some Capstone expectations/contexts differ; the NeverD adapter leaves these scalar forms in fallback. |
| `ba0cd1c4`, `71a49998`, `f33076b6`, `a1d9c8a2`, `f3d7aa41`, `9d0d7183`, `b173b2dc`, `816808a3` | APX and newer SHA-512/feature forms are unsupported capabilities, not evidence of the same implemented-decoder bug. NeverD retains Capstone for them. |
| `fc47d395`, `21aae3ec`, `c2623d7c`, `9a2842c5` | Capstone reduced-name, C compiler and handle-option behavior has no matching iced decoder API. NeverD's option gates preserve the existing Capstone contract. |

UD1's fixed operands are specified in Intel SDM Vol. 2, “UD—Undefined
Instruction” (0F B9 /r). Its operands still have no ordinary read/write effect.
Existing iced decoding semantics remain unchanged; UD1 normalization is owned
by this profile. `DecoderScratch` is an additional Rust API, not a change to the
existing stream decoder's borrowing contract.
The x87 REX.W result is independently represented in Intel XED's
`datafiles/xed-isa.txt` FLDENV/FNSTENV/FNSAVE/FRSTOR patterns and AMD APM Vol. 1,
section 6.6, “Instruction Prefixes”.

This crate retains the repository's MIT license. The `lazy_static` dependency
is MIT/Apache-2.0; its original notices remain applicable. Decoder/compiler
changes must rerun this suite and iced's decoder tests. Tests passing on one
host do not qualify native throughput or ABI linking on other hosts.

The audit covers the relevant x86 fixes since the fork's `a0201371` import,
including earlier changes that were outside the initial September date filter.
Build-only and newer unsupported ISA changes are distinguished from reproduced
decoder defects; this table is not a claim of universal Capstone API equivalence.
