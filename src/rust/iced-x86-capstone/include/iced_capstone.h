// SPDX-License-Identifier: MIT
// Copyright (C) 2026 NeverSight and contributors
#ifndef ICED_CAPSTONE_H
#define ICED_CAPSTONE_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
// Version 1 exposes iced Code/Register/OpKind discriminants from the pinned
// source tree. Consumers must generate their mappings from that same tree.
#define ICED_CAPSTONE_ABI_VERSION 1
#define ICED_CAPSTONE_MAX_OPERANDS 5
#define ICED_CAPSTONE_BATCH_PREFIX_SENSITIVE UINT16_C(0x8000)
struct iced_capstone_instruction {
    uint64_t values[ICED_CAPSTONE_MAX_OPERANDS];
    uint64_t displacement;
    uint32_t code;
    uint32_t registers[ICED_CAPSTONE_MAX_OPERANDS];
    uint32_t kinds[ICED_CAPSTONE_MAX_OPERANDS];
    uint32_t memory_base, memory_index, segment, memory_size;
    uint8_t length, op_count, scale, disp_offset, disp_size;
    uint8_t imm_offset, imm_size, imm_offset2, imm_size2;
};
// Per-consumer state. Do not share a handle across concurrent calls. No input
// pointers survive a call, so callers may change or free their input afterward.
void *iced_capstone_create(uint32_t bits);
void iced_capstone_destroy(void *state);
uint32_t iced_capstone_scan_with_state(void *state, const uint8_t *bytes, size_t length);
// Batch classification for a caller-admitted set of 32/64-bit encodings.
// Set PREFIX_SENSITIVE for entries that permit only bare encodings or one REX.
// For other entries, native iced validity checks include all prefixes.
struct iced_capstone_scan_result { size_t count, bytes; };
// ids maps pinned iced Code values to nonzero 15-bit IDs plus the policy flag.
// A zero ID, invalid instruction or declined prefix stops before that input.
// The result is a count
// of packed (caller ID << 8) | length entries and their total byte extent;
// only that output prefix changes. A declined instruction is never counted.
// bytes covers min(length, saturating(capacity * 15)) readable bytes, ids covers
// id_count entries, and output covers capacity entries. Output must not overlap
// either input. No pointers survive the call. Zero/null inputs return zero.
struct iced_capstone_scan_result iced_capstone_scan_batch(uint32_t bits, const uint8_t *bytes, size_t length,
                               const uint16_t *ids, size_t id_count,
                               uint32_t *output, size_t capacity);
// On success: (iced Code << 8) | length. Zero requests the caller's fallback.
// Only 16, 32 and 64 are valid bitness values. No input pointer is retained.
uint32_t iced_capstone_scan(uint32_t bits, const uint8_t *bytes, size_t length);
// Bounded decode without formatting. Returns 1 on success, 0 on failure;
// failure does not modify *out. UD1 uses Intel's r32/rm32 representation.
// IP/base-relative displacements are signed, including RIP/EIP operands.
// Absolute addressing retains iced's address value. values[] contains
// immediates and absolute near targets.
// Far targets pack the 16-bit selector above the low 32-bit offset.
uint32_t iced_capstone_decode(uint32_t bits, const uint8_t *bytes, size_t length,
                             uint64_t ip, struct iced_capstone_instruction *out);
#ifdef __cplusplus
}
#endif
#endif
