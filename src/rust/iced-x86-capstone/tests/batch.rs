// SPDX-License-Identifier: MIT
// Copyright (C) 2026 NeverSight and contributors
use iced_x86::{Code, Decoder, DecoderOptions, FlowControl};
use iced_x86_capstone::{iced_capstone_scan_batch, CapstoneScanResult, CAPSTONE_BATCH_PREFIX_SENSITIVE};

const POISON: u32 = 0xfefe_fefe;

fn scan(bits: u32, bytes: &[u8], ids: &[u16], out: &mut [u32]) -> usize {
	let result = unsafe { iced_capstone_scan_batch(bits, bytes.as_ptr(), bytes.len(), ids.as_ptr(), ids.len(), out.as_mut_ptr(), out.len()) };
	assert!(result.count <= out.len());
	assert_eq!(result.bytes, out[..result.count].iter().map(|r| (r & 0xff) as usize).sum());
	result.count
}

#[test]
fn bounded_outputs_match_independent_decodes() {
	let ids: Vec<u16> =
		Code::values().map(|c| (c as u16) | if c.flow_control() == FlowControl::Next { 0 } else { CAPSTONE_BATCH_PREFIX_SENSITIVE }).collect();
	for bits in [32, 64] {
		let bytes = [0x50, 0x89, 0xc1, 0x83, 0xc0, 0x7f, 0xe8, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x85, 1, 0, 0, 0, 0xc3, 0x0f];
		for length in 0..=bytes.len() {
			let mut decoder = Decoder::new(bits, &bytes[..length], DecoderOptions::NONE);
			let mut expected = Vec::new();
			while decoder.can_decode() {
				let instruction = decoder.decode();
				if instruction.is_invalid() {
					break;
				}
				expected.push(((instruction.code() as u32) << 8) | instruction.len() as u32);
			}
			for capacity in 0..=expected.len() + 1 {
				let mut out = [POISON; 16];
				let count = scan(bits, &bytes[..length], &ids, &mut out[..capacity]);
				assert_eq!(count, capacity.min(expected.len()));
				assert_eq!(out[..count], expected[..count]);
				assert!(out[count..].iter().all(|&x| x == POISON));
			}
		}
	}
}

#[test]
fn declined_inputs_do_not_publish_or_skip_an_instruction() {
	let mut ids = vec![0u16; Code::values().len()];
	ids[Code::Nopd as usize] = 23;
	ids[Code::Inc_r32 as usize] = 24;
	for bits in [32, 64] {
		for suffix in [&[0x0f][..], &[0x89, 0xc1], &[0x66, 0x90], &[0x67, 0xe3, 0xff], &[0xf3, 0x90], &[0xf0, 0x90]] {
			let mut bytes = vec![0x90];
			bytes.extend_from_slice(suffix);
			bytes.push(0x90);
			let mut out = [POISON; 8];
			assert_eq!(scan(bits, &bytes, &ids, &mut out), 1);
			assert_eq!(out[0], (23 << 8) | 1);
			assert!(out[1..].iter().all(|&x| x == POISON));
		}
	}
	// Ordinary mapped NOPs preserve repeated REX; a missing NOP width is declined;
	// in 32-bit mode 40 is its own INC and remains a one-byte instruction.
	let mut out = [POISON; 8];
	assert_eq!(scan(64, &[0x40, 0x40, 0x90], &ids, &mut out), 1);
	assert_eq!(out[0], (23 << 8) | 3);
	assert_eq!(scan(64, &[0x48, 0x66, 0x90], &ids, &mut out), 0);
	assert_eq!(scan(32, &[0x40, 0x40, 0x90], &ids, &mut out), 3);
	assert_eq!(&out[..3], &[(24 << 8) | 1, (24 << 8) | 1, (23 << 8) | 1]);
}

#[test]
fn ffi_rejects_missing_ranges_and_unsupported_modes() {
	let bytes = [0x90];
	let ids: Vec<u16> =
		Code::values().map(|c| (c as u16) | if c.flow_control() == FlowControl::Next { 0 } else { CAPSTONE_BATCH_PREFIX_SENSITIVE }).collect();
	let mut out = [POISON; 2];
	for bits in [0, 16, 128] {
		assert_eq!(scan(bits, &bytes, &ids, &mut out), 0);
	}
	assert_eq!(scan(64, &bytes, &[], &mut out), 0);
	unsafe {
		assert_eq!(iced_capstone_scan_batch(64, core::ptr::null(), 1, ids.as_ptr(), ids.len(), out.as_mut_ptr(), 2), CapstoneScanResult::default());
		assert_eq!(iced_capstone_scan_batch(64, bytes.as_ptr(), 1, core::ptr::null(), ids.len(), out.as_mut_ptr(), 2), CapstoneScanResult::default());
		assert_eq!(iced_capstone_scan_batch(64, bytes.as_ptr(), 1, ids.as_ptr(), ids.len(), core::ptr::null_mut(), 2), CapstoneScanResult::default());
	}
	assert_eq!(out, [POISON; 2]);
}

#[test]
fn mapped_alignment_nops_preserve_prefix_length_and_validity() {
	let mut ids = vec![0u16; Code::values().len()];
	for code in [Code::Nopw, Code::Nopd, Code::Nopq, Code::Nop_rm16, Code::Nop_rm32, Code::Nop_rm64] {
		ids[code as usize] = 23;
	}
	for bits in [32, 64] {
		for bytes in [&[0x66, 0x90][..], &[0x2e, 0x0f, 0x1f, 0x00], &[0x66, 0x66, 0x2e, 0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0]] {
			let mut out = [POISON; 2];
			for length in 0..bytes.len() {
				assert_eq!(scan(bits, &bytes[..length], &ids, &mut out), 0);
			}
			assert_eq!(scan(bits, bytes, &ids, &mut out), 1);
			assert_eq!(out, [(23 << 8) | bytes.len() as u32, POISON]);
		}
		for bytes in [&[0x66, 0xf0, 0x90][..], &[0x66, 0xe8, 0, 0, 0, 0], &[0x2e, 0x89, 0xc1]] {
			let mut out = [POISON; 2];
			assert_eq!(scan(bits, bytes, &ids, &mut out), 0);
			assert_eq!(out, [POISON; 2]);
		}
	}
}

#[test]
fn mapped_prefixes_preserve_the_control_transfer_fallback() {
	let ids: Vec<u16> =
		Code::values().map(|c| (c as u16) | if c.flow_control() == FlowControl::Next { 0 } else { CAPSTONE_BATCH_PREFIX_SENSITIVE }).collect();
	for bits in [32, 64] {
		for bytes in [&[0x66, 0xe8, 0, 0, 0, 0][..], &[0x67, 0xe3, 0], &[0xf2, 0xeb, 0], &[0x2e, 0x0f, 0x85, 0, 0, 0, 0], &[0xf3, 0xc3]] {
			let mut out = [POISON; 2];
			assert_eq!(scan(bits, bytes, &ids, &mut out), 0);
			assert_eq!(out, [POISON; 2]);
		}
		for bytes in [&[0x66, 0x89, 0xc1][..], &[0x64, 0x8b, 0], &[0xf3, 0x0f, 0x10, 0], &[0x66, 0x0f, 0xef, 0xc0]] {
			let mut out = [POISON; 2];
			let instruction = Decoder::new(bits, bytes, DecoderOptions::NONE).decode();
			assert!(!instruction.is_invalid());
			for length in 0..bytes.len() {
				assert_eq!(scan(bits, &bytes[..length], &ids, &mut out), 0);
			}
			assert_eq!(scan(bits, bytes, &ids, &mut out), 1);
			assert_eq!(out[0], ((instruction.code() as u32) << 8) | bytes.len() as u32);
			assert_eq!(out[1], POISON);
		}
	}
}

#[test]
fn policy_flag_never_becomes_part_of_an_output_id() {
	let mut ids = vec![0u16; Code::values().len()];
	let mut out = [POISON; 2];
	ids[Code::Nopd as usize] = CAPSTONE_BATCH_PREFIX_SENSITIVE;
	assert_eq!(scan(64, &[0x90], &ids, &mut out), 0);
	assert_eq!(out, [POISON; 2]);
	ids[Code::Nopd as usize] |= 23;
	assert_eq!(scan(64, &[0x90], &ids, &mut out), 1);
	assert_eq!(out, [(23 << 8) | 1, POISON]);
	ids[Code::Nopw as usize] = 23 | CAPSTONE_BATCH_PREFIX_SENSITIVE;
	for bytes in [&[0x66, 0x90][..], &[0x40, 0x40, 0x90]] {
		out.fill(POISON);
		assert_eq!(scan(64, bytes, &ids, &mut out), 0);
		assert_eq!(out, [POISON; 2]);
	}
}
