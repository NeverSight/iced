// SPDX-License-Identifier: MIT
// Copyright (C) 2026 NeverSight and contributors
use iced_x86::{Decoder, DecoderOptions, DecoderScratch, Instruction};
use iced_x86_capstone::{iced_capstone_create, iced_capstone_destroy, iced_capstone_scan, iced_capstone_scan_with_state};

fn compare(scratch: &mut DecoderScratch, bits: u32, options: u32, bytes: &[u8], ip: u64, out: &mut Instruction) {
	let mut fresh = Decoder::with_ip(bits, bytes, ip, options);
	let expected = fresh.decode();
	let (error, offsets) = scratch.decode_with_offsets(bytes, ip, out);
	assert!(out.eq_all_bits(&expected), "bits={bits} options={options} ip={ip:x} bytes={bytes:x?}");
	assert_eq!(error, fresh.last_error());
	assert_eq!(offsets, fresh.get_constant_offsets(&expected));
	// Reuse both a decoder and nonempty output storage; the no-offset entry point
	// must have the same reset semantics after an invalid or prefixed instruction.
	assert_eq!(scratch.decode_out(bytes, ip, out), error);
	assert!(out.eq_all_bits(&expected));
	assert!(scratch.decode(bytes, ip).eq_all_bits(&expected));
}

#[test]
fn independent_windows_match_fresh_decoder() {
	let mut random = 0x7317_a319_2946_e55bu64;
	for bits in [16, 32, 64] {
		for options in [DecoderOptions::NONE, DecoderOptions::AMD, DecoderOptions::NO_INVALID_CHECK] {
			let mut scratch = DecoderScratch::new(bits, options).unwrap();
			let mut out = Instruction::default();
			for n in 0..100_000 {
				// Reallocate, shift the start, and destroy each previous buffer. A
				// scratch instance may retain mode/tables, never a caller's input.
				let mut allocation = vec![0u8; 64];
				for byte in &mut allocation {
					random ^= random << 13;
					random ^= random >> 7;
					random ^= random << 17;
					*byte = random as u8;
				}
				let start = n % 32;
				let len = n % 33;
				compare(&mut scratch, bits, options, &allocation[start..start + len], random, &mut out);
			}
		}
	}
}

#[test]
fn prefix_modrm_and_truncation_state_is_reset() {
	for bits in [16, 32, 64] {
		let mut scratch = DecoderScratch::new(bits, DecoderOptions::NONE).unwrap();
		let mut out = Instruction::default();
		for prefix in [&[][..], &[0x66], &[0x67], &[0x64, 0x65], &[0x48], &[0x48, 0x66], &[0x66, 0x48]] {
			for opcode in 0..=255 {
				for modrm in 0..=255 {
					let mut bytes = prefix.to_vec();
					bytes.extend([opcode, modrm]);
					bytes.resize(15, 0xff);
					compare(&mut scratch, bits, DecoderOptions::NONE, &bytes, u64::MAX - 4, &mut out);
				}
			}
		}
		for bytes in [
			&[0x66; 16][..],
			&[0x62, 0xf1, 0x7c, 0x48, 0x58, 0x44, 0x88, 0xff],
			&[0xc4, 0xe2, 0x6d, 0x90, 0x04, 0x0b],
			&[0x48, 0x8b, 0x05, 0x80, 0xff, 0xff, 0xff],
			&[0xf0, 0xf3, 0x01, 0x18],
			&[0x9a, 1, 2, 3, 4, 5, 6],
		] {
			for len in 0..=bytes.len() {
				compare(&mut scratch, bits, DecoderOptions::NONE, &bytes[..len], 0xffff_fff8, &mut out);
				compare(&mut scratch, bits, DecoderOptions::NONE, &[0x90], 0, &mut out);
			}
		}
	}
}

#[test]
fn ffi_handles_are_independent_and_validate_null_inputs() {
	assert!(iced_capstone_create(0).is_null());
	assert!(iced_capstone_create(128).is_null());
	let contexts = [16, 32, 64].map(|bits| iced_capstone_create(bits));
	assert!(contexts.iter().all(|p| !p.is_null()));
	for bytes in [&[0x48, 0x89, 0xd8][..], &[0x0f], &[0xf0, 0x90], &[0x67, 0xe3, 0xfe], &[0x90], &[]] {
		for (bits, context) in [16, 32, 64].into_iter().zip(contexts) {
			unsafe {
				assert_eq!(
					iced_capstone_scan_with_state(context, bytes.as_ptr(), bytes.len()),
					iced_capstone_scan(bits, bytes.as_ptr(), bytes.len())
				);
				assert_eq!(iced_capstone_scan_with_state(context, core::ptr::null(), usize::MAX), 0);
			}
		}
	}
	unsafe {
		assert_eq!(iced_capstone_scan_with_state(core::ptr::null_mut(), core::ptr::null(), 0), 0);
		iced_capstone_destroy(core::ptr::null_mut());
		for context in contexts {
			iced_capstone_destroy(context);
		}
	}
}
