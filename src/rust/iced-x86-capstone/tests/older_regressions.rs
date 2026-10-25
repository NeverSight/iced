// SPDX-License-Identifier: MIT
// Copyright (C) 2026 NeverSight and contributors
// Earlier Capstone history: 511ba599 through c00aa8ae (May–September 2026).
use iced_x86::*;

fn decode(bits: u32, bytes: &[u8]) -> Instruction {
	Decoder::with_ip(bits, bytes, 0x1000, DecoderOptions::NONE).decode()
}

#[test]
fn evex_compare_length_and_sae() {
	for (scalar, p1) in [(true, 0x6e), (true, 0xef), (false, 0x6c), (false, 0xed)] {
		for ll in 0..4 {
			for reg in [false, true] {
				for b in [false, true] {
					for mask in [0, 2] {
						let bytes = [0x62, 0xf1, p1, 8 | (ll << 5) | if b { 16 } else { 0 } | mask, 0xc2, if reg { 0xcb } else { 0x0b }, 0];
						let valid = !(scalar && b && !reg) && (ll != 3 || (b && reg));
						let i = decode(64, &bytes);
						assert_eq!(!i.is_invalid(), valid, "{bytes:x?}");
						if valid {
							assert_eq!(i.len(), bytes.len());
							assert_eq!(i.suppress_all_exceptions(), b && reg);
							let width = if scalar {
								16
							} else if b && reg {
								64
							} else {
								16 << ll
							};
							assert_eq!(i.op1_register().size(), width);
							assert_eq!(i.rounding_control(), RoundingControl::None);
						}
					}
				}
			}
		}
	}
}

#[test]
fn normalization_does_not_read_following_instruction() {
	for bytes in [
		&[0x62, 0xf2, 0x4d, 0x28, 0xcb, 0xef][..],
		&[0x62, 0xf2, 0x7d, 0x28, 0x4d, 0xca],
		&[0x62, 0xf3, 0x7d, 0x29, 0x67, 0xda, 0xff],
		&[0x62, 0xf2, 0x5f, 0x28, 0x9b, 0x08],
		&[0x64, 0x62, 0xf2, 0x4d, 0x28, 0xcb, 0x28],
		&[0x64, 0x62, 0xf2, 0x7d, 0x28, 0x4d, 0x08],
		&[0x64, 0x62, 0xf3, 0x7d, 0x29, 0x67, 0x1a, 0xff],
		&[0x64, 0x62, 0xf2, 0x5f, 0x28, 0x9b, 0x08],
		&[0x8b, 0x45, 0xf4],
		&[0x90],
	] {
		let expected = decode(64, bytes);
		assert!(!expected.is_invalid());
		assert_eq!(expected.len(), bytes.len());
		let mut extended = bytes.to_vec();
		extended.extend([0x05, 0x17, 0xc0, 0x62, 0xe1, 0x89, 0x45, 0xf4, 0xe9, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90]);
		assert!(expected.eq_all_bits(&decode(64, &extended)));
	}
	for bits in [16, 32] {
		assert_eq!(decode(bits, &[0x40, 0x62, 0xf4, 0x7c, 8, 0, 0xd9]).len(), 1);
		assert_eq!(decode(bits, &[0x62, 2, 5, 0x60, 0xcb, 0xc0]).code(), if bits == 16 { Code::Bound_r16_m1616 } else { Code::Bound_r32_m3232 });
	}
}

#[test]
fn legacy_width_access_and_implicit_operands() {
	let mut factory = InstructionInfoFactory::new();
	for bits in [16, 32, 64] {
		for override_address in [false, true] {
			let counter = match (bits, override_address) {
				(16, false) | (32, true) => Register::CX,
				(64, false) => Register::RCX,
				_ => Register::ECX,
			};
			for opcode in [0xe0, 0xe1, 0xe2] {
				let mut bytes = Vec::new();
				if override_address {
					bytes.push(0x67);
				}
				bytes.extend([opcode, 0xfe]);
				let i = decode(bits, &bytes);
				assert!(!i.is_invalid());
				assert!(factory.info(&i).used_registers().iter().any(|r| r.register() == counter));
			}
		}
	}
	for prefix in [&[][..], &[0x66], &[0x67], &[0x66, 0x67]] {
		let mut bytes = prefix.to_vec();
		bytes.extend([0x63, 0x20]);
		let i = decode(64, &bytes);
		assert!(!i.is_invalid());
		// XED agrees that 66 MOVSXD reads a 16-bit source, not a dword.
		assert_eq!(i.memory_size().size(), if prefix.contains(&0x66) { 2 } else { 4 });
	}
	for rm in [0x23, 0x13] {
		let i = decode(64, &[0xd3, rm]);
		assert_eq!(i.op1_register(), Register::CL);
		assert_eq!(factory.info(&i).op1_access(), OpAccess::Read);
	}
	assert_eq!(decode(64, &[0x83, 0xf8, 0xab]).immediate8to32(), -0x55);
	assert_eq!(decode(64, &[0x6a, 0x48]).op0_kind(), OpKind::Immediate8to64);
	assert_eq!(decode(32, &[0xd4, 0x59]).op0_kind(), OpKind::Immediate8);
	let i = decode(64, &[0xc5, 0xf8, 0x11, 0x28]);
	assert_eq!(factory.info(&i).op0_access(), OpAccess::Write);
	assert_eq!(factory.info(&i).op1_access(), OpAccess::Read);
}

#[test]
fn vp4_dot_product_tuple_is_distinct_from_destination_width() {
	let mut factory = InstructionInfoFactory::new();
	for opcode in [0x52, 0x53] {
		for p2 in [0x42, 0xc2] {
			let i = decode(64, &[0x62, 0xf2, 0x5f, p2, opcode, 0x08]);
			assert!(!i.is_invalid());
			assert_eq!(i.op0_register().size(), 64);
			assert_eq!(i.memory_size().size(), 16);
			assert_eq!(i.op_mask(), Register::K2);
			assert!(factory.info(&i).used_registers().iter().any(|r| r.register() == Register::K2 && r.access() == OpAccess::Read));
		}
	}
}
