// SPDX-License-Identifier: MIT
// Copyright (C) 2026 NeverSight and contributors
// Regression inputs trace to the Capstone commits documented in ../README.md.
use iced_x86::*;
use iced_x86_capstone::*;

fn decode(bits: u32, bytes: &[u8]) -> Instruction {
	Decoder::with_ip(bits, bytes, 0x1234_50000, DecoderOptions::NONE).decode()
}
fn profile(bits: u32, bytes: &[u8]) -> CapstoneInstruction {
	let mut out = CapstoneInstruction::default();
	assert_eq!(unsafe { iced_capstone_decode(bits, bytes.as_ptr(), bytes.len(), 0x1234_50000, &mut out) }, 1);
	out
}
#[test]
fn lock_and_mov_cs_validity() {
	for bits in [16, 32, 64] {
		for op in [0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30] {
			for form in 0..4 {
				for reg in [false, true] {
					let bytes = [0xf0, op + form, if reg { 0xc2 } else { 0x02 }];
					assert_eq!(!decode(bits, &bytes).is_invalid(), form < 2 && !reg, "{bits} {bytes:x?}");
				}
			}
		}
		for prefix in [&[][..], &[0x66], &[0x67], &[0x64]] {
			for rm in [0x0a, 0xc8] {
				let mut bytes = prefix.to_vec();
				bytes.extend([0x8e, rm]);
				assert!(decode(bits, &bytes).is_invalid());
				bytes[prefix.len()] = 0x8c;
				assert!(!decode(bits, &bytes).is_invalid());
			}
		}
	}
}
#[test]
fn legacy_prefixes_before_vector_encodings() {
	for bits in [32, 64] {
		for prefix in [&[0x66][..], &[0xf2], &[0xf3], &[0xf0], &[0xf2, 0x2e]] {
			for body in [&[0xc5, 0xf8, 0x77][..], &[0x62, 0xf1, 0x7c, 0x08, 0x58, 0xc2], &[0x8f, 0xe9, 0x78, 0xe2, 0xc8]] {
				let mut bytes = prefix.to_vec();
				bytes.extend(body);
				assert!(decode(bits, &bytes).is_invalid(), "{bits} {bytes:x?}");
			}
		}
	}
	assert!(decode(64, &[0x48, 0xc5, 0xf8, 0x77]).is_invalid());
	assert_eq!(decode(64, &[0x48, 0x2e, 0xc5, 0xf8, 0x77]).code(), Code::VEX_Vzeroupper);
}
#[test]
fn evex_reserved_fields_and_gather_overlap() {
	for row in include_str!("evex-validity.txt").lines().filter(|s| !s.starts_with('#')) {
		let p: Vec<_> = row.split_whitespace().collect();
		let bytes: Vec<_> = p[2].as_bytes().chunks(2).map(|s| u8::from_str_radix(core::str::from_utf8(s).unwrap(), 16).unwrap()).collect();
		let i = decode(p[0].parse().unwrap(), &bytes);
		assert_eq!(!i.is_invalid(), p[1] == "1", "{row}");
		if !i.is_invalid() {
			assert_eq!(i.len(), bytes.len());
		}
	}
}
#[test]
fn last_segment_and_mandatory_address_prefix() {
	let prefixes = [0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65];
	let regs = [Register::ES, Register::CS, Register::SS, Register::DS, Register::FS, Register::GS];
	for bits in [32, 64] {
		for a in 0..6 {
			for b in 0..6 {
				for c in 0..6 {
					let bytes = [prefixes[a], prefixes[b], prefixes[c], 0x8b, 0x00];
					let i = decode(bits, &bytes);
					assert!(!i.is_invalid());
					let expected = if bits == 64 { [a, b, c].into_iter().rev().find(|n| *n >= 4).unwrap_or(c) } else { c };
					assert_eq!(i.segment_prefix(), regs[expected]);
				}
			}
		}
		for mandatory in [0xf2, 0xf3] {
			for opcode in [0x2c, 0x2d] {
				for bytes in [[0x67, mandatory, 0x0f, opcode, 0x00], [mandatory, 0x67, 0x0f, opcode, 0x00]] {
					let i = decode(bits, &bytes);
					assert!(!i.is_invalid());
					assert_eq!(i.memory_base(), if bits == 32 { Register::BX } else { Register::EAX });
					assert_eq!(i.memory_index(), if bits == 32 { Register::SI } else { Register::None });
				}
			}
		}
	}
}
#[test]
fn consumed_displacement_and_far_immediate_extents() {
	for bits in [16, 32, 64] {
		for address_override in [false, true] {
			let a16 = (bits == 16) != address_override && bits != 64;
			for opcode in [&[0x66, 0x8b][..], &[0xc5, 0xf9, 0x5a], &[0x62, 0xf1, 0xfd, 0x48, 0x5a]] {
				for (modrm, size) in [(0x00, 0usize), (0x40, 1), (0x80, if a16 { 2 } else { 4 })] {
					let mut bytes = Vec::new();
					if address_override {
						bytes.push(0x67)
					}
					bytes.extend(opcode);
					bytes.push(modrm);
					let offset = if size == 0 { 0 } else { bytes.len() };
					bytes.extend(std::iter::repeat(0xff).take(size));
					let i = profile(bits, &bytes);
					assert_eq!(i.length as usize, bytes.len());
					assert_eq!(i.disp_offset as usize, offset);
					assert_eq!(i.disp_size as usize, size);
				}
			}
		}
	}
	for bits in [16, 32] {
		for pref in [false, true] {
			for opcode in [0x9a, 0xea] {
				let wide = (bits == 32) != pref;
				let mut b = Vec::new();
				if pref {
					b.push(0x66)
				}
				b.push(opcode);
				b.extend([0x34, 0x12]);
				if wide {
					b.extend([0x78, 0x56])
				}
				b.extend([0xbc, 0x9a]);
				let i = profile(bits, &b);
				assert_eq!(i.length as usize, b.len());
				assert_eq!(i.imm_offset, if pref { 2 } else { 1 });
				assert_eq!(i.imm_size, if wide { 4 } else { 2 });
				assert_eq!(i.imm_offset2, i.imm_offset + i.imm_size);
				assert_eq!(i.imm_size2, 2);
				for n in 0..b.len() {
					assert!(decode(bits, &b[..n]).is_invalid());
				}
			}
		}
	}
}
#[test]
fn x87_environment_rex_w_selects_full_format() {
	let mut factory = InstructionInfoFactory::new();
	for bits in [16, 32, 64] {
		for pref in [false, true] {
			for rex in [false, true] {
				if rex && bits != 64 {
					continue;
				}
				for (op, rm, state, access) in [
					(0xd9, 0x30, false, OpAccess::Write),
					(0xd9, 0x20, false, OpAccess::Read),
					(0xdd, 0x30, true, OpAccess::Write),
					(0xdd, 0x20, true, OpAccess::Read),
				] {
					let mut b = Vec::new();
					if pref {
						b.push(0x66)
					}
					if rex {
						b.push(0x48)
					}
					b.extend([op, rm]);
					let i = decode(bits, &b);
					let short = ((bits == 16) != pref) && !rex;
					assert_eq!(i.memory_size().size(), if short { 14 } else { 28 } + if state { 80 } else { 0 });
					assert_eq!(factory.info(&i).op0_access(), access);
				}
			}
		}
	}
	assert_eq!(decode(64, &[0x48, 0x66, 0xd9, 0x30]).memory_size().size(), 14);
}
#[test]
fn ud1_profile_preserves_extent_and_uses_r32_operands() {
	for bits in [16, 32, 64] {
		for pref in [&[][..], &[0x66], &[0x67]] {
			let mut b = pref.to_vec();
			b.extend([0x0f, 0xb9, 0xc1]);
			let i = profile(bits, &b);
			assert_eq!(i.code, Code::Ud1_r32_rm32 as u32);
			assert_eq!(i.registers[0], Register::EAX as u32);
			assert_eq!(i.registers[1], Register::ECX as u32);
			assert_eq!(i.length as usize, b.len());
			for n in 0..b.len() {
				assert!(decode(bits, &b[..n]).is_invalid());
			}
		}
	}
	let b = [0x66, 0x4d, 0x0f, 0xb9, 0x8c, 0x9a, 0x80, 0xff, 0xff, 0xff];
	let i = profile(64, &b);
	assert_eq!(i.registers[0], Register::R9D as u32);
	assert_eq!(i.memory_size, 4);
	assert_eq!(i.memory_base, Register::R10 as u32);
	assert_eq!(i.memory_index, Register::RBX as u32);
	assert_eq!(i.displacement as i64, -128);
	assert_eq!((i.disp_offset, i.disp_size), (6, 4));
}
#[test]
fn jump_vendor_mode_and_sse_family() {
	let b = [0x66, 0xe9, 0xfe, 0xff, 0xff, 0xff];
	for (opt, len, target) in [(DecoderOptions::NONE, 6, 0x1234_50004), (DecoderOptions::AMD, 4, 2)] {
		let i = Decoder::with_ip(64, &b, 0x1234_50000, opt).decode();
		assert_eq!(i.len(), len);
		assert_eq!(i.near_branch_target(), target);
	}
	for options in [DecoderOptions::NONE, DecoderOptions::AMD] {
		for opcode in [0x80, 0x81] {
			let b = [0x66, 0x0f, opcode, 1, 0, 0, 0];
			let i = Decoder::with_ip(64, &b, 0x1000, options).decode();
			assert_eq!(i.len(), if options == DecoderOptions::AMD { 5 } else { 7 });
		}
		for (prefix, wide) in [(&[0x66][..], false), (&[0x66, 0x48], true), (&[0x48, 0x66], false)] {
			let mut b = prefix.to_vec();
			b.push(0xc3);
			let i = Decoder::with_ip(64, &b, 0x1000, options).decode();
			assert_eq!(i.code(), if options == DecoderOptions::AMD && !wide { Code::Retnw } else { Code::Retnq });
			assert_eq!(i.len(), b.len());
		}
	}
	for (pref, mnemonic) in
		[(&[][..], Mnemonic::Cmpps), (&[0x66][..], Mnemonic::Cmppd), (&[0xf2][..], Mnemonic::Cmpsd), (&[0xf3][..], Mnemonic::Cmpss)]
	{
		for pred in 0..=255 {
			let mut b = pref.to_vec();
			b.extend([0x0f, 0xc2, 0xc1, pred]);
			let i = decode(64, &b);
			assert_eq!(i.mnemonic(), mnemonic);
			assert_eq!(i.immediate8(), pred);
		}
	}
}
#[test]
fn ffi_invalid_inputs_preserve_output() {
	let mut out = CapstoneInstruction { code: 123, ..Default::default() };
	let old = out;
	for bits in [0, 16, 32, 64, 128] {
		assert_eq!(unsafe { iced_capstone_decode(bits, core::ptr::null(), 0, 0, &mut out) }, 0);
		assert_eq!(unsafe { iced_capstone_scan(bits, core::ptr::null(), usize::MAX) }, 0);
		assert_eq!(out, old);
	}
	assert_eq!(unsafe { iced_capstone_decode(64, [0x0f].as_ptr(), 1, 0, &mut out) }, 0);
	assert_eq!(out, old);
}

#[test]
fn access_flags_and_legacy_escape_ownership() {
	let mut f = InstructionInfoFactory::new();
	for bits in [32, 64] {
		for b in [&[0x0f, 0xa4, 0xc8, 3][..], &[0x0f, 0xac, 0xc8, 3]] {
			let i = decode(bits, b);
			let info = f.info(&i);
			assert_eq!(info.op0_access(), OpAccess::ReadWrite);
			assert_eq!(info.op1_access(), OpAccess::Read);
		}
		for b in [&[0xc5, 0xf8, 0x5a, 0x00][..], &[0xc5, 0xf9, 0x5a, 0x00]] {
			let i = decode(bits, b);
			let info = f.info(&i);
			assert_eq!(info.op0_access(), OpAccess::Write);
			assert_eq!(info.op1_access(), OpAccess::Read);
		}
		let i = decode(bits, &[0xf7, 0x00, 1, 0, 0, 0]);
		let info = f.info(&i);
		assert_eq!(info.op0_access(), OpAccess::Read);
		assert_eq!(i.rflags_cleared(), RflagsBits::CF | RflagsBits::OF);
		assert_eq!(i.rflags_undefined(), RflagsBits::AF);
	}
	for (b, m) in [(&[0xc4, 0x00][..], Mnemonic::Les), (&[0xc5, 0x00][..], Mnemonic::Lds), (&[0x62, 0x00][..], Mnemonic::Bound)] {
		assert_eq!(decode(32, b).mnemonic(), m);
		assert!(decode(64, b).is_invalid());
	}
	for zero in [0, 0x80] {
		let b = [0x62, 0xf3, 0xed, 0x5a | zero, 0xce, 0x48, 0xff, 1];
		let i = decode(64, &b);
		assert!(!i.is_invalid());
		assert!(i.is_broadcast());
		assert_eq!(i.memory_size().size(), 8);
		assert_eq!(i.memory_displacement64() as i64, -8);
		assert!(f.info(&i).used_registers().iter().any(|r| r.register() == Register::K2 && r.access() == OpAccess::Read));
	}
}

#[test]
fn new_extensions_request_fallback_and_abi_layout_is_fixed() {
	assert_eq!(core::mem::size_of::<CapstoneInstruction>(), 120);
	assert_eq!(core::mem::align_of::<CapstoneInstruction>(), core::mem::align_of::<u64>());
	for bytes in [&[0xd5, 0x58, 0x31, 0x02][..], &[0x62, 0xf1, 0x78, 0x48, 0x58, 0x04, 0x0c]] {
		assert_eq!(unsafe { iced_capstone_scan(64, bytes.as_ptr(), bytes.len()) }, 0);
	}
}
