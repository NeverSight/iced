// SPDX-License-Identifier: MIT
// Copyright (C) 2026 NeverSight and contributors
//! Allocation-free C boundary for the NeverSight Capstone compatibility profile.
use iced_x86::{Code, Decoder, DecoderOptions, DecoderScratch, Instruction, OpKind, Register};

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CapstoneInstruction {
	pub values: [u64; 5],
	pub displacement: u64,
	pub code: u32,
	pub registers: [u32; 5],
	pub kinds: [u32; 5],
	pub memory_base: u32,
	pub memory_index: u32,
	pub segment: u32,
	pub memory_size: u32,
	pub length: u8,
	pub op_count: u8,
	pub scale: u8,
	pub disp_offset: u8,
	pub disp_size: u8,
	pub imm_offset: u8,
	pub imm_size: u8,
	pub imm_offset2: u8,
	pub imm_size2: u8,
}

// Architectural maximum, independent of the caller's buffer size.
const MAX_INSTRUCTION_BYTES: usize = 15;

/// # Safety
/// bytes must point to at least min(length, 15) readable bytes when non-null.
#[no_mangle]
pub unsafe extern "C" fn iced_capstone_scan(bits: u32, bytes: *const u8, length: usize) -> u32 {
	if !matches!(bits, 16 | 32 | 64) || bytes.is_null() || length == 0 {
		return 0;
	}
	let input = unsafe { core::slice::from_raw_parts(bytes, length.min(MAX_INSTRUCTION_BYTES)) };
	let instruction = Decoder::new(bits, input, DecoderOptions::NONE).decode();
	if instruction.is_invalid() {
		0
	} else {
		((instruction.code() as u32) << 8) | instruction.len() as u32
	}
}

fn normalize_ud1(instruction: &mut Instruction) {
	// Intel SDM: 0F B9 /r is UD1 r32,r/m32, independent of 66 and REX.W.
	// Keep address size, displacement, length and invalid checks in the decoder.
	if matches!(instruction.code(), Code::Ud1_r16_rm16 | Code::Ud1_r64_rm64) {
		instruction.set_code(Code::Ud1_r32_rm32);
		instruction.set_op0_register(instruction.op0_register().full_register32());
		if instruction.op1_kind() == OpKind::Register {
			instruction.set_op1_register(instruction.op1_register().full_register32());
		}
	}
}

/// # Safety
/// bytes must point to at least min(length, 15) readable bytes when non-null.
/// out must point to writable, properly aligned CapstoneInstruction storage.
#[no_mangle]
pub unsafe extern "C" fn iced_capstone_decode(bits: u32, bytes: *const u8, length: usize, ip: u64, out: *mut CapstoneInstruction) -> u32 {
	if !matches!(bits, 16 | 32 | 64) || bytes.is_null() || out.is_null() || length == 0 {
		return 0;
	}
	let input = unsafe { core::slice::from_raw_parts(bytes, length.min(MAX_INSTRUCTION_BYTES)) };
	let mut decoder = Decoder::with_ip(bits, input, ip, DecoderOptions::NONE);
	let mut instruction = decoder.decode();
	if instruction.is_invalid() {
		return 0;
	}
	let offsets = decoder.get_constant_offsets(&instruction);
	normalize_ud1(&mut instruction);
	let mut result = CapstoneInstruction {
		code: instruction.code() as u32,
		length: instruction.len() as u8,
		op_count: instruction.op_count() as u8,
		scale: instruction.memory_index_scale() as u8,
		memory_base: instruction.memory_base() as u32,
		memory_index: instruction.memory_index() as u32,
		segment: instruction.segment_prefix() as u32,
		memory_size: instruction.memory_size().size() as u32,
		disp_offset: offsets.displacement_offset() as u8,
		disp_size: offsets.displacement_size() as u8,
		imm_offset: offsets.immediate_offset() as u8,
		imm_size: offsets.immediate_size() as u8,
		imm_offset2: offsets.immediate_offset2() as u8,
		imm_size2: offsets.immediate_size2() as u8,
		..CapstoneInstruction::default()
	};
	// iced represents RIP-relative displacement as a resolved target. Read its
	// original signed encoding to preserve the Capstone operand convention.
	result.displacement = instruction.memory_displacement64();
	if instruction.is_ip_rel_memory_operand() {
		let n = offsets.displacement_offset();
		let raw = i32::from_le_bytes(input[n..n + 4].try_into().unwrap());
		result.displacement = raw as i64 as u64;
	} else if offsets.displacement_size() != 0 && instruction.memory_base() != Register::None {
		// 16/32-bit address arithmetic in iced is modular; Capstone retains
		// the signed displacement. Compressed EVEX disp8 is already scaled.
		result.displacement = match instruction.memory_base().size() {
			2 => instruction.memory_displacement64() as u16 as i16 as i64 as u64,
			4 => instruction.memory_displacement64() as u32 as i32 as i64 as u64,
			_ => instruction.memory_displacement64(),
		};
	}
	for n in 0..instruction.op_count() {
		result.kinds[n as usize] = instruction.op_kind(n) as u32;
		result.registers[n as usize] = instruction.op_register(n) as u32;
		result.values[n as usize] = match instruction.op_kind(n) {
			OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => instruction.near_branch_target(),
			OpKind::FarBranch16 => instruction.far_branch16() as u64 | ((instruction.far_branch_selector() as u64) << 32),
			OpKind::FarBranch32 => instruction.far_branch32() as u64 | ((instruction.far_branch_selector() as u64) << 32),
			OpKind::Immediate8
			| OpKind::Immediate8_2nd
			| OpKind::Immediate16
			| OpKind::Immediate32
			| OpKind::Immediate64
			| OpKind::Immediate8to16
			| OpKind::Immediate8to32
			| OpKind::Immediate8to64
			| OpKind::Immediate32to64 => instruction.immediate(n),
			_ => 0,
		};
	}
	unsafe {
		out.write(result);
	}
	1
}

/// Creates per-consumer state; a handle must not be used concurrently.
#[no_mangle]
pub extern "C" fn iced_capstone_create(bits: u32) -> *mut DecoderScratch {
	match DecoderScratch::new(bits, DecoderOptions::NONE) {
		Ok(decoder) => Box::into_raw(Box::new(decoder)),
		Err(_) => core::ptr::null_mut(),
	}
}
/// # Safety
/// state is null or an unfreed handle returned by iced_capstone_create.
#[no_mangle]
pub unsafe extern "C" fn iced_capstone_destroy(state: *mut DecoderScratch) {
	if !state.is_null() {
		unsafe {
			drop(Box::from_raw(state));
		}
	}
}
/// # Safety
/// state is an exclusively used live handle. bytes covers min(length,15)
/// readable bytes for this call only; it is not retained after return.
#[no_mangle]
pub unsafe extern "C" fn iced_capstone_scan_with_state(state: *mut DecoderScratch, bytes: *const u8, length: usize) -> u32 {
	if state.is_null() || bytes.is_null() || length == 0 {
		return 0;
	}
	let input = unsafe { core::slice::from_raw_parts(bytes, length.min(MAX_INSTRUCTION_BYTES)) };
	let instruction = unsafe { &mut *state }.decode(input, 0);
	if instruction.is_invalid() {
		0
	} else {
		((instruction.code() as u32) << 8) | instruction.len() as u32
	}
}
