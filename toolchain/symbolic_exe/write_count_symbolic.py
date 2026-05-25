#!/usr/bin/env python3
"""
MSP430 symbolic execution: path-sensitive write-count profiling using P-code STORE.
"""
import argparse
import subprocess
import re
from collections import defaultdict, deque

import angr
import claripy
import pypcode

from angr_platforms.msp430 import arch_msp430

OUTPUT_FILE = "write_count_profile.txt"
DISASM_OUTPUT_FILE = "disassembly_debug.txt"

REG_MAP = {
    0x0: "pc", 0x4: "sp", 0x8: "sr", 0xc: "cg",
    0x10: "r4", 0x14: "r5", 0x18: "r6", 0x1c: "r7",
    0x20: "r8", 0x24: "r9", 0x28: "r10", 0x2c: "r11",
    0x30: "r12", 0x34: "r13", 0x38: "r14", 0x3c: "r15",
}

label = "((-|\+)?\s*(?!(\s*R(1[0-5]|[0-9])|PC|SR|SP))(\.?\w(\w|\.)*))"
address = "((-|\+)?\s*(0x[\da-f]+|[\da-f]+h|\d+))"
mathOp = "(\s*((-|\+)\s*(0x[\da-f]+|[\da-f]+h|\d+)))*"

regMode = "(R(1[0-5]|[0-9])|PC|SR|SP)"
offsetPart_IndexMode = "(({}|{}){})".format(address, label, mathOp)
registerPart_IndexMode = "(R(1[0-5]|[13-9]))"
indexMode = "(\s?{}\s*\(\s*{}\s*\))".format(offsetPart_IndexMode, registerPart_IndexMode)

registerPart_IndrectMode = "(R\d\d?)"
indirectMode = "(@\s*{}?\+?)".format(registerPart_IndrectMode)

offsetPart_SymbolicMode = "(({}|{}){})".format(address, label, mathOp)
symbolicMode = "({}(\s*\((R0|PC)\))?)".format(offsetPart_SymbolicMode)

normalSyntax = "(&\s*(({}|{}){}))".format(address, label, mathOp)
registerSyntax = "((({}|{}){})\s*\((R2|SR)\))".format(address, label, mathOp)
absoluteMode = "({}|{})".format(normalSyntax, registerSyntax)

immediateMode = "(#\s*(({}|{}){}))".format(label, address, mathOp)

plusOneMode = "({}|{}|{}|{})".format(indexMode, absoluteMode, immediateMode, symbolicMode)
plusOneModeNoImm = "({}|{}|{})".format(indexMode, absoluteMode, symbolicMode)
plusZeroMode = "({}|{})".format(regMode, indirectMode)

writeMov = re.compile(
    "MOV(.W)?\s+({}|{})\s*,\s*({}|{})\s+".format(
        plusOneMode, plusZeroMode, plusOneModeNoImm, indirectMode
    ),
    re.I,
)
writeMovx = re.compile(
    "MOVX(.W)?\s+({}|{})\s*,\s*({}|{})\s+".format(
        plusOneMode, plusZeroMode, plusOneModeNoImm, indirectMode
    ),
    re.I,
)
writePop = re.compile("POP(.W)?\s+({}|{})\s+".format(plusOneModeNoImm, indirectMode), re.I)
writePopx = re.compile("POPX(.W)?\s+({}|{})\s+".format(plusOneModeNoImm, indirectMode), re.I)
writePush = re.compile("PUSH(.W)?\s+({}|{})\s+".format(plusOneMode, plusZeroMode), re.I)
writePushx = re.compile("PUSHX(.W)?\s+({}|{})\s+".format(plusOneMode, plusZeroMode), re.I)


def is_mem_write_insn(mnem, body):
    insn = f"{mnem} {body}".strip()
    return (
        writeMov.match(insn)
        or writeMovx.match(insn)
        or writePop.match(insn)
        or writePopx.match(insn)
        or writePush.match(insn)
        or writePushx.match(insn)
    )


def extract_sections(elf_path, out_path):
    objcopy = "../../toolchain/compiler/msp430-gcc-9.2.0.50_linux64_original/bin/msp430-elf-objcopy"
    subprocess.run(
        [objcopy, "-O", "binary", "-j", ".lowtext", "-j", ".text", elf_path, out_path],
        check=True,
    )
    print("OK: code sections extracted")


def disassemble_full(bin_path, base_addr):
    ctx = pypcode.Context("TI_MSP430X:LE:32:default")
    with open(bin_path, "rb") as f:
        data = f.read()

    instructions, off = {}, 0
    with open(DISASM_OUTPUT_FILE, "w", encoding="utf-8") as df:
        df.write("=" * 80 + "\n")
        df.write("MSP430 Disassembly with P-code\n")
        df.write(f"Code base: 0x{base_addr:04x}\n")
        df.write("=" * 80 + "\n\n")

        while off < len(data):
            addr = base_addr + off
            try:
                dis = ctx.disassemble(data[off:off + 12], addr)
                if not dis.instructions:
                    off += 2
                    continue

                insn = dis.instructions[0]
                pcode = ctx.translate(data[off:off + insn.length], addr, max_instructions=1)

                ops = []
                imark_cnt = 0
                for op in pcode.ops:
                    if op.opcode == pypcode.OpCode.IMARK:
                        imark_cnt += 1
                        if imark_cnt == 1:
                            continue
                    ops.append(op)

                branch_target = None
                if insn.mnem.upper() in ["JEQ", "JNE", "JZ", "JNZ", "JC", "JNC", "JL", "JGE", "JMP", "JHS", "JLO", "BRA"]:
                    match = re.search(r"0x([0-9a-fA-F]+)", insn.body)
                    if match:
                        branch_target = int(match.group(1), 16)

                instructions[addr] = (insn.mnem, insn.body, insn.length, ops, branch_target)

                df.write(f"0x{addr:04x}: {insn.mnem:12s} {insn.body:30s} (len={insn.length})")
                if branch_target is not None:
                    df.write(f" -> 0x{branch_target:04x}")
                df.write("\n")
                for op in ops:
                    df.write(f"          {str(op.opcode):20s}\n")
                df.write("\n")

                off += insn.length
            except Exception:
                off += 2

    print(f"OK: disassembled {len(instructions)} instructions")
    return instructions


def _parse_imm_target(body_text):
    match = re.search(r"#0x([0-9a-fA-F]+)", body_text or "")
    return int(match.group(1), 16) if match else None


def merge_continuous_pairs(values):
    if not values:
        return []
    sorted_vals = sorted(values)
    start = sorted_vals[0]
    end = sorted_vals[0]
    pairs = []
    for val in sorted_vals[1:]:
        if val == end + 1:
            end = val
        else:
            pairs.append((start, end))
            start = val
            end = val
    pairs.append((start, end))
    return pairs


def read_vn(state, vn, temp_vars):
    sp, sb = vn.space.name, vn.size * 8
    if sp == "register":
        reg_name = REG_MAP.get(vn.offset, f"r_{vn.offset:x}")
        v = state.registers.load(reg_name, vn.size)
        if v.size() < sb:
            return claripy.ZeroExt(sb - v.size(), v)
        if v.size() > sb:
            return claripy.Extract(sb - 1, 0, v)
        return v
    if sp == "RAM":
        return state.memory.load(vn.offset, vn.size, endness="Iend_LE")
    if sp == "const":
        return claripy.BVV(vn.offset, sb)
    if sp == "unique":
        key = ("unique", vn.offset, vn.size)
        if key not in temp_vars:
            temp_vars[key] = claripy.BVS(f"tmp_{vn.offset:x}", sb)
        return temp_vars[key]
    raise NotImplementedError(f"read {sp}")


def write_vn(state, vn, val, temp_vars):
    sp, tb = vn.space.name, vn.size * 8
    if sp == "register":
        if val.size() < tb:
            val = claripy.ZeroExt(tb - val.size(), val)
        elif val.size() > tb:
            val = claripy.Extract(tb - 1, 0, val)
        reg_name = REG_MAP.get(vn.offset, f"r_{vn.offset:x}")
        state.registers.store(reg_name, val)
    elif sp == "RAM":
        state.memory.store(vn.offset, val, endness="Iend_LE")
    elif sp == "unique":
        temp_vars[("unique", vn.offset, vn.size)] = val


def execute_instruction(state, addr, ops, instructions, skip_call_targets):
    temp_vars = {}
    mnem, body, length, _, branch_target = instructions[addr]
    next_addr = addr + length
    call_target = None
    branch_info = None
    sp_before = state.regs.sp

    for op in ops:
        if op.opcode == pypcode.OpCode.IMARK:
            continue

        if op.opcode == pypcode.OpCode.COPY:
            val = read_vn(state, op.inputs[0], temp_vars)
            write_vn(state, op.output, val, temp_vars)

        elif op.opcode == pypcode.OpCode.LOAD:
            ptr = read_vn(state, op.inputs[1], temp_vars)
            val = state.memory.load(ptr, op.output.size, endness="Iend_LE")
            write_vn(state, op.output, val, temp_vars)

        elif op.opcode == pypcode.OpCode.STORE:
            ptr = read_vn(state, op.inputs[1], temp_vars)
            val = read_vn(state, op.inputs[2], temp_vars)
            state.memory.store(ptr, val, endness="Iend_LE")

        elif op.opcode == pypcode.OpCode.BRANCH:
            if mnem.upper() in ["BRA", "JMP"] and branch_target is not None:
                next_addr = branch_target
            else:
                target = read_vn(state, op.inputs[0], temp_vars)
                if not state.solver.symbolic(target):
                    next_addr = state.solver.eval(target)

        elif op.opcode == pypcode.OpCode.CBRANCH:
            cond = read_vn(state, op.inputs[1], temp_vars)
            branch_info = (cond, branch_target)

        elif op.opcode == pypcode.OpCode.BRANCHIND:
            target = read_vn(state, op.inputs[0], temp_vars)
            if not state.solver.symbolic(target):
                next_addr = state.solver.eval(target)

        elif op.opcode == pypcode.OpCode.CALL:
            pass

        elif op.opcode == pypcode.OpCode.CALLIND:
            call_target = read_vn(state, op.inputs[0], temp_vars)

        elif op.opcode == pypcode.OpCode.RETURN:
            sp_val = state.regs.sp
            ret_addr = state.memory.load(sp_val, 4, endness="Iend_LE")
            if ret_addr.size() > 16:
                ret_addr = claripy.Extract(15, 0, ret_addr)
            if not state.solver.symbolic(ret_addr):
                next_addr = state.solver.eval(ret_addr)
            state.regs.sp = sp_val + claripy.BVV(4, sp_val.size())

    if mnem.upper() in ["CALL", "CALLA"]:
        target_addr = None
        if call_target is not None and not state.solver.symbolic(call_target):
            target_addr = state.solver.eval(call_target)
        else:
            target_addr = _parse_imm_target(body)

        if target_addr is not None and target_addr in skip_call_targets:
            return [(state, next_addr)], True

        if target_addr is not None:
            ret_addr_bv = claripy.BVV(next_addr, 32)
            new_sp = sp_before - claripy.BVV(4, sp_before.size())
            state.regs.sp = new_sp
            state.memory.store(new_sp, ret_addr_bv, endness="Iend_LE")
            return [(state, target_addr)], True

    if branch_info is not None:
        cond, target_addr = branch_info
        if state.solver.symbolic(cond):
            state_taken = state.copy()
            state_taken.solver.add(cond != 0)

            state_fall = state.copy()
            state_fall.solver.add(cond == 0)

            results = []
            if state_taken.solver.satisfiable():
                results.append((state_taken, target_addr))
            if state_fall.solver.satisfiable():
                results.append((state_fall, next_addr))
            return results, True

        cond_val = state.solver.eval(cond)
        if cond_val != 0:
            return [(state, target_addr)], True

    return [(state, next_addr)], True


def main():
    parser = argparse.ArgumentParser(description="MSP430 write-count profiling using assembly patterns")
    parser.add_argument("elf_file", help="Input ELF file path")
    parser.add_argument("--code-base", default="0x4406", help="Code base address")
    parser.add_argument("--entry", default="0x4584", help="Entry address (main)")
    parser.add_argument("--max-steps", type=int, default=200000, help="Max total steps")
    parser.add_argument("--max-steps-per-path", type=int, default=2000, help="Max steps per path")
    parser.add_argument("--skip-call", action="append", default=[], help="Call targets to skip (hex)")
    parser.add_argument("--out", default=OUTPUT_FILE, help="Output file")
    args = parser.parse_args()

    code_base = int(args.code_base, 0)
    entry_addr = int(args.entry, 0)
    skip_call_targets = {int(v, 0) for v in args.skip_call}

    extract_sections(args.elf_file, "apptext.bin")
    instructions = disassemble_full("apptext.bin", code_base)

    proj = angr.Project(
        "apptext.bin",
        arch="MSP430",
        main_opts={"backend": "blob", "base_addr": code_base, "entry_point": code_base},
        auto_load_libs=False,
    )

    state0 = proj.factory.blank_state(addr=entry_addr, add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY})
    state0.regs.sp = claripy.BVV(0x4400, 16)
    state0.regs.pc = claripy.BVV(entry_addr, 16)
    state0.globals["write_count"] = 0

    write_count_sets = defaultdict(set)
    worklist = deque()
    path_counter = 0
    worklist.append((state0, entry_addr, 0, set(), path_counter))
    path_counter += 1

    total_steps = 0

    while worklist and total_steps < args.max_steps:
        state, pc, step_count, visited, path_id = worklist.popleft()

        state_hash = (pc, step_count % 50)
        if state_hash in visited:
            continue
        visited = visited | {state_hash}

        if pc not in instructions:
            continue
        if step_count >= args.max_steps_per_path:
            continue

        mnem, body, _, ops, _ = instructions[pc]
        mnem_u = mnem.upper()

        if is_mem_write_insn(mnem, body):
            state.globals["write_count"] = state.globals.get("write_count", 0) + 1

        if mnem_u in ["CALL", "CALLA", "RETURN", "RET", "RETA"]:
            w = state.globals.get("write_count", 0)
            write_count_sets[pc].add(w)

        results, ok = execute_instruction(state, pc, ops, instructions, skip_call_targets)
        if not ok:
            continue

        for new_state, next_pc in results:
            new_state.regs.pc = claripy.BVV(next_pc, 16)
            if len(results) > 1:
                new_path_id = path_counter
                path_counter += 1
            else:
                new_path_id = path_id
            worklist.append((new_state, next_pc, step_count + 1, visited, new_path_id))

        total_steps += 1

    call_idx = 0
    ret_idx = 0
    with open(args.out, "w", encoding="utf-8") as f:
        for addr in sorted(write_count_sets.keys()):
            pairs = merge_continuous_pairs(write_count_sets[addr])
            ranges = ", ".join([f"{a}--{b}" for a, b in pairs])
            mnem = instructions.get(addr, ("", "", 0, None, None))[0].upper()
            if mnem in ["RETURN", "RET", "RETA"]:
                ret_idx += 1
                f.write(f"ret{ret_idx}: {ranges}\n")
            else:
                call_idx += 1
                f.write(f"call{call_idx}: {ranges}\n")

    print(f"OK: write-count profile written to {args.out}")


if __name__ == "__main__":
    main()

