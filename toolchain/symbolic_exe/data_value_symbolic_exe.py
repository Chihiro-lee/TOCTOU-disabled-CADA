# ...existing code...
#!/usr/bin/env python3
"""
MSP430 Symbolic Execution Engine with pypcode
Monitors R5 register values at specified addresses
Based on IDA disassembly of DF_attack_local_noatk.out
"""
import angr, claripy, pypcode, argparse, subprocess
import math
from collections import defaultdict, deque
from angr_platforms.msp430 import arch_msp430
import re

NEW_SETTINGS_ADDR = 0x2400  # __datastart
TOTAL_ADDR = 0x2406          # _edata

DEFAULT_INT_MIN = 0
DEFAULT_INT_MAX = 65535
DEFAULT_FLOAT_MIN = 0.0
DEFAULT_FLOAT_MAX = 10.0

# Output file configuration
R5_RANGES_OUTPUT_FILE = "r5_ranges_by_path.txt"
DATABASE_OUTPUT_FILE = "database-DF.txt"
DISASM_OUTPUT_FILE = "disassembly_debug.txt"
EXEC_TRACE_FILE = "execution_trace.txt"

# R5 monitoring points: will be populated dynamically from pypcode disassembly
R5_OPERATIONS = []

# Key addresses from IDA/map/disassembly
#MAIN_ADDR = 0x4584              # main function entry
MAIN_ADDR = 0x44b8
ENTRY_ADDR = MAIN_ADDR          # symbolic execution entry
#SKIP_CALL_TARGETS = {0x4728, 0x46d0, 0x46cc}  # memset, memmove, _exit
SKIP_CALL_TARGETS = {0x45c2, 0x456a, 0x4566}  # memset, memmove, _exit

def extract_sections(f):
    """Extract code sections from ELF file"""
    objcopy = "../../toolchain/compiler/msp430-gcc-9.2.0.50_linux64_original/bin/msp430-elf-objcopy"
    subprocess.run([objcopy, "-O", "binary", "-j", ".lowtext", "-j", ".text", f, "apptext.bin"], check=True)
    print(f"✓ Code sections extracted")

def merge_continuous_ranges(values):
    """Merge continuous values into ranges, preserve discrete values"""
    if not values:
        return []
    
    sorted_vals = sorted(values)
    
    # If there is only one value, return it directly
    if len(sorted_vals) == 1:
        return [f"0x{sorted_vals[0]:04x}"]
    
    ranges = []
    start = sorted_vals[0]
    end = sorted_vals[0]
    
    for val in sorted_vals[1:]:
        if val == end + 1:
            # Continuous value, extend range
            end = val
        else:
            # Gap encountered
            if start == end:
                # Single value
                ranges.append(f"0x{start:04x}")
            else:
                # Continuous range
                ranges.append(f"[0x{start:04x}-0x{end:04x}]")
            start = val
            end = val
    
    # Handle the last segment
    if start == end:
        ranges.append(f"0x{start:04x}")
    else:
        ranges.append(f"[0x{start:04x}-0x{end:04x}]")
    
    return ranges

def merge_continuous_pairs(values):
    """Merge continuous values into (start, end) pairs."""
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

def disassemble_full(bf, ba):
    """Disassemble binary code using pypcode"""
    ctx = pypcode.Context("TI_MSP430X:LE:32:default")
    with open(bf, "rb") as f:
        data = f.read()
    
    print(f"✓ Code segment: {len(data)} bytes (0x{ba:04x} - 0x{ba+len(data):04x})")
    
    instructions, off = {}, 0
    
    # Write disassembly to file for debugging
    with open(DISASM_OUTPUT_FILE, 'w', encoding='utf-8') as df:
        df.write("="*80 + "\n")
        df.write("MSP430 Disassembly with P-code\n")
        df.write(f"Code base: 0x{ba:04x}\n")
        df.write("="*80 + "\n\n")
        
        while off < len(data):
            addr = ba + off
            try:
                dis = ctx.disassemble(data[off:off+12], addr)
                if not dis.instructions:
                    off += 2
                    continue
                
                insn = dis.instructions[0]
                pcode = ctx.translate(data[off:off+insn.length], addr, max_instructions=1)
                
                ops = []
                imark_cnt = 0
                for op in pcode.ops:
                    if op.opcode == pypcode.OpCode.IMARK:
                        imark_cnt += 1
                        if imark_cnt == 1:
                            continue
                    ops.append(op)
                
                # Extract branch target from instruction body (more reliable)
                branch_target = None
                if insn.mnem.upper() in ['JEQ', 'JNE', 'JZ', 'JNZ', 'JC', 'JNC', 'JL', 'JGE', 'JMP', 'JHS', 'JLO', 'BRA']:
                    # Parse target address from body like "0x4510"
                    match = re.search(r'0x([0-9a-fA-F]+)', insn.body)
                    if match:
                        branch_target = int(match.group(1), 16)
                
                instructions[addr] = (insn.mnem, insn.body, insn.length, ops, branch_target)
                
                # Write to debug file
                df.write(f"0x{addr:04x}: {insn.mnem:12s} {insn.body:30s} (len={insn.length})")
                if branch_target:
                    df.write(f" -> 0x{branch_target:04x}")
                df.write("\n")
                for op in ops:
                    df.write(f"          {str(op.opcode):20s}\n")
                df.write("\n")
                
                off += insn.length
            except:
                off += 2
    
    print(f"✓ Disassembled {len(instructions)} instructions")
    print(f"✓ Disassembly written to: {DISASM_OUTPUT_FILE}")
    return instructions, data

def _parse_imm_target(body_text):
    match = re.search(r'#0x([0-9a-fA-F]+)', body_text or "")
    return int(match.group(1), 16) if match else None

def compute_reachable_addrs(instructions, entry_addr, skip_call_targets):
    """Compute reachable addresses from entry by following branches/calls."""
    reachable = set()
    work = deque([entry_addr])
    while work:
        addr = work.popleft()
        if addr in reachable or addr not in instructions:
            continue
        reachable.add(addr)
        mnem, body, length, _, branch_target = instructions[addr]
        next_addr = addr + length

        mnem_u = mnem.upper()
        # Unconditional branch
        if mnem_u in ['BRA', 'JMP'] and branch_target is not None:
            if branch_target in instructions:
                work.append(branch_target)
            continue

        # Conditional branch: both target and fall-through
        if mnem_u in ['JEQ', 'JNE', 'JZ', 'JNZ', 'JC', 'JNC', 'JL', 'JGE', 'JHS', 'JLO']:
            if branch_target is not None and branch_target in instructions:
                work.append(branch_target)
            if next_addr in instructions:
                work.append(next_addr)
            continue

        # Return: stop
        if mnem_u == 'RETURN':
            continue

        # Call: follow callee (if local) and fall-through
        if mnem_u in ['CALL', 'CALLA']:
            tgt = _parse_imm_target(body)
            if tgt is not None and tgt not in skip_call_targets and tgt in instructions:
                work.append(tgt)
            if next_addr in instructions:
                work.append(next_addr)
            continue

        # Default: follow sequential
        if next_addr in instructions:
            work.append(next_addr)

    return reachable

def extract_r5_operations_from_pcode(instructions):
    """
    Scan pypcode-derived instructions to find ops that write into register R5 output varnode.
    Returns list of (addr, body_text, category).
    """
    ops = []
    seen = set()
    for addr, (mnem, body, length, pcode_ops, branch_target) in instructions.items():
        for op in pcode_ops:
            out = getattr(op, 'output', None)
            if out is None:
                continue
            # detect register varnode with offset 0x14 (R5 as used in REG_MAP)
            try:
                sp_name = out.space.name
                off = out.offset
            except Exception:
                continue
            if sp_name == 'register' and off == 0x14:
                if addr in seen:
                    continue
                seen.add(addr)
                cat = 'unknown'
                b = body or ""
                # Heuristics to classify variable source
                if re.search(r'\bR12\b', b) or '@R12' in b or 'R12' in b:
                    cat = 'new_settings'
                elif 'SP' in b or '(SP)' in b:
                    m = re.search(r'([0-9]+|0x[0-9a-fA-F]+)\s*\(\s*SP\s*\)', b)
                    if m:
                        off_str = m.group(1)
                        try:
                            off_val = int(off_str, 0)
                            if off_val <= 5:
                                cat = 'settings'
                            else:
                                cat = 'local'
                        except:
                            cat = 'settings'
                    else:
                        cat = 'settings'
                else:
                    m = re.search(r'0x([0-9a-fA-F]+)', b)
                    if m:
                        try:
                            addrval = int(m.group(0), 16)
                            if NEW_SETTINGS_ADDR <= addrval < NEW_SETTINGS_ADDR + 0x100:
                                cat = 'new_settings'
                        except:
                            pass
                ops.append((addr, b.strip(), cat))
    ops.sort(key=lambda x: x[0])
    return ops

def symbolic_exec(code_file, code_base, input_mode, int_min, int_max, int_value, float_min, float_max, float_value, r5_range_specs):
    """Main symbolic execution engine"""
    print("="*80 + "\nInitialization\n" + "="*80)
    
    instructions, code_data = disassemble_full(code_file, code_base)
    
    # Dynamically populate R5_OPERATIONS from p-code
    dynamic_ops = extract_r5_operations_from_pcode(instructions)
    if dynamic_ops:
        global R5_OPERATIONS
        R5_OPERATIONS = [(addr, desc, cat) for (addr, desc, cat) in dynamic_ops]
    else:
        print("! Warning: no R5 ops found via pypcode; using existing R5_OPERATIONS if any")

    reachable_addrs = compute_reachable_addrs(instructions, ENTRY_ADDR, SKIP_CALL_TARGETS)
    if reachable_addrs:
        R5_OPERATIONS = [(addr, desc, cat) for (addr, desc, cat) in R5_OPERATIONS if addr in reachable_addrs]
    
    CODE_START = min(instructions.keys())
    CODE_END = max(instructions.keys()) + 4
    print(f"✓ Valid code range: 0x{CODE_START:04x} - 0x{CODE_END:04x}")
    
    # Check if key addresses are in range
    print(f"\nAddress validation:")
    print(f"  MAIN_ADDR (0x{MAIN_ADDR:04x}): {'✓ in range' if MAIN_ADDR in instructions else '✗ NOT FOUND'}")
    
    # Check R5 monitoring addresses
    r5_in_range = sum(1 for addr, _, _ in R5_OPERATIONS if addr in instructions)
    print(f"  R5 monitor points: {r5_in_range}/{len(R5_OPERATIONS)} in range")
    
    if r5_in_range < len(R5_OPERATIONS):
        print(f"\n  Missing R5 addresses:")
        for addr, desc, _ in R5_OPERATIONS:
            if addr not in instructions:
                print(f"    0x{addr:04x}: {desc}")
    
    proj = angr.Project(code_file, arch='MSP430', 
                       main_opts={'backend':'blob','base_addr':code_base,'entry_point':code_base}, 
                       auto_load_libs=False)
    
    initial_state = proj.factory.blank_state(addr=ENTRY_ADDR, 
                                            add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY})
    
    print(f"\n✓ Starting from main @ 0x{ENTRY_ADDR:04x}")
    
    STACK_TOP = 0x4400
    initial_state.regs.sp = claripy.BVV(STACK_TOP, 16)
    initial_state.regs.pc = claripy.BVV(ENTRY_ADDR, 16)
    initial_state.regs.r13 = claripy.BVV(0, 16)
    initial_state.regs.r14 = claripy.BVV(0, 16)
    
    print(f"✓ Symbolic input: new_settings @ 0x{NEW_SETTINGS_ADDR:04x} (6 bytes)")

    initial_constraint_desc = None
    initial_constraint_range_str = None

    if input_mode == 'int':
        if int_value is not None:
            if int_value < 0 or int_value >= 65536:
                raise ValueError("int_value must be in [0, 65535]")
            int_sym = claripy.BVV(int_value, 16)
            initial_constraint_desc = f"Initial constraint: input_int == 0x{int_value:04x} (unsigned 16-bit)"
            initial_constraint_range_str = f"0x{int_value:04x}"
        else:
            if int_min < 0 or int_max >= 65536 or int_min > int_max:
                raise ValueError("int_min/int_max must be in [0, 65535] and min <= max")
            int_sym = claripy.BVS('input_int', 16)
            initial_state.solver.add(int_sym >= int_min)
            initial_state.solver.add(int_sym <= int_max)
            initial_constraint_desc = f"Initial constraint: input_int ∈ [0x{int_min:04x}, 0x{int_max:04x}] (unsigned 16-bit)"
            initial_constraint_range_str = f"[0x{int_min:04x}-0x{int_max:04x}]"

        initial_state.memory.store(NEW_SETTINGS_ADDR, int_sym, endness='Iend_LE')
        for i in range(2, 6):
            initial_state.memory.store(NEW_SETTINGS_ADDR + i, claripy.BVV(0, 8))

    elif input_mode == 'float':
        if float_value is not None:
            fp_sym = claripy.FPV(float_value, claripy.FSORT_FLOAT)
            initial_constraint_desc = f"Initial constraint: input_float == {float_value} (float32)"
            initial_constraint_range_str = f"{float_value}"
        else:
            if float_min > float_max:
                raise ValueError("float_min must be <= float_max")
            fp_sym = claripy.FPS('input_float', claripy.FSORT_FLOAT)
            initial_state.solver.add(claripy.fpGEQ(fp_sym, claripy.FPV(float_min, claripy.FSORT_FLOAT)))
            initial_state.solver.add(claripy.fpLEQ(fp_sym, claripy.FPV(float_max, claripy.FSORT_FLOAT)))
            initial_constraint_desc = f"Initial constraint: input_float ∈ [{float_min}, {float_max}] (float32)"
            initial_constraint_range_str = f"[{float_min}-{float_max}]"

        fp_bits = claripy.fpToIEEEBV(fp_sym)
        initial_state.memory.store(NEW_SETTINGS_ADDR, fp_bits, endness='Iend_LE')
        for i in range(4, 6):
            initial_state.memory.store(NEW_SETTINGS_ADDR + i, claripy.BVV(0, 8))
    else:
        raise ValueError("input_mode must be 'int' or 'float'")
    
    initial_state.memory.store(TOTAL_ADDR, claripy.BVV(0, 8))
    initial_state.memory.store(STACK_TOP, claripy.BVV(0, 32), endness='Iend_LE')
    
    # Track R5 ranges per path and per call edge
    path_r5_data = {}
    edge_r5_values = defaultdict(lambda: defaultdict(set))  # edge_key -> {r5_idx -> values}
    r5_addrs = {addr for addr, _, _ in R5_OPERATIONS}
    r5_idx_map = {addr: i for i, (addr, _, _) in enumerate(R5_OPERATIONS, 1)}
    all_r5_indices = set(range(1, len(R5_OPERATIONS) + 1))

    r5_ranges = {}
    for r5_idx in all_r5_indices:
        spec = r5_range_specs.get(r5_idx)
        if spec is None:
            r5_ranges[r5_idx] = {
                'mode': 'int',
                'min': DEFAULT_INT_MIN,
                'max': DEFAULT_INT_MAX
            }
        else:
            r5_ranges[r5_idx] = spec
    
    # Global aggregation structure
    global_r5_aggregated = defaultdict(lambda: {
        'address': None,
        'instruction': None,
        'category': None,
        'values': set(),
        'paths': set()
    })
    
    REG_MAP = {0x0:'pc',0x4:'sp',0x8:'sr',0xc:'cg',0x10:'r4',0x14:'r5',0x18:'r6',0x1c:'r7',
               0x20:'r8',0x24:'r9',0x28:'r10',0x2c:'r11',0x30:'r12',0x34:'r13',0x38:'r14',0x3c:'r15'}
    
    def read_vn(state, vn, temp_vars):
        """Read value from varnode"""
        sp, sb = vn.space.name, vn.size * 8
        if sp == 'register':
            reg_name = REG_MAP.get(vn.offset, f'r_{vn.offset:x}')
            v = state.registers.load(reg_name, vn.size)
            return claripy.ZeroExt(sb-v.size(), v) if v.size()<sb else (claripy.Extract(sb-1,0,v) if v.size()>sb else v)
        elif sp == 'RAM':
            return state.memory.load(vn.offset, vn.size, endness='Iend_LE')
        elif sp == 'const':
            return claripy.BVV(vn.offset, sb)
        elif sp == 'unique':
            k = ('unique', vn.offset, vn.size)
            if k not in temp_vars:
                temp_vars[k] = claripy.BVS(f'tmp_{vn.offset:x}', sb)
            return temp_vars[k]
        raise NotImplementedError(f"read {sp}")
    
    def write_vn(state, vn, val, temp_vars):
        """Write value to varnode"""
        sp, tb = vn.space.name, vn.size * 8
        if sp == 'register':
            val = claripy.ZeroExt(tb-val.size(), val) if val.size()<tb else (claripy.Extract(tb-1,0,val) if val.size()>tb else val)
            reg_name = REG_MAP.get(vn.offset, f'r_{vn.offset:x}')
            state.registers.store(reg_name, val)
        elif sp == 'RAM':
            state.memory.store(vn.offset, val, endness='Iend_LE')
        elif sp == 'unique':
            temp_vars[('unique', vn.offset, vn.size)] = val
    
    def get_register_state(state):
        """Get current register values for debugging"""
        regs = {}
        for offset, name in REG_MAP.items():
            try:
                val = state.registers.load(name, 2 if offset >= 0x10 else 4)
                if state.solver.symbolic(val):
                    regs[name] = f"<symbolic>"
                else:
                    regs[name] = f"0x{state.solver.eval(val):04x}"
            except:
                regs[name] = "<error>"
        return regs
    
    def execute_instruction(state, addr, ops, trace_file):
        """Execute single instruction via p-code interpretation"""
        temp_vars = {}
        mnem, body, length, _, branch_target = instructions[addr]
        next_addr = addr + length
        call_target = None
        branch_info = None
        sp_before = state.regs.sp
        
        # Write detailed trace before execution
        trace_file.write(f"\n{'='*80}\n")
        trace_file.write(f"Executing @ 0x{addr:04x}: {mnem:12s} {body:30s}\n")
        trace_file.write(f"{'='*80}\n")
        
        # Get register state before execution
        regs_before = get_register_state(state)
        trace_file.write("Registers BEFORE:\n")
        trace_file.write(f"  PC={regs_before['pc']}  SP={regs_before['sp']}  SR={regs_before['sr']}\n")
        trace_file.write(f"  R4={regs_before['r4']}  R5={regs_before['r5']}  R6={regs_before['r6']}  R7={regs_before['r7']}\n")
        trace_file.write(f"  R12={regs_before['r12']} R13={regs_before['r13']} R14={regs_before['r14']} R15={regs_before['r15']}\n")
        
        # Skip known library calls to avoid getting stuck in libc loops
        if mnem.upper() in ['CALL', 'CALLA']:
            match = re.search(r'#0x([0-9a-fA-F]+)', body)
            if match:
                imm_target = int(match.group(1), 16)
                if imm_target in SKIP_CALL_TARGETS:
                    trace_file.write(f"\n  [SKIP CALL to 0x{imm_target:04x}]")
                    state.regs.sp = sp_before
                    regs_after = get_register_state(state)
                    trace_file.write("\n\nRegisters AFTER:\n")
                    trace_file.write(f"  PC={regs_after['pc']}  SP={regs_after['sp']}  SR={regs_after['sr']}\n")
                    trace_file.write(f"  R4={regs_after['r4']}  R5={regs_after['r5']}  R6={regs_after['r6']}  R7={regs_after['r7']}\n")
                    trace_file.write(f"  R12={regs_after['r12']} R13={regs_after['r13']} R14={regs_after['r14']} R15={regs_after['r15']}\n")
                    trace_file.write(f"\n>>> NEXT: Sequential execution to 0x{next_addr:04x}\n")
                    return [(state, next_addr)], True

        for op in ops:
            if op.opcode == pypcode.OpCode.IMARK:
                continue
            
            try:
                trace_file.write(f"\n  P-code: {str(op.opcode):16s}")
                
                if op.opcode == pypcode.OpCode.COPY:
                    val = read_vn(state, op.inputs[0], temp_vars)
                    write_vn(state, op.output, val, temp_vars)
                    
                elif op.opcode == pypcode.OpCode.LOAD:
                    ptr = read_vn(state, op.inputs[1], temp_vars)
                    if not state.solver.symbolic(ptr):
                        addr_val = state.solver.eval(ptr)
                        trace_file.write(f" [LOAD from 0x{addr_val:04x}]")
                    val = state.memory.load(ptr, op.output.size, endness='Iend_LE')
                    write_vn(state, op.output, val, temp_vars)
                    
                elif op.opcode == pypcode.OpCode.STORE:
                    ptr = read_vn(state, op.inputs[1], temp_vars)
                    val = read_vn(state, op.inputs[2], temp_vars)
                    if not state.solver.symbolic(ptr):
                        addr_val = state.solver.eval(ptr)
                        trace_file.write(f" [STORE to 0x{addr_val:04x}]")
                    state.memory.store(ptr, val, endness='Iend_LE')
                    
                elif op.opcode == pypcode.OpCode.BRANCH:
                    # Prefer disassembly-extracted target for BRA/JMP to avoid p-code mis-decode
                    if mnem.upper() in ['BRA', 'JMP'] and branch_target is not None:
                        next_addr = branch_target
                        trace_file.write(f" [Unconditional to 0x{next_addr:04x}]")
                    else:
                        target = read_vn(state, op.inputs[0], temp_vars)
                        if not state.solver.symbolic(target):
                            next_addr = state.solver.eval(target)
                            trace_file.write(f" [Unconditional to 0x{next_addr:04x}]")
                    
                elif op.opcode == pypcode.OpCode.CBRANCH:
                    cond = read_vn(state, op.inputs[1], temp_vars)
                    # Use pre-extracted branch_target instead of parsing p-code
                    branch_info = (cond, branch_target)
                    trace_file.write(f" [CBRANCH to 0x{branch_target:04x}]")
                    
                elif op.opcode == pypcode.OpCode.BRANCHIND:
                    target = read_vn(state, op.inputs[0], temp_vars)
                    if not state.solver.symbolic(target):
                        next_addr = state.solver.eval(target)
                        trace_file.write(f" [Indirect to 0x{next_addr:04x}]")
                    
                elif op.opcode == pypcode.OpCode.CALL:
                    pass
                    
                elif op.opcode == pypcode.OpCode.CALLIND:
                    target = read_vn(state, op.inputs[0], temp_vars)
                    call_target = target
                    
                elif op.opcode == pypcode.OpCode.RETURN:
                    sp_val = state.regs.sp
                    ret_addr = state.memory.load(sp_val, 4, endness='Iend_LE')
                    if ret_addr.size() > 16:
                        ret_addr = claripy.Extract(15, 0, ret_addr)
                    if not state.solver.symbolic(ret_addr):
                        next_addr = state.solver.eval(ret_addr)
                        trace_file.write(f" [RETURN to 0x{next_addr:04x}]")
                    state.regs.sp = sp_val + claripy.BVV(4, sp_val.size())
                    
                elif op.opcode in [pypcode.OpCode.INT_ADD, pypcode.OpCode.INT_SUB, pypcode.OpCode.INT_MULT, 
                                  pypcode.OpCode.INT_DIV, pypcode.OpCode.INT_SDIV, pypcode.OpCode.INT_REM, 
                                  pypcode.OpCode.INT_SREM]:
                    a = read_vn(state, op.inputs[0], temp_vars)
                    b = read_vn(state, op.inputs[1], temp_vars)
                    if op.opcode == pypcode.OpCode.INT_ADD:
                        res = a + b
                    elif op.opcode == pypcode.OpCode.INT_SUB:
                        res = a - b
                    elif op.opcode == pypcode.OpCode.INT_MULT:
                        res = a * b
                    elif op.opcode == pypcode.OpCode.INT_DIV:
                        res = claripy.UDiv(a, b)
                    elif op.opcode == pypcode.OpCode.INT_SDIV:
                        res = a / b
                    elif op.opcode == pypcode.OpCode.INT_REM:
                        res = claripy.UMod(a, b)
                    else:
                        res = claripy.SMod(a, b)
                    write_vn(state, op.output, res, temp_vars)
                    
                elif op.opcode in [pypcode.OpCode.INT_AND, pypcode.OpCode.INT_OR, pypcode.OpCode.INT_XOR]:
                    a = read_vn(state, op.inputs[0], temp_vars)
                    b = read_vn(state, op.inputs[1], temp_vars)
                    if op.opcode == pypcode.OpCode.INT_AND:
                        res = a & b
                    elif op.opcode == pypcode.OpCode.INT_OR:
                        res = a | b
                    else:
                        res = a ^ b
                    write_vn(state, op.output, res, temp_vars)
                    
                elif op.opcode in [pypcode.OpCode.INT_LEFT, pypcode.OpCode.INT_RIGHT, pypcode.OpCode.INT_SRIGHT]:
                    a = read_vn(state, op.inputs[0], temp_vars)
                    b = read_vn(state, op.inputs[1], temp_vars)
                    if op.opcode == pypcode.OpCode.INT_LEFT:
                        res = a << b
                    elif op.opcode == pypcode.OpCode.INT_RIGHT:
                        res = claripy.LShR(a, b)
                    else:
                        res = a >> b
                    write_vn(state, op.output, res, temp_vars)
                    
                elif op.opcode in [pypcode.OpCode.INT_EQUAL, pypcode.OpCode.INT_NOTEQUAL, 
                                  pypcode.OpCode.INT_LESS, pypcode.OpCode.INT_SLESS, 
                                  pypcode.OpCode.INT_LESSEQUAL, pypcode.OpCode.INT_SLESSEQUAL]:
                    a = read_vn(state, op.inputs[0], temp_vars)
                    b = read_vn(state, op.inputs[1], temp_vars)
                    if op.opcode == pypcode.OpCode.INT_EQUAL:
                        res = claripy.If(a == b, claripy.BVV(1, 1), claripy.BVV(0, 1))
                    elif op.opcode == pypcode.OpCode.INT_NOTEQUAL:
                        res = claripy.If(a != b, claripy.BVV(1, 1), claripy.BVV(0, 1))
                    elif op.opcode == pypcode.OpCode.INT_LESS:
                        res = claripy.If(claripy.ULT(a, b), claripy.BVV(1, 1), claripy.BVV(0, 1))
                    elif op.opcode == pypcode.OpCode.INT_SLESS:
                        res = claripy.If(claripy.SLT(a, b), claripy.BVV(1, 1), claripy.BVV(0, 1))
                    elif op.opcode == pypcode.OpCode.INT_LESSEQUAL:
                        res = claripy.If(claripy.ULE(a, b), claripy.BVV(1, 1), claripy.BVV(0, 1))
                    else:
                        res = claripy.If(claripy.SLE(a, b), claripy.BVV(1, 1), claripy.BVV(0, 1))
                    write_vn(state, op.output, res, temp_vars)
                    
                elif op.opcode == pypcode.OpCode.INT_ZEXT:
                    val = read_vn(state, op.inputs[0], temp_vars)
                    res = claripy.ZeroExt(op.output.size * 8 - val.size(), val)
                    write_vn(state, op.output, res, temp_vars)
                    
                elif op.opcode == pypcode.OpCode.INT_SEXT:
                    val = read_vn(state, op.inputs[0], temp_vars)
                    res = claripy.SignExt(op.output.size * 8 - val.size(), val)
                    write_vn(state, op.output, res, temp_vars)
                    
                elif op.opcode == pypcode.OpCode.INT_NEGATE:
                    val = read_vn(state, op.inputs[0], temp_vars)
                    res = ~val
                    write_vn(state, op.output, res, temp_vars)
                    
                elif op.opcode == pypcode.OpCode.INT_2COMP:
                    val = read_vn(state, op.inputs[0], temp_vars)
                    res = -val
                    write_vn(state, op.output, res, temp_vars)
                    
                elif op.opcode == pypcode.OpCode.SUBPIECE:
                    val = read_vn(state, op.inputs[0], temp_vars)
                    offset = read_vn(state, op.inputs[1], temp_vars)
                    if not state.solver.symbolic(offset):
                        off_val = state.solver.eval(offset)
                        bit_off = off_val * 8
                        res = claripy.Extract(bit_off + op.output.size * 8 - 1, bit_off, val)
                        write_vn(state, op.output, res, temp_vars)
                    
                elif op.opcode == pypcode.OpCode.PIECE:
                    hi = read_vn(state, op.inputs[0], temp_vars)
                    lo = read_vn(state, op.inputs[1], temp_vars)
                    res = claripy.Concat(hi, lo)
                    write_vn(state, op.output, res, temp_vars)
                    
                elif op.opcode in [pypcode.OpCode.INT_CARRY, pypcode.OpCode.INT_SCARRY, pypcode.OpCode.INT_SBORROW]:
                    write_vn(state, op.output, claripy.BVV(0, op.output.size * 8), temp_vars)
                    
                elif op.opcode == pypcode.OpCode.BOOL_AND:
                    a = read_vn(state, op.inputs[0], temp_vars)
                    b = read_vn(state, op.inputs[1], temp_vars)
                    res = a & b
                    write_vn(state, op.output, res, temp_vars)
                    
                elif op.opcode == pypcode.OpCode.BOOL_OR:
                    a = read_vn(state, op.inputs[0], temp_vars)
                    b = read_vn(state, op.inputs[1], temp_vars)
                    res = a | b
                    write_vn(state, op.output, res, temp_vars)
                    
                elif op.opcode == pypcode.OpCode.BOOL_XOR:
                    a = read_vn(state, op.inputs[0], temp_vars)
                    b = read_vn(state, op.inputs[1], temp_vars)
                    res = a ^ b
                    write_vn(state, op.output, res, temp_vars)
                    
                elif op.opcode == pypcode.OpCode.BOOL_NEGATE:
                    val = read_vn(state, op.inputs[0], temp_vars)
                    res = ~val
                    write_vn(state, op.output, res, temp_vars)
                
            except Exception as e:
                trace_file.write(f" [ERROR: {e}]")
        
        # Get register state after execution
        regs_after = get_register_state(state)
        trace_file.write("\n\nRegisters AFTER:\n")
        trace_file.write(f"  PC={regs_after['pc']}  SP={regs_after['sp']}  SR={regs_after['sr']}\n")
        trace_file.write(f"  R4={regs_after['r4']}  R5={regs_after['r5']}  R6={regs_after['r6']}  R7={regs_after['r7']}\n")
        trace_file.write(f"  R12={regs_after['r12']} R13={regs_after['r13']} R14={regs_after['r14']} R15={regs_after['r15']}\n")
        
        # Handle CALL/CALLA instruction (push return address)
        if mnem.upper() in ['CALL', 'CALLA']:
            target_addr = None
            if call_target is not None and not state.solver.symbolic(call_target):
                target_addr = state.solver.eval(call_target)
            else:
                match = re.search(r'#0x([0-9a-fA-F]+)', body)
                if match:
                    target_addr = int(match.group(1), 16)

            if target_addr is not None:
                ret_addr_bv = claripy.BVV(next_addr, 32)
                new_sp = sp_before - claripy.BVV(4, sp_before.size())
                state.regs.sp = new_sp
                state.memory.store(new_sp, ret_addr_bv, endness='Iend_LE')
                trace_file.write(f"\n>>> NEXT: Call to function @ 0x{target_addr:04x}\n")
                return [(state, target_addr)], True
        
        if branch_info is not None:
            cond, target_addr = branch_info
            
            if state.solver.symbolic(cond):
                # Fork paths
                state_taken = state.copy()
                state_taken.solver.add(cond != 0)
                
                state_fall = state.copy()
                state_fall.solver.add(cond == 0)
                
                results = []
                if state_taken.solver.satisfiable():
                    trace_file.write(f"\n>>> NEXT: Branch TAKEN to 0x{target_addr:04x}\n")
                    results.append((state_taken, target_addr))
                if state_fall.solver.satisfiable():
                    trace_file.write(f">>> NEXT: Branch FALL-THROUGH to 0x{next_addr:04x}\n")
                    results.append((state_fall, next_addr))
                return results, True
            else:
                cond_val = state.solver.eval(cond)
                if cond_val != 0:
                    trace_file.write(f"\n>>> NEXT: Branch taken to 0x{target_addr:04x}\n")
                    return [(state, target_addr)], True
                else:
                    trace_file.write(f"\n>>> NEXT: Branch not taken, fall through to 0x{next_addr:04x}\n")
        
        trace_file.write(f"\n>>> NEXT: Sequential execution to 0x{next_addr:04x}\n")
        return [(state, next_addr)], True

    def apply_r5_constraints(state, r5_idx, r5_val):
        cfg = r5_ranges.get(r5_idx)
        if not cfg:
            return
        mode = cfg.get('mode')
        if mode == 'int':
            min_v = int(cfg.get('min', DEFAULT_INT_MIN))
            max_v = int(cfg.get('max', DEFAULT_INT_MAX))
            min_bv = claripy.BVV(min_v, r5_val.size())
            max_bv = claripy.BVV(max_v, r5_val.size())
            state.solver.add(claripy.UGE(r5_val, min_bv))
            state.solver.add(claripy.ULE(r5_val, max_bv))
        elif mode == 'float':
            min_f = float(cfg.get('min', DEFAULT_FLOAT_MIN))
            max_f = float(cfg.get('max', DEFAULT_FLOAT_MAX))
            if r5_val.size() == 32:
                fp_val = claripy.fpToFP(r5_val, claripy.FSORT_FLOAT)
                state.solver.add(claripy.fpGEQ(fp_val, claripy.FPV(min_f, claripy.FSORT_FLOAT)))
                state.solver.add(claripy.fpLEQ(fp_val, claripy.FPV(max_f, claripy.FSORT_FLOAT)))
            else:
                min_v = int(math.floor(min_f))
                max_v = int(math.ceil(max_f))
                min_bv = claripy.BVV(min_v, r5_val.size())
                max_bv = claripy.BVV(max_v, r5_val.size())
                state.solver.add(claripy.UGE(r5_val, min_bv))
                state.solver.add(claripy.ULE(r5_val, max_bv))
    
    print("\n" + "="*80 + "\nExecution\n" + "="*80)
    
    path_counter = 0
    worklist = deque()
    worklist.append((initial_state, ENTRY_ADDR, 0, path_counter, set(), [ENTRY_ADDR]))
    path_counter += 1
    
    max_steps_per_path = 2000
    max_total_steps = 200000
    total_steps = 0
    completed_paths = 0
    executed_addrs = set()
    
    # Open trace file
    with open(EXEC_TRACE_FILE, 'w', encoding='utf-8') as trace_file:
        trace_file.write("="*80 + "\n")
        trace_file.write("MSP430 Symbolic Execution - Detailed Execution Trace\n")
        trace_file.write("="*80 + "\n\n")
        
        while worklist and total_steps < max_total_steps:
            state, pc, step_count, path_id, visited, call_stack = worklist.popleft()
            
            if path_id not in path_r5_data:
                path_r5_data[path_id] = {'r5_values': {}, 'covered_indices': set()}
            
            state_hash = (pc, step_count % 50)
            if state_hash in visited:
                continue
            visited = visited | {state_hash}
            
            executed_addrs.add(pc)
            
            # Write step header to trace file
            if total_steps < 100:  # Limit to first 100 steps
                trace_file.write(f"\n{'#'*80}\n")
                trace_file.write(f"STEP {total_steps} | Path {path_id} | Step {step_count}\n")
                trace_file.write(f"{'#'*80}\n")
            
            if pc not in instructions:
                if total_steps < 100:
                    trace_file.write(f"\n  [Step {step_count} Path{path_id}] PC 0x{pc:04x} not in instructions - stopping path\n")
                continue
            
            if step_count >= max_steps_per_path:
                continue
            
            mnem, body, length, ops, _ = instructions[pc]
            
            # Capture R5 values at monitoring points
            if pc in r5_addrs:
                r5_idx = r5_idx_map[pc]
                addr, r5_desc, category = R5_OPERATIONS[r5_idx - 1]
                
                r5_val = state.regs.r5
                current_callee = call_stack[-1] if call_stack else None
                current_caller = call_stack[-2] if len(call_stack) >= 2 else None
                if current_callee is None:
                    edge_key = "main"
                elif current_caller is None:
                    edge_key = f"main"
                else:
                    edge_key = f"0x{current_caller:04x}->0x{current_callee:04x}"
                
                apply_r5_constraints(state, r5_idx, r5_val)

                if state.solver.symbolic(r5_val):
                    try:
                        solutions = []
                        for _ in range(100):
                            sol = state.solver.eval(r5_val, 1)[0]
                            solutions.append(sol)
                            state.solver.add(r5_val != sol)
                            if not state.solver.satisfiable():
                                break
                        
                        if r5_idx not in path_r5_data[path_id]['r5_values']:
                            path_r5_data[path_id]['r5_values'][r5_idx] = set()
                        path_r5_data[path_id]['r5_values'][r5_idx].update(solutions)
                        path_r5_data[path_id]['covered_indices'].add(r5_idx)
                        
                        global_r5_aggregated[r5_idx]['address'] = pc
                        global_r5_aggregated[r5_idx]['instruction'] = r5_desc
                        global_r5_aggregated[r5_idx]['category'] = category
                        global_r5_aggregated[r5_idx]['values'].update(solutions)
                        global_r5_aggregated[r5_idx]['paths'].add(path_id)
                        edge_r5_values[edge_key][r5_idx].update(solutions)
                        
                        if total_steps < 100:
                            trace_file.write(f"\n*** R5 MONITOR POINT #{r5_idx} @ 0x{pc:04x} ***\n")
                            trace_file.write(f"    Instruction: {r5_desc}\n")
                            trace_file.write(f"    Values: {len(solutions)} solutions\n")
                        
                    except:
                        pass
                else:
                    val = state.solver.eval(r5_val)
                    if r5_idx not in path_r5_data[path_id]['r5_values']:
                        path_r5_data[path_id]['r5_values'][r5_idx] = set()
                    path_r5_data[path_id]['r5_values'][r5_idx].add(val)
                    path_r5_data[path_id]['covered_indices'].add(r5_idx)
                    
                    global_r5_aggregated[r5_idx]['address'] = pc
                    global_r5_aggregated[r5_idx]['instruction'] = r5_desc
                    global_r5_aggregated[r5_idx]['category'] = category
                    global_r5_aggregated[r5_idx]['values'].add(val)
                    global_r5_aggregated[r5_idx]['paths'].add(path_id)
                    edge_r5_values[edge_key][r5_idx].add(val)
                    
                    if total_steps < 100:
                        trace_file.write(f"\n*** R5 MONITOR POINT #{r5_idx} @ 0x{pc:04x} ***\n")
                        trace_file.write(f"    Instruction: {r5_desc}\n")
                        trace_file.write(f"    Value: 0x{val:04x}\n")
            
            # Execute instruction
            if total_steps < 100:
                results, ok = execute_instruction(state, pc, ops, trace_file)
            else:
                import io
                with io.StringIO() as null_trace:
                    results, ok = execute_instruction(state, pc, ops, null_trace)
            
            if not ok:
                if total_steps < 100:
                    trace_file.write(f"\n  [Execution failed]\n")
                continue
            
            mnem_u = mnem.upper()
            call_target_addr = _parse_imm_target(body) if mnem_u in ['CALL', 'CALLA'] else None
            is_skip_call = call_target_addr in SKIP_CALL_TARGETS if call_target_addr is not None else False

            # If returning from main, stop the path
            if mnem_u == 'RETURN' and len(call_stack) == 1:
                completed_paths += 1
                if total_steps < 100:
                    trace_file.write(f"\n  [Path {path_id} COMPLETE at main return]\n")
                print(f"  Path {path_id} completed at step {step_count}")
                continue

            for new_state, next_pc in results:
                new_state.regs.pc = claripy.BVV(next_pc, 16)
                new_call_stack = list(call_stack)

                if mnem_u in ['CALL', 'CALLA'] and not is_skip_call:
                    if call_target_addr is not None and call_target_addr in instructions:
                        new_call_stack.append(call_target_addr)
                elif mnem_u == 'RETURN' and new_call_stack:
                    new_call_stack.pop()

                if len(results) > 1:
                    new_path_id = path_counter
                    path_counter += 1
                    worklist.append((new_state, next_pc, step_count + 1, new_path_id, visited, new_call_stack))
                else:
                    worklist.append((new_state, next_pc, step_count + 1, path_id, visited, new_call_stack))
            
            total_steps += 1
            
            if total_steps % 1000 == 0:
                print(f"  Progress: {total_steps} steps, {len(worklist)} paths in queue, "
                      f"{len(executed_addrs)} unique addresses")

    
    covered_r5_indices = {idx for idx, info in global_r5_aggregated.items() if info['values']}
    total_r5_points = len(all_r5_indices)
    covered_r5_points = len(covered_r5_indices)
    coverage_pct = (covered_r5_points / total_r5_points * 100.0) if total_r5_points else 0.0

    print(f"\n✓ Completed: {total_steps} steps, {completed_paths} complete paths, {len(path_r5_data)} paths with R5 data")
    print(f"✓ Executed addresses: {len(executed_addrs)}")
    print(f"✓ R5 coverage: {covered_r5_points}/{total_r5_points} ({coverage_pct:.2f}%)")
    if executed_addrs:
        print(f"✓ Address range: 0x{min(executed_addrs):04x} - 0x{max(executed_addrs):04x}")
    
    # Write R5 ranges to output file
    print("\n" + "="*80 + "\nWriting R5 ranges to file\n" + "="*80)
    
    with open(R5_RANGES_OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write("="*80 + "\n")
        f.write("MSP430 Symbolic Execution - R5 Register Ranges by Path\n")
        f.write(f"{initial_constraint_desc}\n")
        f.write(f"R5 coverage (covered/total reachable): {covered_r5_points}/{total_r5_points} ({coverage_pct:.2f}%)\n")
        f.write("="*80 + "\n\n")
        
        # Output merged ranges grouped by call-ret edge within main call graph
        f.write("="*80 + "\n")
        f.write("Merged R5 Value Ranges by Call-Ret Edge (from main)\n")
        f.write("="*80 + "\n\n")

        for edge_key in sorted(edge_r5_values.keys()):
            f.write(f"{edge_key}:\n")
            for r5_idx in sorted(edge_r5_values[edge_key].keys()):
                values = edge_r5_values[edge_key][r5_idx]
                addr, desc, _ = R5_OPERATIONS[r5_idx - 1]
                ranges = merge_continuous_ranges(values)
                range_str = ', '.join(ranges)
                f.write(f"  R5_{r5_idx:2d} @ 0x{addr:04x}: {range_str:40s} # {desc}\n")
            f.write("\n")

    with open(DATABASE_OUTPUT_FILE, 'w', encoding='utf-8') as df:
        edge_key = "main" if "main" in edge_r5_values else next(iter(sorted(edge_r5_values.keys())), None)
        if edge_key is not None:
            df.write(f"call-ret Path 1: {edge_key}\n")
            r5_keys = sorted(edge_r5_values[edge_key].keys())
            for i, r5_idx in enumerate(r5_keys):
                values = edge_r5_values[edge_key][r5_idx]
                pairs = merge_continuous_pairs(values)
                range_str = ', '.join([f"0x{start:04x}--0x{end:04x}" for start, end in pairs])
                if i < len(r5_keys) - 1:
                    df.write(f"{range_str}\n")
                else:
                    df.write(f"{range_str}")

    print(f"\n✓ R5 ranges written to: {R5_RANGES_OUTPUT_FILE}")
    print(f"✓ Call-ret values written to: {DATABASE_OUTPUT_FILE}")
    print(f"\n✓ Execution trace written to: {EXEC_TRACE_FILE}")

def parse_r5_range_specs(spec_list):
    specs = {}
    if not spec_list:
        return specs
    for spec in spec_list:
        parts = spec.split(':')
        if len(parts) not in (2, 4):
            raise ValueError("r5-range must be in the form idx:mode[:min:max]")
        idx = int(parts[0])
        mode = parts[1].strip().lower()
        if mode not in ('int', 'float'):
            raise ValueError("r5-range mode must be 'int' or 'float'")
        if len(parts) == 4:
            min_v = parts[2]
            max_v = parts[3]
        else:
            min_v = None
            max_v = None

        if mode == 'int':
            min_val = int(min_v, 0) if min_v is not None else DEFAULT_INT_MIN
            max_val = int(max_v, 0) if max_v is not None else DEFAULT_INT_MAX
        else:
            min_val = float(min_v) if min_v is not None else DEFAULT_FLOAT_MIN
            max_val = float(max_v) if max_v is not None else DEFAULT_FLOAT_MAX

        specs[idx] = {'mode': mode, 'min': min_val, 'max': max_val}
    return specs

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MSP430 Symbolic Execution with R5 Monitoring")
    parser.add_argument("elf_file", help="Input ELF file path")
    parser.add_argument("--mode", choices=["int", "float"], default="int",
                        help="Initial input constraint mode (int/float)")
    parser.add_argument("--int-min", default="0x0000",
                        help="Minimum integer value (default 0x0000)")
    parser.add_argument("--int-max", default="0xFFFF",
                        help="Maximum integer value (default 0xFFFF)")
    parser.add_argument("--int-value", default=None,
                        help="Exact integer value (< 65536). Overrides int-min/int-max")
    parser.add_argument("--float-min", default="0.0",
                        help="Minimum float value (default 0.0)")
    parser.add_argument("--float-max", default="10.0",
                        help="Maximum float value (default 10.0)")
    parser.add_argument("--float-value", default=None,
                        help="Exact float value. Overrides float-min/float-max")
    parser.add_argument("--r5-range", action="append", default=[],
                        help="Per R5 range: idx:mode[:min:max], mode is int or float")
    args = parser.parse_args()

    int_min = int(args.int_min, 0)
    int_max = int(args.int_max, 0)
    int_value = int(args.int_value, 0) if args.int_value is not None else None
    float_min = float(args.float_min)
    float_max = float(args.float_max)
    float_value = float(args.float_value) if args.float_value is not None else None
    
    r5_range_specs = parse_r5_range_specs(args.r5_range)

    extract_sections(args.elf_file)
    symbolic_exec("apptext.bin", 0x4408, args.mode, int_min, int_max, int_value, float_min, float_max, float_value, r5_range_specs)
    #symbolic_exec("apptext.bin", 0x4406, args.mode, int_min, int_max, int_value, float_min, float_max, float_value, r5_range_specs)
# ...existing code...
