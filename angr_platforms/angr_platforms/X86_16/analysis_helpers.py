from __future__ import annotations

import claripy
from dataclasses import dataclass
from pathlib import Path

from angr import SimProcedure


@dataclass(frozen=True)
class FarCallTarget:
    callsite_addr: int
    target_addr: int
    return_addr: int | None


@dataclass(frozen=True)
class DOSInt21Call:
    insn_addr: int
    ah: int | None = None
    al: int | None = None
    ax: int | None = None
    bx: int | None = None
    cx: int | None = None
    dx: int | None = None
    ah_expr: str | None = None
    al_expr: str | None = None
    bx_expr: str | None = None
    cx_expr: str | None = None
    dx_expr: str | None = None
    string_literal: str | None = None


DOS_SERVICE_BASE_ADDR = 0xFE000


def _dos_service_key(call: DOSInt21Call) -> int:
    return call.ah & 0xFF if call.ah is not None else 0


def dos_service_addr(call: DOSInt21Call) -> int:
    return DOS_SERVICE_BASE_ADDR + _dos_service_key(call)


def dos_service_name(call: DOSInt21Call) -> str:
    if call.ah == 0x39:
        return "dos_mkdir"
    if call.ah == 0x3A:
        return "dos_rmdir"
    if call.ah == 0x3B:
        return "dos_chdir"
    if call.ah == 0x09:
        return "dos_print_dollar_string"
    if call.ah == 0x30:
        return "dos_get_version"
    if call.ah == 0x3C:
        return "dos_creat"
    if call.ah == 0x3D:
        return "dos_open"
    if call.ah == 0x3E:
        return "dos_close"
    if call.ah == 0x3F:
        return "dos_read"
    if call.ah == 0x40:
        return "dos_write"
    if call.ah == 0x42:
        return "dos_lseek"
    if call.ah == 0x4A:
        return "dos_setblock"
    if call.ah == 0x4C:
        return "dos_exit"
    return "dos_int21"


def ensure_dos_service_hook(project, call: DOSInt21Call) -> tuple[int, str]:
    addr = dos_service_addr(call)
    name = dos_service_name(call)

    if not project.is_hooked(addr):
        no_ret = call.ah == 0x4C

        def _run(self):  # pylint:disable=unused-argument
            if no_ret:
                code = getattr(self.state.regs, "al", claripy.BVV(0, 8))
                self.exit(claripy.ZeroExt(8, code))
            return claripy.BVS(f"{name}_ax", 16, explicit_name=True)

        proc_cls = type(
            f"{name.title().replace('_', '')}Procedure",
            (SimProcedure,),
            {
                "display_name": name,
                "NO_RET": no_ret,
                "run": _run,
            },
        )
        project.hook(addr, proc_cls(), replace=True)

    return addr, name


def normalize_api_style(api_style: str) -> str:
    if api_style in {"dos", "msc", "compiler"}:
        return "dos"
    return api_style


def infer_com_region(path: Path, *, base_addr: int, window: int, arch) -> tuple[int, int]:
    """
    Infer a bounded `.COM` code region by scanning until a likely terminator.

    This keeps tiny DOS stubs from decompiling their trailing strings as code.
    """

    data = path.read_bytes()
    end_limit = min(len(data), window)
    current = 0
    ah = None

    while current < end_limit:
        chunk = data[current : current + 16]
        insn = next(arch.capstone.disasm(chunk, base_addr + current, 1), None)
        if insn is None:
            break

        text = f"{insn.mnemonic} {insn.op_str}".strip().lower()
        if text.startswith("mov ah, "):
            ah = int(text.split(", ", 1)[1], 0)
        elif text.startswith("mov ax, "):
            ax = int(text.split(", ", 1)[1], 0)
            ah = (ax >> 8) & 0xFF

        current += insn.size

        if insn.mnemonic == "int":
            if insn.op_str.lower() == "0x20":
                break
            if insn.op_str.lower() == "0x21" and ah == 0x4C:
                break
            if insn.op_str.lower() == "0x27":
                break
        if insn.mnemonic in {"ret", "retf", "iret", "jmp"}:
            break

    return base_addr, base_addr + max(current, 1)


def _decode_com_ascii_string(binary_path: Path | None, dx: int | None, *, terminator: int) -> str | None:
    if binary_path is None or binary_path.suffix.lower() != ".com" or dx is None or dx < 0x100:
        return None
    try:
        data = binary_path.read_bytes()
    except OSError:
        return None

    start = dx - 0x100
    if start < 0 or start >= len(data):
        return None
    end = data.find(bytes([terminator]), start)
    if end == -1:
        return None
    raw = data[start:end]
    if not raw:
        return ""
    if any(byte < 0x20 or byte > 0x7E for byte in raw):
        return None
    text = raw.decode("ascii", errors="ignore")
    return text.replace("\\", "\\\\").replace('"', '\\"')


def _coerce_path(binary_path: Path | str | None) -> Path | None:
    if binary_path is None or isinstance(binary_path, Path):
        return binary_path
    return Path(binary_path)


def decode_com_dollar_string(binary_path: Path | str | None, dx: int | None) -> str | None:
    binary_path = _coerce_path(binary_path)
    return _decode_com_ascii_string(binary_path, dx, terminator=ord("$"))


def decode_com_c_string(binary_path: Path | str | None, dx: int | None) -> str | None:
    binary_path = _coerce_path(binary_path)
    return _decode_com_ascii_string(binary_path, dx, terminator=0)


def _format_imm(value: int) -> str:
    if 0 <= value <= 9:
        return str(value)
    return f"0x{value:x}"


def _format_mem_operand(ins, operand) -> str:
    mem = getattr(operand, "mem", None)
    if mem is None:
        return "<mem>"

    pieces: list[str] = []
    base = getattr(mem, "base", 0)
    index = getattr(mem, "index", 0)
    disp = getattr(mem, "disp", 0)
    if base:
        pieces.append(ins.reg_name(base).lower())
    if index:
        pieces.append(ins.reg_name(index).lower())
    if disp:
        disp_text = hex(abs(disp)) if abs(disp) > 9 else str(abs(disp))
        if pieces:
            pieces.append(("+" if disp >= 0 else "-") + disp_text)
        else:
            pieces.append(("-" if disp < 0 else "") + disp_text)
    if not pieces:
        pieces.append("0")
    return "[" + "".join(pieces) + "]"


def _operand_expr(ins, operand) -> tuple[int | None, str | None]:
    if operand.type == 1:
        reg_name = ins.reg_name(operand.reg).lower()
        return None, reg_name
    if operand.type == 2:
        imm = operand.imm & 0xFFFF
        return imm, _format_imm(imm)
    if operand.type == 3:
        return None, _format_mem_operand(ins, operand)
    return None, None


def collect_dos_int21_calls(function, binary_path: Path | str | None = None) -> list[DOSInt21Call]:
    binary_path = _coerce_path(binary_path)
    project = function.project
    if project is None:
        return []

    calls: list[DOSInt21Call] = []
    regs: dict[str, tuple[int | None, str | None]] = {
        "ah": (None, None),
        "al": (None, None),
        "ax": (None, None),
        "bx": (None, None),
        "cx": (None, None),
        "dx": (None, None),
    }

    def set_reg(reg_name: str, value: int | None, expr: str | None) -> None:
        regs[reg_name] = (value, expr)

        if reg_name == "ax":
            if value is not None:
                regs["ah"] = ((value >> 8) & 0xFF, _format_imm((value >> 8) & 0xFF))
                regs["al"] = (value & 0xFF, _format_imm(value & 0xFF))
            else:
                regs["ah"] = (None, None)
                regs["al"] = (None, None)
        elif reg_name == "ah":
            al_val, al_expr = regs["al"]
            if value is not None and al_val is not None:
                regs["ax"] = (((value & 0xFF) << 8) | (al_val & 0xFF), None)
            else:
                regs["ax"] = (None, None)
        elif reg_name == "al":
            ah_val, ah_expr = regs["ah"]
            if value is not None and ah_val is not None:
                regs["ax"] = ((((ah_val & 0xFF) << 8) | (value & 0xFF)), None)
            else:
                regs["ax"] = (None, None)

    for block_addr in sorted(getattr(function, "block_addrs_set", ())):
        block = project.factory.block(block_addr, opt_level=0)
        for ins in block.capstone.insns:
            operands = getattr(ins, "operands", ())
            if ins.mnemonic == "mov" and len(operands) == 2:
                dst, src = operands
                if dst.type == 1:
                    reg_name = ins.reg_name(dst.reg).lower()
                    if reg_name in regs:
                        value, expr = _operand_expr(ins, src)
                        set_reg(reg_name, value, expr)
            elif ins.mnemonic == "xor" and len(operands) == 2 and operands[0].type == 1 and operands[1].type == 1:
                dst_name = ins.reg_name(operands[0].reg).lower()
                src_name = ins.reg_name(operands[1].reg).lower()
                if dst_name == src_name:
                    if dst_name in regs:
                        set_reg(dst_name, 0, "0")
            elif ins.mnemonic == "int" and ins.op_str.lower() == "0x21":
                ah, ah_expr = regs["ah"]
                al, al_expr = regs["al"]
                ax, _ = regs["ax"]
                bx, bx_expr = regs["bx"]
                cx, cx_expr = regs["cx"]
                dx, dx_expr = regs["dx"]
                path_literal = None
                if ah in {0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x41}:
                    path_literal = decode_com_c_string(binary_path, dx)
                elif ah == 0x09:
                    path_literal = decode_com_dollar_string(binary_path, dx)
                calls.append(
                    DOSInt21Call(
                        insn_addr=ins.address,
                        ah=ah,
                        al=al,
                        ax=ax,
                        bx=bx,
                        cx=cx,
                        dx=dx,
                        ah_expr=ah_expr,
                        al_expr=al_expr,
                        bx_expr=bx_expr,
                        cx_expr=cx_expr,
                        dx_expr=dx_expr,
                        string_literal=path_literal,
                    )
                )
                set_reg("dx", None, None)

    return calls


def _dos_path_arg(call: DOSInt21Call, *, far_ptr: bool) -> str | None:
    if call.string_literal is not None:
        return f'"{call.string_literal}"'
    if call.dx is not None:
        cast = "const char far *" if far_ptr else "const char *"
        return f"({cast})0x{call.dx:x}"
    if call.dx_expr is not None:
        cast = "const char far *" if far_ptr else "const char *"
        return f"({cast}){call.dx_expr}"
    return None


def _dos_arg(value: int | None, expr: str | None) -> str | None:
    if value is not None:
        return _format_imm(value)
    return expr


def _dos_buffer_arg(call: DOSInt21Call, *, far_ptr: bool, const: bool) -> str | None:
    cast = "const void far *" if far_ptr and const else "void far *" if far_ptr else "const void *" if const else "void *"
    if call.dx is not None:
        return f"({cast})0x{call.dx:x}"
    if call.dx_expr is not None:
        return f"({cast}){call.dx_expr}"
    return None


def _dos_seek_offset_arg(call: DOSInt21Call) -> str:
    if call.cx is not None and call.dx is not None:
        return f"0x{(((call.cx & 0xFFFF) << 16) | (call.dx & 0xFFFF)):x}"
    high = _dos_arg(call.cx, call.cx_expr)
    low = _dos_arg(call.dx, call.dx_expr)
    if high is not None and low is not None:
        return f"MK_LONG({low}, {high})"
    if low is not None:
        return low
    return "0"


def render_dos_int21_call(call: DOSInt21Call, api_style: str) -> str:
    api_style = normalize_api_style(api_style)

    if api_style == "raw":
        return "dos_int21()"

    if api_style == "dos":
        if call.ah == 0x39:
            path = _dos_path_arg(call, far_ptr=True) or "NULL"
            return f"_dos_mkdir({path})"
        if call.ah == 0x3A:
            path = _dos_path_arg(call, far_ptr=True) or "NULL"
            return f"_dos_rmdir({path})"
        if call.ah == 0x3B:
            path = _dos_path_arg(call, far_ptr=True) or "NULL"
            return f"_dos_chdir({path})"
        if call.ah == 0x30:
            return "_dos_get_version()"
        if call.ah == 0x09:
            if call.string_literal is not None:
                return f'_dos_print_dollar_string("{call.string_literal}")'
            if call.dx is None:
                return "_dos_print_dollar_string()"
            return f"_dos_print_dollar_string((const char far *)0x{call.dx:x})"
        if call.ah == 0x3D:
            path = _dos_path_arg(call, far_ptr=True) or "NULL"
            mode = _dos_arg(call.al, call.al_expr) or "0"
            return f"_dos_open({path}, {mode})"
        if call.ah == 0x3C:
            path = _dos_path_arg(call, far_ptr=True) or "NULL"
            attrs = _dos_arg(call.cx, call.cx_expr) or "0"
            return f"_dos_creat({path}, {attrs})"
        if call.ah == 0x3E:
            handle = _dos_arg(call.bx, call.bx_expr) or "0"
            return f"_dos_close({handle})"
        if call.ah == 0x3F:
            handle = _dos_arg(call.bx, call.bx_expr) or "0"
            buffer = _dos_buffer_arg(call, far_ptr=True, const=False) or "NULL"
            count = _dos_arg(call.cx, call.cx_expr) or "0"
            return f"_dos_read({handle}, {buffer}, {count})"
        if call.ah == 0x40:
            handle = _dos_arg(call.bx, call.bx_expr) or "0"
            buffer = _dos_buffer_arg(call, far_ptr=True, const=True) or "NULL"
            count = _dos_arg(call.cx, call.cx_expr) or "0"
            return f"_dos_write({handle}, {buffer}, {count})"
        if call.ah == 0x42:
            handle = _dos_arg(call.bx, call.bx_expr) or "0"
            offset = _dos_seek_offset_arg(call)
            origin = _dos_arg(call.al, call.al_expr) or "0"
            return f"_dos_seek({handle}, {offset}, {origin})"
        if call.ah == 0x41:
            path = _dos_path_arg(call, far_ptr=True) or "NULL"
            return f"_dos_unlink({path})"
        if call.ah == 0x4A:
            return "_dos_setblock()"
        if call.ah == 0x4C:
            exit_code = call.ax & 0xFF if call.ax is not None else 0
            return f"_dos_exit({exit_code})"
        return "dos_int21()"

    if call.ah == 0x39:
        path = _dos_path_arg(call, far_ptr=False) or "NULL"
        return f"mkdir({path})"
    if call.ah == 0x3A:
        path = _dos_path_arg(call, far_ptr=False) or "NULL"
        return f"rmdir({path})"
    if call.ah == 0x3B:
        path = _dos_path_arg(call, far_ptr=False) or "NULL"
        return f"chdir({path})"
    if call.ah == 0x30:
        return "get_dos_version()"
    if call.ah == 0x09:
        if call.string_literal is not None:
            return f'print_dos_string("{call.string_literal}")'
        if call.dx is None:
            return "print_dos_string()"
        return f"print_dos_string((const char *)0x{call.dx:x})"
    if call.ah == 0x3D:
        path = _dos_path_arg(call, far_ptr=False) or "NULL"
        mode = _dos_arg(call.al, call.al_expr) or "0"
        return f"open({path}, {mode})"
    if call.ah == 0x3C:
        path = _dos_path_arg(call, far_ptr=False) or "NULL"
        attrs = _dos_arg(call.cx, call.cx_expr) or "0"
        return f"creat({path}, {attrs})"
    if call.ah == 0x3E:
        handle = _dos_arg(call.bx, call.bx_expr) or "0"
        return f"close({handle})"
    if call.ah == 0x3F:
        handle = _dos_arg(call.bx, call.bx_expr) or "0"
        buffer = _dos_buffer_arg(call, far_ptr=False, const=False) or "NULL"
        count = _dos_arg(call.cx, call.cx_expr) or "0"
        return f"read({handle}, {buffer}, {count})"
    if call.ah == 0x40:
        handle = _dos_arg(call.bx, call.bx_expr) or "0"
        buffer = _dos_buffer_arg(call, far_ptr=False, const=True) or "NULL"
        count = _dos_arg(call.cx, call.cx_expr) or "0"
        return f"write({handle}, {buffer}, {count})"
    if call.ah == 0x42:
        handle = _dos_arg(call.bx, call.bx_expr) or "0"
        offset = _dos_seek_offset_arg(call)
        origin = _dos_arg(call.al, call.al_expr) or "0"
        return f"lseek({handle}, {offset}, {origin})"
    if call.ah == 0x41:
        path = _dos_path_arg(call, far_ptr=False) or "NULL"
        return f"unlink({path})"
    if call.ah == 0x4A:
        return "resize_dos_memory_block()"
    if call.ah == 0x4C:
        exit_code = call.ax & 0xFF if call.ax is not None else 0
        return f"exit({exit_code})"
    return "dos_int21()"


def dos_helper_declarations(calls: list[DOSInt21Call], api_style: str) -> list[str]:
    api_style = normalize_api_style(api_style)
    if api_style == "raw":
        return []

    declarations: list[str] = []
    seen: set[str] = set()
    for call in calls:
        if api_style == "dos":
            if call.ah == 0x39:
                decl = "int _dos_mkdir(const char far *path);"
            elif call.ah == 0x3A:
                decl = "int _dos_rmdir(const char far *path);"
            elif call.ah == 0x3B:
                decl = "int _dos_chdir(const char far *path);"
            elif call.ah == 0x30:
                decl = "unsigned short _dos_get_version(void);"
            elif call.ah == 0x09:
                decl = "void _dos_print_dollar_string(const char far *s);"
            elif call.ah == 0x3D:
                decl = "int _dos_open(const char far *path, unsigned char mode);"
            elif call.ah == 0x3C:
                decl = "int _dos_creat(const char far *path, unsigned short attrs);"
            elif call.ah == 0x3E:
                decl = "int _dos_close(unsigned short handle);"
            elif call.ah == 0x3F:
                decl = "int _dos_read(unsigned short handle, void far *buffer, unsigned short count);"
            elif call.ah == 0x40:
                decl = "int _dos_write(unsigned short handle, const void far *buffer, unsigned short count);"
            elif call.ah == 0x42:
                decl = "long _dos_seek(unsigned short handle, long offset, unsigned char origin);"
            elif call.ah == 0x41:
                decl = "int _dos_unlink(const char far *path);"
            elif call.ah == 0x4A:
                decl = "int _dos_setblock(void);"
            elif call.ah == 0x4C:
                decl = "void _dos_exit(unsigned char status);"
            else:
                decl = "unsigned short dos_int21(void);"
        else:
            if call.ah == 0x39:
                decl = "int mkdir(const char *path);"
            elif call.ah == 0x3A:
                decl = "int rmdir(const char *path);"
            elif call.ah == 0x3B:
                decl = "int chdir(const char *path);"
            elif call.ah == 0x30:
                decl = "int get_dos_version(void);"
            elif call.ah == 0x09:
                decl = "void print_dos_string(const char *s);"
            elif call.ah == 0x3D:
                decl = "int open(const char *path, int oflag);"
            elif call.ah == 0x3C:
                decl = "int creat(const char *path, int attrs);"
            elif call.ah == 0x3E:
                decl = "int close(int fd);"
            elif call.ah == 0x3F:
                decl = "int read(int fd, void *buf, unsigned int count);"
            elif call.ah == 0x40:
                decl = "int write(int fd, const void *buf, unsigned int count);"
            elif call.ah == 0x42:
                decl = "long lseek(int fd, long offset, int whence);"
            elif call.ah == 0x41:
                decl = "int unlink(const char *path);"
            elif call.ah == 0x4A:
                decl = "int resize_dos_memory_block(void);"
            elif call.ah == 0x4C:
                decl = "void exit(int status);"
            else:
                decl = "int dos_int21(void);"
        if decl not in seen:
            seen.add(decl)
            declarations.append(decl)
    return declarations


def _absolute_mem_disp(operand) -> int | None:
    mem = getattr(operand, "mem", None)
    if mem is None:
        return None
    if getattr(mem, "base", 0) != 0 or getattr(mem, "index", 0) != 0:
        return None
    return getattr(mem, "disp", 0) & 0xFFFF


def _initial_cs_linear_base(project) -> int | None:
    initial_regs = getattr(project.loader.main_object, "initial_register_values", None)
    if not initial_regs:
        return None
    cs = initial_regs.get("cs")
    if cs is None:
        return None
    return (cs & 0xFFFF) << 4


def resolve_direct_call_target_from_block(project, block_addr: int) -> int | None:
    """
    Recover a direct call target from the last instruction in a block.

    This is intentionally narrow and only handles the direct near/far forms
    that show up in our DOS samples. Indirect calls still return ``None``.
    """

    block = project.factory.block(block_addr, opt_level=0)
    insns = getattr(block.capstone, "insns", ())
    if not insns:
        return None

    last = insns[-1]
    operands = getattr(last.insn, "operands", ())

    if last.mnemonic == "lcall" and len(operands) == 2 and all(op.type == 2 for op in operands):
        seg = operands[0].imm & 0xFFFF
        off = operands[1].imm & 0xFFFF
        return (seg << 4) + off

    if last.mnemonic == "call" and len(operands) == 1 and operands[0].type == 2:
        return operands[0].imm & 0xFFFF

    return None


def resolve_stored_near_call_target_from_function(function, callsite_addr: int) -> int | None:
    """
    Recover a near call target from a startup-built absolute pointer slot.

    This is intentionally narrow. It only handles patterns like:

        mov word ptr ss:[0x60], 0x01a2
        ...
        call word ptr [0x60]

    which appear in MSC startup code for real-mode DOS.
    """

    project = function.project
    if project is None:
        return None

    block = project.factory.block(callsite_addr, opt_level=0)
    insns = getattr(block.capstone, "insns", ())
    if not insns:
        return None
    last = insns[-1]
    operands = getattr(last.insn, "operands", ())
    if last.mnemonic != "call" or len(operands) != 1 or operands[0].type != 3:
        return None

    slot_disp = _absolute_mem_disp(operands[0])
    if slot_disp is None:
        return None

    cs_base = _initial_cs_linear_base(project)
    if cs_base is None:
        return None

    prior_insns = []
    for addr in sorted(function.block_addrs_set):
        if addr >= callsite_addr:
            continue
        prior_block = project.factory.block(addr, opt_level=0)
        prior_insns.extend(getattr(prior_block.capstone, "insns", ()))

    for ins in reversed(prior_insns):
        if ins.address >= callsite_addr:
            continue
        opers = getattr(ins.insn, "operands", ())
        if ins.mnemonic != "mov" or len(opers) != 2:
            continue
        dst, src = opers
        if dst.type != 3 or src.type != 2:
            continue
        dst_disp = _absolute_mem_disp(dst)
        if dst_disp != slot_disp:
            continue
        return cs_base + (src.imm & 0xFFFF)

    return None


def collect_direct_far_call_targets(function) -> list[FarCallTarget]:
    """
    Recover direct or startup-recoverable call targets directly from lifted blocks.

    angr's stock call-target recovery does not currently understand the x86-16
    `CS:IP` far-call pattern very well, so medium-model DOS startup code often
    ends up with `UnresolvableCallTarget` call edges even when the block itself
    is fully understood. This helper keeps the workaround small, explicit, and
    reusable for CLI tooling and tests.
    """

    if function.project is None or function.project.arch.name != "86_16":
        return []

    project = function.project
    recovered: list[FarCallTarget] = []

    for callsite_addr in sorted(function.get_call_sites()):
        target_addr = resolve_direct_call_target_from_block(project, callsite_addr)
        if target_addr is None:
            target_addr = resolve_stored_near_call_target_from_function(function, callsite_addr)
        # Real-mode far calls commonly land below 64 KiB once segment:offset is
        # linearized (for example 0x0114:0x0240 -> 0x1380). Only discard calls
        # we still failed to resolve, not low linear addresses.
        if target_addr is None:
            continue

        recovered.append(
            FarCallTarget(
                callsite_addr=callsite_addr,
                target_addr=target_addr,
                return_addr=function.get_call_return(callsite_addr),
            )
        )

    return recovered


def patch_far_call_sites(function, far_targets: list[FarCallTarget]) -> bool:
    """
    Rewrite Function._call_sites for immediate far calls recovered from blocks.

    CFGFast currently leaves some x86-16 far callsites pointing at a bogus short
    target (for example `0x14`) even when the block disassembly clearly shows an
    immediate `seg:off` far call. The decompiler reads `Function.get_call_target()`
    from `_call_sites`, so patching those entries gives downstream analyses a
    much better callee address without needing to modify site-packages angr.
    """

    changed = False

    for target in far_targets:
        old = function._call_sites.get(target.callsite_addr)
        new = (target.target_addr, target.return_addr)
        if old != new:
            function._call_sites[target.callsite_addr] = new
            changed = True

    return changed


def patch_dos_int21_call_sites(function, binary_path: Path | str | None = None) -> bool:
    """
    Rewrite Function._call_sites for recoverable int 21h services.

    This gives the decompiler service-specific pseudo-callees instead of a
    single undifferentiated `dos_int21` hook at every site.
    """

    project = function.project
    if project is None:
        return False

    changed = False
    for call in collect_dos_int21_calls(function, binary_path):
        target_addr, name = ensure_dos_service_hook(project, call)
        return_addr = function.get_call_return(call.insn_addr)
        new = (target_addr, return_addr)
        old = function._call_sites.get(call.insn_addr)
        if old != new:
            function._call_sites[call.insn_addr] = new
            changed = True
        callee = project.kb.functions.function(addr=target_addr, create=True)
        if callee is not None:
            callee.name = name
            callee._init_prototype_and_calling_convention()

    return changed


def extend_cfg_for_far_calls(project, function, *, entry_window: int, callee_window: int = 0x80):
    """
    Re-run CFG with direct far callees seeded as extra function starts.

    This keeps bounded DOS startup recovery focused on the functions actually
    reached by immediate far calls, instead of forcing a broad CFG window that
    quickly runs into unrelated unsupported instructions.
    """

    far_targets = collect_direct_far_call_targets(function)
    if not far_targets:
        return None

    patch_far_call_sites(function, far_targets)

    function_starts = [function.addr, *(target.target_addr for target in far_targets)]
    regions = [(function.addr, function.addr + entry_window)]
    regions.extend((target.target_addr, target.target_addr + callee_window) for target in far_targets)

    cfg = project.analyses.CFGFast(
        start_at_entry=False,
        function_starts=sorted(set(function_starts)),
        regions=regions,
        normalize=True,
        force_complete_scan=False,
    )
    all_targets = list(far_targets)
    if function.addr in cfg.functions:
        recovered_function = cfg.functions[function.addr]
        recovered_targets = collect_direct_far_call_targets(recovered_function)
        merged: dict[tuple[int, int], FarCallTarget] = {
            (target.callsite_addr, target.target_addr): target for target in far_targets
        }
        for target in recovered_targets:
            merged[(target.callsite_addr, target.target_addr)] = target
        all_targets = list(merged.values())
        patch_far_call_sites(recovered_function, all_targets)
    for target in all_targets:
        callee = cfg.kb.functions.function(addr=target.target_addr, create=True)
        if callee is not None:
            callee._init_prototype_and_calling_convention()
    return cfg
