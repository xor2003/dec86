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
class InterruptCall:
    insn_addr: int
    vector: int = 0x21
    ah: int | None = None
    al: int | None = None
    ax: int | None = None
    bx: int | None = None
    cx: int | None = None
    dx: int | None = None
    si: int | None = None
    di: int | None = None
    bh: int | None = None
    bl: int | None = None
    ch: int | None = None
    cl: int | None = None
    dh: int | None = None
    dl: int | None = None
    ds: int | None = None
    es: int | None = None
    ss: int | None = None
    cs: int | None = None
    ah_expr: str | None = None
    al_expr: str | None = None
    ax_expr: str | None = None
    bx_expr: str | None = None
    cx_expr: str | None = None
    dx_expr: str | None = None
    si_expr: str | None = None
    di_expr: str | None = None
    bh_expr: str | None = None
    bl_expr: str | None = None
    ch_expr: str | None = None
    cl_expr: str | None = None
    dh_expr: str | None = None
    dl_expr: str | None = None
    ds_expr: str | None = None
    es_expr: str | None = None
    ss_expr: str | None = None
    cs_expr: str | None = None
    string_literal: str | None = None


DOSInt21Call = InterruptCall


@dataclass(frozen=True)
class InterruptServiceSpec:
    vector: int
    pseudo_name: str
    dos_name: str
    modern_name: str
    render_kind: str = "generic"
    default_output: str = "return"


INTERRUPT_SERVICE_SPECS: dict[int, InterruptServiceSpec] = {
    0x10: InterruptServiceSpec(0x10, "bios_int10_video", "_bios_int10_video", "_bios_int10_video", "wrapper"),
    0x11: InterruptServiceSpec(0x11, "bios_equiplist", "_bios_equiplist", "_bios_equiplist", "direct"),
    0x12: InterruptServiceSpec(0x12, "bios_memsize", "_bios_memsize", "_bios_memsize", "direct"),
    0x13: InterruptServiceSpec(0x13, "bios_int13_disk", "_bios_disk", "_bios_disk", "wrapper"),
    0x14: InterruptServiceSpec(0x14, "bios_int14_serial", "_bios_serialcom", "_bios_serialcom", "wrapper"),
    0x15: InterruptServiceSpec(0x15, "bios_int15_system", "_bios_int15_system", "_bios_int15_system", "wrapper"),
    0x16: InterruptServiceSpec(0x16, "bios_keybrd", "_bios_keybrd", "_bios_keybrd", "direct"),
    0x17: InterruptServiceSpec(0x17, "bios_int17_printer", "_bios_printer", "_bios_printer", "wrapper"),
    0x1A: InterruptServiceSpec(0x1A, "bios_timeofday", "_bios_timeofday", "_bios_timeofday", "direct"),
}


INTERRUPT_SERVICE_BASE_ADDR = 0xFE000
DOS_SERVICE_BASE_ADDR = INTERRUPT_SERVICE_BASE_ADDR


def _interrupt_service_key(call: InterruptCall) -> int:
    if call.vector == 0x21:
        return call.ah & 0xFF if call.ah is not None else 0
    return call.vector & 0xFF


def interrupt_service_addr(call: InterruptCall) -> int:
    return INTERRUPT_SERVICE_BASE_ADDR + _interrupt_service_key(call)


def interrupt_service_name(call: InterruptCall, api_style: str = "pseudo") -> str:
    spec = INTERRUPT_SERVICE_SPECS.get(call.vector)
    if spec is not None:
        if api_style == "pseudo":
            return spec.pseudo_name
        if api_style in {"dos", "msc", "compiler"}:
            return spec.dos_name
        return spec.modern_name

    if call.vector == 0x21:
        if call.ah == 0x0E:
            return "dos_set_current_drive" if api_style == "pseudo" else "_dos_setdrive"
        if call.ah == 0x39:
            return "dos_mkdir" if api_style == "pseudo" else "_dos_mkdir"
        if call.ah == 0x3A:
            return "dos_rmdir" if api_style == "pseudo" else "_dos_rmdir"
        if call.ah == 0x3B:
            return "dos_chdir" if api_style == "pseudo" else "_dos_chdir"
        if call.ah == 0x47:
            return "dos_get_current_directory" if api_style == "pseudo" else "_dos_getcwd"
        if call.ah == 0x09:
            return "dos_print_dollar_string" if api_style == "pseudo" else "_dos_print_dollar_string"
        if call.ah == 0x30:
            return "dos_get_version" if api_style == "pseudo" else "_dos_get_version"
        if call.ah == 0x3C:
            return "dos_creat" if api_style == "pseudo" else "_dos_creat"
        if call.ah == 0x3D:
            return "dos_open" if api_style == "pseudo" else "_dos_open"
        if call.ah == 0x3E:
            return "dos_close" if api_style == "pseudo" else "_dos_close"
        if call.ah == 0x3F:
            return "dos_read" if api_style == "pseudo" else "_dos_read"
        if call.ah == 0x40:
            return "dos_write" if api_style == "pseudo" else "_dos_write"
        if call.ah == 0x42:
            return "dos_lseek" if api_style == "pseudo" else "_dos_seek"
        if call.ah == 0x4A:
            return "dos_setblock" if api_style == "pseudo" else "_dos_setblock"
        if call.ah == 0x4C:
            return "dos_exit" if api_style == "pseudo" else "_dos_exit"
        return "dos_int21"

    if call.vector == 0x10:
        return "bios_int10_video" if api_style == "pseudo" else "_bios_int10_video"
    if call.vector == 0x11:
        return "bios_equiplist" if api_style == "pseudo" else "_bios_equiplist"
    if call.vector == 0x12:
        return "bios_memsize" if api_style == "pseudo" else "_bios_memsize"
    if call.vector == 0x13:
        return "bios_int13_disk" if api_style == "pseudo" else "_bios_disk"
    if call.vector == 0x14:
        return "bios_int14_serial" if api_style == "pseudo" else "_bios_serialcom"
    if call.vector == 0x15:
        return "bios_int15_system" if api_style == "pseudo" else "_bios_int15_system"
    if call.vector == 0x16:
        return "bios_keybrd" if api_style == "pseudo" else "_bios_keybrd"
    if call.vector == 0x17:
        return "bios_int17_printer" if api_style == "pseudo" else "_bios_printer"
    if call.vector == 0x1A:
        return "bios_timeofday" if api_style == "pseudo" else "_bios_timeofday"
    return f"int{call.vector:02x}"


def dos_service_name(call: InterruptCall) -> str:
    return interrupt_service_name(call, "pseudo")


def _interrupt_service_name_for_helper(call: InterruptCall, api_style: str) -> str:
    if api_style in {"dos", "msc", "compiler"}:
        return interrupt_service_name(call, "dos")
    return interrupt_service_name(call, "pseudo")


def interrupt_service_spec(call: InterruptCall) -> InterruptServiceSpec | None:
    if call.vector == 0x21:
        return None
    return INTERRUPT_SERVICE_SPECS.get(call.vector)


def dos_service_addr(call: InterruptCall) -> int:
    return interrupt_service_addr(call)


def ensure_interrupt_service_hook(project, call: InterruptCall) -> tuple[int, str]:
    addr = interrupt_service_addr(call)
    name = _interrupt_service_name_for_helper(call, "pseudo")

    if not project.is_hooked(addr):
        no_ret = call.vector == 0x21 and call.ah == 0x4C

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


def ensure_dos_service_hook(project, call: InterruptCall) -> tuple[int, str]:
    return ensure_interrupt_service_hook(project, call)


def normalize_api_style(api_style: str) -> str:
    if api_style in {"pseudo", "service"}:
        return "pseudo"
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


def collect_interrupt_calls(
    function,
    binary_path: Path | str | None = None,
    *,
    vectors: set[int] | None = None,
) -> list[InterruptCall]:
    binary_path = _coerce_path(binary_path)
    project = function.project
    if project is None:
        return []

    calls: list[InterruptCall] = []
    regs: dict[str, tuple[int | None, str | None]] = {
        "ah": (None, None),
        "al": (None, None),
        "ax": (None, None),
        "bh": (None, None),
        "bl": (None, None),
        "bx": (None, None),
        "ch": (None, None),
        "cl": (None, None),
        "cx": (None, None),
        "dh": (None, None),
        "dl": (None, None),
        "dx": (None, None),
        "si": (None, None),
        "di": (None, None),
        "ds": (None, None),
        "es": (None, None),
        "ss": (None, None),
        "cs": (None, None),
    }

    def set_reg(reg_name: str, value: int | None, expr: str | None) -> None:
        regs[reg_name] = (value, expr)

        if reg_name in {"ax", "bx", "cx", "dx"}:
            if value is not None:
                high = (value >> 8) & 0xFF
                low = value & 0xFF
                regs[f"{reg_name[0]}h"] = (high, _format_imm(high))
                regs[f"{reg_name[0]}l"] = (low, _format_imm(low))
            else:
                regs[f"{reg_name[0]}h"] = (None, None)
                regs[f"{reg_name[0]}l"] = (None, None)
        elif reg_name in {"ah", "al"}:
            high, _ = regs["ah"]
            low, _ = regs["al"]
            if high is not None and low is not None:
                regs["ax"] = (((high & 0xFF) << 8) | (low & 0xFF), None)
            else:
                regs["ax"] = (None, None)
        elif reg_name in {"bh", "bl"}:
            high, _ = regs["bh"]
            low, _ = regs["bl"]
            if high is not None and low is not None:
                regs["bx"] = (((high & 0xFF) << 8) | (low & 0xFF), None)
            else:
                regs["bx"] = (None, None)
        elif reg_name in {"ch", "cl"}:
            high, _ = regs["ch"]
            low, _ = regs["cl"]
            if high is not None and low is not None:
                regs["cx"] = (((high & 0xFF) << 8) | (low & 0xFF), None)
            else:
                regs["cx"] = (None, None)
        elif reg_name in {"dh", "dl"}:
            high, _ = regs["dh"]
            low, _ = regs["dl"]
            if high is not None and low is not None:
                regs["dx"] = (((high & 0xFF) << 8) | (low & 0xFF), None)
            else:
                regs["dx"] = (None, None)

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
                if dst_name == src_name and dst_name in regs:
                    set_reg(dst_name, 0, "0")
            elif ins.mnemonic == "int":
                vector_text = ins.op_str.lower().strip()
                try:
                    vector = int(vector_text, 0) & 0xFF
                except ValueError:
                    continue
                if vectors is not None and vector not in vectors:
                    continue

                ah, ah_expr = regs["ah"]
                al, al_expr = regs["al"]
                ax, ax_expr = regs["ax"]
                bh, bh_expr = regs["bh"]
                bl, bl_expr = regs["bl"]
                bx, bx_expr = regs["bx"]
                ch, ch_expr = regs["ch"]
                cl, cl_expr = regs["cl"]
                cx, cx_expr = regs["cx"]
                dh, dh_expr = regs["dh"]
                dl, dl_expr = regs["dl"]
                dx, dx_expr = regs["dx"]
                si, si_expr = regs["si"]
                di, di_expr = regs["di"]
                ds, ds_expr = regs["ds"]
                es, es_expr = regs["es"]
                ss, ss_expr = regs["ss"]
                cs, cs_expr = regs["cs"]
                path_literal = None
                if vector == 0x21 and ah in {0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x41}:
                    path_literal = decode_com_c_string(binary_path, dx)
                elif vector == 0x21 and ah == 0x09:
                    path_literal = decode_com_dollar_string(binary_path, dx)
                calls.append(
                    InterruptCall(
                        insn_addr=ins.address,
                        vector=vector,
                        ah=ah,
                        al=al,
                        ax=ax,
                        bh=bh,
                        bl=bl,
                        bx=bx,
                        ch=ch,
                        cl=cl,
                        cx=cx,
                        dh=dh,
                        dl=dl,
                        dx=dx,
                        si=si,
                        di=di,
                        ds=ds,
                        es=es,
                        ss=ss,
                        cs=cs,
                        ah_expr=ah_expr,
                        al_expr=al_expr,
                        ax_expr=ax_expr,
                        bh_expr=bh_expr,
                        bl_expr=bl_expr,
                        bx_expr=bx_expr,
                        ch_expr=ch_expr,
                        cl_expr=cl_expr,
                        cx_expr=cx_expr,
                        dh_expr=dh_expr,
                        dl_expr=dl_expr,
                        dx_expr=dx_expr,
                        si_expr=si_expr,
                        di_expr=di_expr,
                        ds_expr=ds_expr,
                        es_expr=es_expr,
                        ss_expr=ss_expr,
                        cs_expr=cs_expr,
                        string_literal=path_literal,
                    )
                )
                if vector == 0x21:
                    set_reg("dx", None, None)

    return calls


def collect_dos_int21_calls(function, binary_path: Path | str | None = None) -> list[DOSInt21Call]:
    return [call for call in collect_interrupt_calls(function, binary_path, vectors={0x21}) if call.vector == 0x21]


def collect_interrupt_service_calls(
    function,
    binary_path: Path | str | None = None,
    *,
    vectors: set[int] | None = None,
) -> list[InterruptCall]:
    return collect_interrupt_calls(function, binary_path, vectors=vectors)


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


def _dos_si_buffer_arg(call: DOSInt21Call, *, far_ptr: bool, const: bool) -> str | None:
    cast = "const char far *" if far_ptr and const else "char far *" if far_ptr else "const char *" if const else "char *"
    if call.si is not None:
        return f"({cast})0x{call.si:x}"
    if call.si_expr is not None:
        return f"({cast}){call.si_expr}"
    return None


def _dos_drive_arg(call: DOSInt21Call) -> str | None:
    if call.dl is not None:
        return _format_imm(call.dl)
    return call.dl_expr


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

    if api_style == "pseudo":
        name = dos_service_name(call)
        if call.ah == 0x0E:
            drive = _dos_drive_arg(call) or "0"
            return f"{name}({drive})"
        if call.ah in {0x39, 0x3A, 0x3B, 0x41}:
            path = _dos_path_arg(call, far_ptr=False) or "NULL"
            return f"{name}({path})"
        if call.ah == 0x47:
            drive = _dos_drive_arg(call) or "0"
            buffer = _dos_si_buffer_arg(call, far_ptr=False, const=False) or "NULL"
            return f"{name}({drive}, {buffer})"
        if call.ah == 0x09:
            if call.string_literal is not None:
                return f'{name}("{call.string_literal}")'
            if call.dx is None:
                return f"{name}()"
            return f"{name}((const char *)0x{call.dx:x})"
        if call.ah == 0x30:
            return f"{name}()"
        if call.ah == 0x3D:
            path = _dos_path_arg(call, far_ptr=False) or "NULL"
            mode = _dos_arg(call.al, call.al_expr) or "0"
            return f"{name}({path}, {mode})"
        if call.ah == 0x3C:
            path = _dos_path_arg(call, far_ptr=False) or "NULL"
            attrs = _dos_arg(call.cx, call.cx_expr) or "0"
            return f"{name}({path}, {attrs})"
        if call.ah == 0x3E:
            handle = _dos_arg(call.bx, call.bx_expr) or "0"
            return f"{name}({handle})"
        if call.ah == 0x3F:
            handle = _dos_arg(call.bx, call.bx_expr) or "0"
            buffer = _dos_buffer_arg(call, far_ptr=False, const=False) or "NULL"
            count = _dos_arg(call.cx, call.cx_expr) or "0"
            return f"{name}({handle}, {buffer}, {count})"
        if call.ah == 0x40:
            handle = _dos_arg(call.bx, call.bx_expr) or "0"
            buffer = _dos_buffer_arg(call, far_ptr=False, const=True) or "NULL"
            count = _dos_arg(call.cx, call.cx_expr) or "0"
            return f"{name}({handle}, {buffer}, {count})"
        if call.ah == 0x42:
            handle = _dos_arg(call.bx, call.bx_expr) or "0"
            offset = _dos_seek_offset_arg(call)
            origin = _dos_arg(call.al, call.al_expr) or "0"
            return f"{name}({handle}, {offset}, {origin})"
        if call.ah == 0x4A:
            return f"{name}()"
        if call.ah == 0x4C:
            exit_code = call.ax & 0xFF if call.ax is not None else 0
            return f"{name}({exit_code})"
        return name + "()"

    if api_style == "dos":
        if call.ah == 0x0E:
            drive = _dos_drive_arg(call) or "0"
            return f"_dos_setdrive({drive})"
        if call.ah == 0x39:
            path = _dos_path_arg(call, far_ptr=True) or "NULL"
            return f"_dos_mkdir({path})"
        if call.ah == 0x3A:
            path = _dos_path_arg(call, far_ptr=True) or "NULL"
            return f"_dos_rmdir({path})"
        if call.ah == 0x3B:
            path = _dos_path_arg(call, far_ptr=True) or "NULL"
            return f"_dos_chdir({path})"
        if call.ah == 0x47:
            drive = _dos_drive_arg(call) or "0"
            buffer = _dos_si_buffer_arg(call, far_ptr=True, const=False) or "NULL"
            return f"_dos_getcwd({drive}, {buffer})"
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

    if call.ah == 0x0E:
        drive = _dos_drive_arg(call) or "0"
        return f"set_current_drive({drive})"
    if call.ah == 0x39:
        path = _dos_path_arg(call, far_ptr=False) or "NULL"
        return f"mkdir({path})"
    if call.ah == 0x3A:
        path = _dos_path_arg(call, far_ptr=False) or "NULL"
        return f"rmdir({path})"
    if call.ah == 0x3B:
        path = _dos_path_arg(call, far_ptr=False) or "NULL"
        return f"chdir({path})"
    if call.ah == 0x47:
        drive = _dos_drive_arg(call) or "0"
        buffer = _dos_si_buffer_arg(call, far_ptr=False, const=False) or "NULL"
        return f"get_current_directory({drive}, {buffer})"
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


def _render_simple_interrupt_call(call: InterruptCall, api_style: str) -> str:
    api_style = normalize_api_style(api_style)
    spec = interrupt_service_spec(call)
    if spec is None:
        return render_dos_int21_call(call, api_style)
    if api_style == "raw":
        return f"int{call.vector:02x}()"

    name = interrupt_service_name(call, api_style)
    if call.vector == 0x10 and api_style in {"dos", "msc", "compiler"}:
        return f"{name}(0x10)"
    if call.vector == 0x13 and api_style == "pseudo":
        return f"{name}()"
    return f"{name}()"


def render_interrupt_call(call: InterruptCall, api_style: str) -> str:
    spec = interrupt_service_spec(call)
    if spec is None:
        return render_dos_int21_call(call, api_style)
    return _render_simple_interrupt_call(call, api_style)


def dos_helper_declarations(calls: list[DOSInt21Call], api_style: str) -> list[str]:
    api_style = normalize_api_style(api_style)
    if api_style == "raw":
        return []

    declarations: list[str] = []
    seen: set[str] = set()
    for call in calls:
        if api_style == "pseudo":
            name = dos_service_name(call)
            if call.ah == 0x0E:
                decl = f"int {name}(int drive);"
            elif call.ah in {0x39, 0x3A, 0x3B, 0x41}:
                decl = f"int {name}(const char *path);"
            elif call.ah == 0x47:
                decl = f"int {name}(int drive, char *buffer);"
            elif call.ah == 0x09:
                decl = f"void {name}(const char *s);"
            elif call.ah == 0x30:
                decl = f"int {name}(void);"
            elif call.ah == 0x3D:
                decl = f"int {name}(const char *path, int mode);"
            elif call.ah == 0x3C:
                decl = f"int {name}(const char *path, int attrs);"
            elif call.ah == 0x3E:
                decl = f"int {name}(int handle);"
            elif call.ah == 0x3F:
                decl = f"int {name}(int handle, void *buffer, unsigned int count);"
            elif call.ah == 0x40:
                decl = f"int {name}(int handle, const void *buffer, unsigned int count);"
            elif call.ah == 0x42:
                decl = f"long {name}(int handle, long offset, int origin);"
            elif call.ah == 0x4A:
                decl = f"int {name}(void);"
            elif call.ah == 0x4C:
                decl = f"void {name}(int status);"
            else:
                decl = f"int {name}(void);"
        elif api_style == "dos":
            if call.ah == 0x0E:
                decl = "int _dos_setdrive(unsigned char drive);"
            elif call.ah == 0x39:
                decl = "int _dos_mkdir(const char far *path);"
            elif call.ah == 0x3A:
                decl = "int _dos_rmdir(const char far *path);"
            elif call.ah == 0x3B:
                decl = "int _dos_chdir(const char far *path);"
            elif call.ah == 0x47:
                decl = "int _dos_getcwd(unsigned char drive, char far *buffer);"
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
            if call.ah == 0x0E:
                decl = "int set_current_drive(int drive);"
            elif call.ah == 0x39:
                decl = "int mkdir(const char *path);"
            elif call.ah == 0x3A:
                decl = "int rmdir(const char *path);"
            elif call.ah == 0x3B:
                decl = "int chdir(const char *path);"
            elif call.ah == 0x47:
                decl = "int get_current_directory(int drive, char *buffer);"
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


def interrupt_service_declarations(calls: list[InterruptCall], api_style: str) -> list[str]:
    api_style = normalize_api_style(api_style)
    if api_style == "raw":
        return []

    declarations: list[str] = []
    seen: set[str] = set()
    for call in calls:
        spec = interrupt_service_spec(call)
        if spec is None:
            decls = dos_helper_declarations([call], api_style)
            for decl in decls:
                if decl not in seen:
                    seen.add(decl)
                    declarations.append(decl)
            continue

        if api_style == "pseudo":
            decl = f"int {spec.pseudo_name}(void);"
        elif api_style == "dos":
            decl = f"int {spec.dos_name}(void);"
        else:
            decl = f"int {spec.modern_name.lstrip('_')}(void);"
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


def seed_calling_conventions(cfg) -> None:
    for function in getattr(cfg, "functions", {}).values():
        try:
            function._init_prototype_and_calling_convention()
        except Exception:
            continue


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
    seed_calling_conventions(cfg)
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
    seed_calling_conventions(cfg)
    return cfg
