#!/usr/bin/env python
# coding: utf-8
"""
ExtractDisassembly_IDA.py

IDA headless script: export per-function disassembly to text files.

Usage (example):
    idat.exe -A -S"ExtractDisassembly_IDA.py" input.exe
"""

from __future__ import print_function

import os
import sys
import traceback

import idc
import idautils
import ida_bytes
import ida_funcs
import ida_ua
import ida_auto
import ida_nalt

try:
    import ida_lines
except Exception:
    ida_lines = None


def log(msg):
    try:
        print(msg)
    except Exception:
        try:
            sys.stdout.write((u"%s\n" % msg).encode("utf-8", errors="ignore"))
        except Exception:
            pass


def sanitize_filename(name, max_len=100):
    if not name:
        name = "None"
    for ch in (".", ":", "<", ">", "*", "?", " ", "\"", "|", "\\", "/"):
        name = name.replace(ch, "_")
    safe = "".join(
        c
        if (u"0" <= c <= u"9") or (u"a" <= c <= u"z") or (u"A" <= c <= u"Z") or c in ("_", "-")
        else "_"
        for c in name
    )
    safe = safe.strip("_-")
    while "__" in safe:
        safe = safe.replace("__", "_")
    if len(safe) > max_len:
        safe = safe[:max_len]
    if not safe:
        return "sanitized_empty_name"
    return safe


def get_input_paths():
    """
    Try to obtain input file path & name in a way compatible with IDA 7.x/9.x.
    """
    # Path
    try:
        input_path = ida_nalt.get_input_file_path()
    except Exception:
        input_path_fn = getattr(idc, "get_input_file_path", None) or getattr(idc, "GetInputFilePath", None)
        input_path = input_path_fn() if callable(input_path_fn) else ""

    # Name
    try:
        input_name = ida_nalt.get_root_filename()
    except Exception:
        input_name_fn = getattr(idc, "get_input_file_name", None) or getattr(idc, "GetInputFile", None)
        if callable(input_name_fn):
            input_name = input_name_fn()
        else:
            input_name = os.path.basename(input_path) if input_path else ""

    if not input_name and input_path:
        input_name = os.path.basename(input_path)
    if not input_path and input_name:
        input_path = input_name
    if not input_name:
        input_name = "unknown_binary"
    return input_path, input_name


def compute_output_dir():
    """
    Output directory: <input_dir>/<base>_disassembly
    """
    input_path, input_name = get_input_paths()
    base_no_ext, _ = os.path.splitext(input_name)
    safe_base = sanitize_filename(base_no_ext)

    root_dir = os.path.dirname(input_path) if input_path else os.getcwd()
    root_dir = root_dir or "."
    out_dir = os.path.join(root_dir, safe_base + "_disassembly")

    if not os.path.exists(out_dir):
        os.makedirs(out_dir)
    return out_dir, safe_base


def _strip_tags(text):
    """
    Remove IDA color / tag codes from a disassembly line.
    """
    if not text:
        return ""

    # Prefer ida_lines.tag_remove if available
    if ida_lines is not None:
        tr = getattr(ida_lines, "tag_remove", None)
    else:
        tr = None

    if tr is None:
        tr = getattr(idc, "tag_remove", None)

    if callable(tr):
        try:
            return tr(text)
        except Exception:
            return text
    return text


def format_instr(ea):
    """
    Build one assembly line: ADDR  MNEM  OPERANDS  ; BYTES
    """
    try:
        # Skip non-code items to avoid noise
        try:
            if not ida_bytes.is_code(ida_bytes.get_full_flags(ea)):
                return ""
        except Exception:
            pass

        # Get plain disassembly line (no color tags)
        full_disasm = ""

        gen_line = getattr(idc, "generate_disasm_line", None)
        if callable(gen_line):
            flags = getattr(idc, "GENDSM_REMOVE_TAGS", 0)
            try:
                full_disasm = gen_line(ea, flags) or ""
            except Exception:
                full_disasm = ""

        if not full_disasm:
            disasm_line_fn = getattr(idc, "GetDisasm", None)
            if callable(disasm_line_fn):
                try:
                    full_disasm = disasm_line_fn(ea) or ""
                except Exception:
                    full_disasm = ""
            full_disasm = _strip_tags(full_disasm)

        mnem = ""
        op_str = ""
        if full_disasm:
            parts = full_disasm.split(None, 1)
            if parts:
                mnem = parts[0]
                if len(parts) > 1:
                    op_str = parts[1]

        size = ida_bytes.get_item_size(ea)
        try:
            b = ida_bytes.get_bytes(ea, size)
        except Exception:
            b = None

        if b:
            byte_str = " ".join("%02X" % (c if isinstance(c, int) else c & 0xFF) for c in b)
        else:
            byte_str = ""

        line = "%08X  %-10s %s" % (ea, mnem or "", op_str or "")
        if byte_str:
            line = "%-50s ; %s" % (line, byte_str)
        return line
    except Exception as e:
        log("[!] Error in format_instr at 0x%X: %s" % (ea, e))
        return ""


def ensure_auto_analysis():
    """
    Make sure auto-analysis has finished before we walk functions.
    """
    try:
        ida_auto.auto_wait()
    except Exception as e:
        log("[!] auto_wait failed: %s" % e)


def export_full_asm(out_dir, safe_base):
    """
    Export a single, full-coverage ASM file for the whole binary.
    Prefer IDA's built-in OFILE_ASM generator; fall back to a
    simple linear disassembly if needed.
    """
    input_path, input_name = get_input_paths()

    filename = "%s_all.asm" % safe_base
    path = os.path.join(out_dir, filename)

    # Try IDA's built-in generator first
    gen_file_fn = getattr(idc, "gen_file", None)
    ofile_asm = getattr(idc, "OFILE_ASM", None)
    badaddr = getattr(idc, "BADADDR", None)

    if callable(gen_file_fn) and ofile_asm is not None and badaddr is not None:
        try:
            gen_file_fn(ofile_asm, path, 0, badaddr, 0)
            log("[+] Full ASM (OFILE_ASM) generated: %s" % path)
            return path
        except Exception as e:
            log("[!] gen_file(OFILE_ASM) failed: %s" % e)

    # Fallback: simple linear disassembly over all segments
    try:
        import ida_segment  # type: ignore
    except Exception:
        ida_segment = None  # type: ignore

    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("; Full disassembly (fallback)\n")
            f.write("; Input file: %s\n" % (input_name or "unknown"))
            f.write("; Generated by ExtractDisassembly_IDA.py\n\n")

            for seg_start in idautils.Segments():
                seg_name = ""
                if ida_segment is not None:
                    try:
                        seg_name = ida_segment.get_segm_name(seg_start) or ""
                    except Exception:
                        seg_name = ""

                if seg_name:
                    f.write("; Segment %s at 0x%X\n" % (seg_name, seg_start))
                else:
                    f.write("; Segment at 0x%X\n" % seg_start)

                seg_end = idc.get_segm_end(seg_start) or seg_start
                ea = seg_start
                while ea < seg_end:
                    line = format_instr(ea)
                    if line:
                        f.write(line + "\n")
                    try:
                        ea = idc.next_head(ea, seg_end)
                    except Exception:
                        ea += 1
                f.write("\n")

        log("[+] Full ASM (fallback) generated: %s" % path)
        return path
    except Exception as e:
        log("[!] Failed to generate full ASM file: %s" % e)
        return None


def main():
    log("--- IDA Disassembly Extraction ---")

    ensure_auto_analysis()

    out_dir, safe_base = compute_output_dir()
    log("[*] Output directory: %s" % out_dir)

    # Export one full ASM file for the whole binary
    export_full_asm(out_dir, safe_base)

    count_funcs = 0
    count_ok = 0
    count_err = 0

    for func_ea in idautils.Functions():
        count_funcs += 1
        func_name = ida_funcs.get_func_name(func_ea)
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue

        safe_name = sanitize_filename(func_name)
        filename = "0x%X_%s.asm" % (func_ea, safe_name)
        path = os.path.join(out_dir, filename)

        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("; Function: %s\n" % func_name)
                f.write("; Start EA: 0x%X\n" % func_ea)
                f.write("\n")

                for ea in idautils.FuncItems(func_ea):
                    line = format_instr(ea)
                    if not line:
                        continue
                    f.write(line + "\n")

            count_ok += 1
        except Exception as e:
            log("[!] Error writing disassembly for %s @ 0x%X: %s" % (func_name, func_ea, e))
            log(traceback.format_exc())
            count_err += 1

        if count_funcs % 50 == 0:
            log("    Progress: %d functions processed" % count_funcs)

    log("[+] Disassembly extraction done.")
    log("    Total functions: %d" % count_funcs)
    log("    Succeeded:       %d" % count_ok)
    log("    Failed:          %d" % count_err)
    log("    Output dir:      %s" % out_dir)


if __name__ == "__main__":
    try:
        main()
    except Exception as _e:
        log("[!] Unhandled error in ExtractDisassembly_IDA.py: %s" % _e)
        log(traceback.format_exc())
    finally:
        try:
            idc.Exit(0)
        except Exception:
            pass
