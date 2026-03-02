#!/usr/bin/env python
# coding: utf-8
"""
ExtractPseudocode_IDA.py

IDA headless script: use Hex-Rays decompiler to export
per-function pseudocode into C-like text files.
"""

from __future__ import print_function

import os
import sys
import traceback

import idc
import idautils
import ida_funcs
import ida_hexrays
import ida_nalt
import ida_lines
import ida_auto
import ida_loader


# 反编译超时（秒级语义在 IDA 中并不精确，仅作为参考）
DECOMPILE_TIMEOUT_HINT = 120


def log(msg):
    try:
        print(msg)
    except Exception:
        sys.stdout.write((u"%s\n" % msg).encode("utf-8", errors="ignore"))


def sanitize_filename(name, max_len=100):
    if not name:
        name = "None"
    for ch in (".", ":", "<", ">", "*", "?", " ", "\"", "|", "\\", "/"):
        name = name.replace(ch, "_")
    safe = "".join(c if (u"0" <= c <= u"9") or (u"a" <= c <= u"z") or (u"A" <= c <= u"Z") or c in ("_", "-")
                   else "_"
                   for c in name)
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
    获取当前 IDB 对应的输入文件路径和名称。
    """
    # IDA 7.x/8.x/9.x Python3 APIs use ida_nalt helpers instead of old idc.GetInputFilePath/GetInputFile
    try:
        input_path = ida_nalt.get_input_file_path()
    except Exception:
        # Old-style fallback (may not exist on recent IDA)
        input_path = getattr(idc, "GetInputFilePath", lambda: "")()

    try:
        # get_root_filename 不含路径，只是文件名
        input_name = ida_nalt.get_root_filename()
    except Exception:
        input_name = getattr(idc, "GetInputFile", lambda: "")()

    # 兜底
    if not input_name and input_path:
        input_name = os.path.basename(input_path)
    if not input_path and input_name:
        input_path = input_name

    if not input_name:
        input_name = "unknown_binary"

    return input_path, input_name


def compute_output_dir():
    """
    输出目录：<input_dir>/decompiled_<base>
    （与 decompile_final.py 保持一致，便于脚本之间互通）
    """
    input_path, input_name = get_input_paths()
    base_no_ext, _ = os.path.splitext(input_name)
    safe_base = sanitize_filename(base_no_ext)

    root_dir = os.path.dirname(input_path) if input_path else os.getcwd()
    root_dir = root_dir or "."
    out_dir = os.path.join(root_dir, safe_base + "_pseudocode" )

    if not os.path.exists(out_dir):
        os.makedirs(out_dir)
    return out_dir, safe_base


def decompile_function(ea):
    """
    对单个函数进行反编译，返回 C 伪代码字符串。
    注意：在 headless 模式下，Hex-Rays 反编译器可能无法完全反编译复杂函数。
    这是 IDA 的已知限制。
    """
    try:
        cfunc = ida_hexrays.decompile(ea)
    except ida_hexrays.DecompilationFailure:
        return None
    except Exception:
        return None

    if not cfunc:
        return None

    result_lines = []
    
    try:
        lines_list = cfunc.get_pseudocode()
        if lines_list:
            for item in lines_list:
                try:
                    if hasattr(item, 'line'):
                        line_text = item.line
                    else:
                        line_text = str(item)
                    
                    # 去掉颜色/高亮标签，但保留前导空格以维持缩进
                    clean_text = ida_lines.tag_remove(line_text)
                    # 仅去掉行尾换行/空白，不动前导缩进
                    clean_text = clean_text.rstrip("\r\n")

                    # 过滤掉 JUMPOUT 这样的伪代码反编译失败标记
                    if clean_text.strip() and not clean_text.lstrip().startswith('JUMPOUT'):
                        result_lines.append(clean_text)
                except Exception:
                    pass
    except Exception as e:
        pass
    
    if result_lines:
        # 不再过滤 '{}' 等，这些在 C 伪代码中也有意义（代码块边界）
        return "\n".join(result_lines)
    
    return ""


def export_whole_program_pseudocode(out_dir, safe_base):
    """
    使用 ida_hexrays.decompile_many 生成整程序的一个大 C 伪代码文件。
    输出文件名：<out_dir>/<safe_base>_decompiled.c
    """
    try:
        # 确保自动分析已经完成
        try:
            ida_auto.auto_wait()
        except Exception:
            pass

        c_output = os.path.join(out_dir, "%s_decompiled.c" % safe_base)
        log("[*] Generating whole-program pseudocode: %s" % c_output)

        rc = ida_hexrays.decompile_many(
            c_output,
            None,
            ida_hexrays.VDRUN_NEWFILE
            | ida_hexrays.VDRUN_SILENT
            | ida_hexrays.VDRUN_MAYSTOP,
        )

        log("[+] decompile_many finished (rc=%s)" % rc)
        if not rc and not os.path.exists(c_output):
            log("[!] decompile_many returned false and output file not found.")
        elif os.path.exists(c_output):
            log("[+] Whole-program pseudocode written to: %s" % c_output)
    except Exception as e:
        log("[!] Error in export_whole_program_pseudocode: %s" % e)
        log(traceback.format_exc())


def main():
    log("--- IDA Pseudocode Extraction ---")
    log("[!] WARNING: Hex-Rays decompiler has known limitations in headless mode.")
    log("[!] Complex functions may not decompile properly. See HEXRAYS_HEADLESS_LIMITATION.md")
    log("")

    if not ida_hexrays.init_hexrays_plugin():
        log("[!] Hex-Rays decompiler is not available. Aborting pseudocode extraction.")
        return

    out_dir, safe_base = compute_output_dir()
    log("[*] Output directory: %s" % out_dir)

    # 先生成整程序的大伪代码文件（功能来自 decompile_final.py）
    export_whole_program_pseudocode(out_dir, safe_base)

    total_funcs = 0
    decompiled = 0
    failed = 0
    empty = 0

    # 再按函数导出伪代码到单独的 .c 文件
    for func_ea in idautils.Functions():
        total_funcs += 1
        func_name = ida_funcs.get_func_name(func_ea)

        if total_funcs % 50 == 0:
            log("    Progress: %d functions processed" % total_funcs)

        code = decompile_function(func_ea)
        if code is None:
            empty += 1
            if total_funcs <= 5:
                log("[*] Empty decompilation for %s @ 0x%X" % (func_name, func_ea))
            continue
        
        safe_name = sanitize_filename(func_name)
        filename = "0x%X_%s.c" % (func_ea, safe_name)
        path = os.path.join(out_dir, filename)

        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("// Function: %s\n" % func_name)
                f.write("// Start EA: 0x%X\n" % func_ea)
                f.write("// Decompile timeout hint: %d seconds\n" % DECOMPILE_TIMEOUT_HINT)
                if code:
                    f.write("\n")
                    f.write(code)
                else:
                    f.write("\n// [WARNING] Empty decompilation in headless mode\n")
            decompiled += 1
        except Exception as e:
            log("[!] Error writing pseudocode for %s @ 0x%X: %s" % (func_name, func_ea, e))
            log(traceback.format_exc())
            failed += 1

    log("[+] Pseudocode extraction done.")
    log("    Total functions:   %d" % total_funcs)
    log("    Successfully done: %d" % decompiled)
    log("    Empty/Failed:      %d" % (empty + failed))
    log("    Output dir:        %s" % out_dir)
    log("")
    log("[!] NOTE: Hex-Rays in headless mode may produce incomplete results.")
    log("[!] For full pseudocode, use IDA GUI (F5) or switch to Ghidra.")
    log("[!] See HEXRAYS_HEADLESS_LIMITATION.md for details.")


if __name__ == "__main__":
    try:
        main()
    except Exception as _e:
        log("[!] Unhandled error in ExtractPseudocode_IDA.py: %s" % _e)
        log(traceback.format_exc())
    finally:
        try:
            idc.Exit(0)
        except Exception:
            pass
