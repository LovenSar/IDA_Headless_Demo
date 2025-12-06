#!/usr/bin/env python
# coding: utf-8
"""
ExtractBinaryInfo_IDA.py

IDA headless script: extract symbol table, strings, segments/sections
and simple cross-reference information for each symbol.

设计目标：
- 尽量复用 Ghidra 版 ExtractBinaryInfo.py 的思路和输出结构
- 在不依赖复杂 IDA 内部标志的前提下，生成通用 CSV 文件

使用方式（示例）：
    idat.exe -A -S"ExtractBinaryInfo_IDA.py" input.exe

推荐配合本目录的 input_prehandle_start.bat 使用（自动复制脚本并创建输出目录）。
"""

from __future__ import print_function

import os
import csv
import sys
import traceback

import idc
import idautils
import ida_bytes
import ida_auto
import ida_segment
import ida_funcs
import ida_xref
import ida_nalt


# --- 配置 ---
# 是否仅为函数符号生成交叉引用 CSV
LIMIT_REFS_TO_FUNCTIONS_ONLY = False
# 生成单个符号交叉引用文件所需的最小引用数量
MIN_REFS_TO_CREATE_FILE = 1
# --- 配置结束 ---


def log(msg):
    try:
        print(msg)
    except Exception:
        # 在某些环境下编码可能出问题，做一次兜底
        sys.stdout.write((u"%s\n" % msg).encode("utf-8", errors="ignore"))


def sanitize_filename(name, max_len=100):
    """
    清理字符串，使其适合作为文件名的一部分。
    """
    if not name:
        name = "None"
    # 替换常见问题字符
    for ch in (".", ":", "<", ">", "*", "?", " ", "\"", "|", "\\", "/"):
        name = name.replace(ch, "_")
    safe_name = "".join(c if (u"0" <= c <= u"9") or (u"a" <= c <= u"z") or (u"A" <= c <= u"Z") or c in ("_", "-")
                        else "_"
                        for c in name)
    # 去掉首尾多余下划线
    safe_name = safe_name.strip("_-")
    # 压缩重复下划线
    while "__" in safe_name:
        safe_name = safe_name.replace("__", "_")
    # 长度限制
    if len(safe_name) > max_len:
        half = max_len // 3
        safe_name = safe_name[:half] + "..." + safe_name[-half:]
    if not safe_name:
        return "sanitized_empty_name"
    return safe_name


def ensure_dir(path):
    if not path:
        return
    if not os.path.exists(path):
        os.makedirs(path)


def write_csv(filepath, header, rows):
    """
    写 CSV 文件，返回写入的行数。
    """
    if not rows:
        log("[-] Skip empty CSV: %s" % os.path.basename(filepath))
        return 0

    parent = os.path.dirname(filepath)
    ensure_dir(parent)

    try:
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if header:
                writer.writerow(header)
            for row in rows:
                writer.writerow(["" if v is None else v for v in row])
        log("[+] Wrote %d rows -> %s" % (len(rows), filepath))
        return len(rows)
    except Exception as e:
        log("[!] Failed to write %s: %s" % (filepath, e))
        log(traceback.format_exc())
        return -1


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


def compute_output_dirs():
    """
    计算输出目录：
    - 默认以输入文件所在目录为根目录
    - 在根目录下创建：
        <base>_output/                主 CSV 输出目录
        <base>_output/xrefs/          交叉引用子目录
    - 其中 <base> 为输入文件名去掉扩展名并清理后的结果
    """
    input_path, input_name = get_input_paths()
    base_no_ext, _ = os.path.splitext(input_name)
    safe_base = sanitize_filename(base_no_ext)

    root_dir = os.path.dirname(input_path) if input_path else os.getcwd()
    root_dir = root_dir or "."

    info_dir = os.path.join(root_dir, safe_base + "_output")
    xref_dir = os.path.join(info_dir, "xrefs")

    ensure_dir(info_dir)
    ensure_dir(xref_dir)

    return safe_base, info_dir, xref_dir


def wait_for_auto_analysis():
    """Ensure IDA auto-analysis is finished before we query xrefs."""
    try:
        log("[*] Waiting for IDA auto-analysis to finish ...")
        ida_auto.auto_wait()
    except Exception:
        # Fallback for very old IDA versions
        try:
            auto_wait = getattr(idc, "auto_wait", None)
            if callable(auto_wait):
                auto_wait()
        except Exception:
            log("[!] auto_wait failed; continuing anyway")


def extract_symbols(symbol_csv_path):
    """
    提取符号列表（函数 / 标签等）。
    这里为了兼容性，使用 idautils.Names()，并用简单的类型判断。
    """
    log("[*] Extracting symbols ...")
    rows = []
    header = ["Name", "Address", "Type", "Source", "Is Global", "Is Primary", "Is External", "Namespace"]

    try:
        for ea, name in idautils.Names():
            addr_str = "0x%X" % ea

            func = ida_funcs.get_func(ea)
            sym_type = "FUNC" if func else "LABEL"

            # 这里的 Source/Global/External 定义比较松，只做简单标记
            source = "auto"
            is_global = "True" if func else "False"
            is_primary = "True"
            is_external = "False"
            namespace = "Global"

            rows.append([
                name,
                addr_str,
                sym_type,
                source,
                is_global,
                is_primary,
                is_external,
                namespace,
            ])
    except Exception as e:
        log("[!] Error while enumerating symbols: %s" % e)
        log(traceback.format_exc())

    write_csv(symbol_csv_path, header, rows)

    # 用于后续交叉引用统计
    return [(ea, name) for ea, name in idautils.Names()]


def extract_strings(strings_csv_path):
    """
    提取字符串信息。使用 idautils.Strings()。
    """
    log("[*] Extracting strings ...")
    header = ["String", "Address", "Length"]
    rows = []

    try:
        s_iter = idautils.Strings()
        s_iter.setup()  # 使用当前 IDB 的字符串设置
        for s in s_iter:
            try:
                value = str(s)
            except Exception:
                value = repr(s)
            addr = s.ea
            length = s.length
            rows.append([value, "0x%X" % addr, str(length)])
    except Exception as e:
        log("[!] Error while extracting strings: %s" % e)
        log(traceback.format_exc())

    write_csv(strings_csv_path, header, rows)


def extract_segments(segments_csv_path):
    """
    提取段信息（Segments）。
    """
    log("[*] Extracting segments ...")
    header = ["Name", "Start Address", "End Address", "Length", "Perm"]
    rows = []

    try:
        for seg_start in idautils.Segments():
            seg = ida_segment.getseg(seg_start)
            if not seg:
                continue
            name = idc.get_segm_name(seg_start)
            start = seg.start_ea
            end = seg.end_ea
            length = end - start
            perm = getattr(seg, "perm", 0)
            rows.append([
                name,
                "0x%X" % start,
                "0x%X" % end,
                str(length),
                "0x%X" % perm,
            ])
    except Exception as e:
        log("[!] Error while extracting segments: %s" % e)
        log(traceback.format_exc())

    write_csv(segments_csv_path, header, rows)


def extract_sections(sections_csv_path):
    """
    在 IDA 中，Section 和 Segment 的概念常常重合。
    这里简单地再次输出一份 segment 视图，作为“Sections”。
    """
    log("[*] Extracting sections (using segments as sections) ...")
    header = ["Name", "Start Address", "End Address", "Length"]
    rows = []

    try:
        for seg_start in idautils.Segments():
            seg = ida_segment.getseg(seg_start)
            if not seg:
                continue
            name = idc.get_segm_name(seg_start)
            start = seg.start_ea
            end = seg.end_ea
            length = end - start
            rows.append([
                name,
                "0x%X" % start,
                "0x%X" % end,
                str(length),
            ])
    except Exception as e:
        log("[!] Error while extracting sections: %s" % e)
        log(traceback.format_exc())

    write_csv(sections_csv_path, header, rows)


def extract_xrefs(all_symbols, safe_base, xrefs_dir):
    """
    为每个符号生成交叉引用 CSV（按符号拆分文件）。
    """
    log("[*] Extracting cross-references (may take a while) ...")

    header = ["Reference From Address", "Reference Type", "Containing Function"]
    generated_files = 0
    processed = 0

    for ea, name in all_symbols:
        processed += 1

        if LIMIT_REFS_TO_FUNCTIONS_ONLY:
            func = ida_funcs.get_func(ea)
            if not func:
                continue

        refs = []
        try:
            for xref in idautils.XrefsTo(ea, 0):
                from_ea = xref.frm
                func = ida_funcs.get_func(from_ea)
                if func:
                    func_name = ida_funcs.get_func_name(func.start_ea)
                else:
                    func_name = ""
                try:
                    ref_type = ida_xref.get_xref_type_name(xref.type)
                except Exception:
                    ref_type = str(xref.type)
                refs.append([
                    "0x%X" % from_ea,
                    ref_type,
                    func_name,
                ])
        except Exception as e:
            log("[!] Error while getting xrefs for %s @ 0x%X: %s" % (name, ea, e))
            continue

        if len(refs) < MIN_REFS_TO_CREATE_FILE:
            continue

        sanitized_name = sanitize_filename(name, max_len=60)
        filename = "%s_0x%X_%s_refs.csv" % (safe_base, ea, sanitized_name)
        filepath = os.path.join(xrefs_dir, filename)
        if write_csv(filepath, header, refs) > 0:
            generated_files += 1

        if processed % 500 == 0:
            log("    Progress: processed %d symbols, generated %d xref files" % (processed, generated_files))

    log("[*] Cross-reference extraction done. Files generated: %d" % generated_files)


def main():
    log("--- IDA Binary Info & XRef Extraction ---")

    wait_for_auto_analysis()

    safe_base, info_dir, xref_dir = compute_output_dirs()

    # 主 CSV 输出路径
    symbol_file = os.path.join(info_dir, safe_base + "_symbols.csv")
    strings_file = os.path.join(info_dir, safe_base + "_strings.csv")
    segments_file = os.path.join(info_dir, safe_base + "_segments.csv")
    sections_file = os.path.join(info_dir, safe_base + "_sections.csv")

    all_symbols = extract_symbols(symbol_file)
    extract_strings(strings_file)
    extract_segments(segments_file)
    extract_sections(sections_file)
    extract_xrefs(all_symbols, safe_base, xref_dir)

    log("[+] All binary info CSVs written under: %s" % info_dir)


if __name__ == "__main__":
    try:
        main()
    except Exception as _e:
        log("[!] Unhandled error in ExtractBinaryInfo_IDA.py: %s" % _e)
        log(traceback.format_exc())
    finally:
        # 确保在 headless 模式下可以退出 IDA
        try:
            idc.Exit(0)
        except Exception:
            pass
