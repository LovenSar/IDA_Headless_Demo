#!/usr/bin/env python
# coding: utf-8
"""
ExtractAll_IDA.py

单次 IDA 会话内依次导出：符号/字符串/段与节/xrefs、按函数反汇编与整包 asm、
Hex-Rays 伪代码（整包 + 按函数）。

断点续跑：
  - 进度保存在与输出同目录的 .ida_extract_state.json（按阶段：binary_info / disassembly / pseudocode）。
  - 中断后请用已有数据库再次启动，且不要加 -c（否则会新建库、进度文件仍可能被覆盖）。
    例：idat -A -S"ExtractAll_IDA.py" /path/to/work/re1.i64
  - 强制全量重跑：在脚本参数中加 --force，或环境变量 IDA_EXTRACT_FORCE=1。

安全退出：
  - 每个阶段成功结束后会 save_database，进程退出前在 finally 中再次保存，减少 IDB/缓存文件异常截断。
"""

from __future__ import print_function

import json
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
import ida_hexrays

try:
    import ida_lines
except Exception:
    ida_lines = None

try:
    import ida_loader
except Exception:
    ida_loader = None

STATE_FILENAME = ".ida_extract_state.json"
STATE_VERSION = 1

# --- 交叉引用 CSV ---
LIMIT_REFS_TO_FUNCTIONS_ONLY = False
MIN_REFS_TO_CREATE_FILE = 1

# --- 伪代码导出 ---
DECOMPILE_TIMEOUT_HINT = 120


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
    safe_name = "".join(
        c
        if (u"0" <= c <= u"9") or (u"a" <= c <= u"z") or (u"A" <= c <= u"Z") or c in ("_", "-")
        else "_"
        for c in name
    )
    safe_name = safe_name.strip("_-")
    while "__" in safe_name:
        safe_name = safe_name.replace("__", "_")
    if len(safe_name) > max_len:
        half = max_len // 3
        safe_name = safe_name[:half] + "..." + safe_name[-half:]
    if not safe_name:
        return "sanitized_empty_name"
    return safe_name


def sanitize_filename_disasm(name, max_len=100):
    """反汇编/伪代码输出文件名：简单截断到 max_len（与 xref 用的 sanitize_filename 不同）。"""
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
    try:
        input_path = ida_nalt.get_input_file_path()
    except Exception:
        input_path_fn = getattr(idc, "get_input_file_path", None) or getattr(idc, "GetInputFilePath", None)
        input_path = input_path_fn() if callable(input_path_fn) else ""

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


def ensure_dir(path):
    if not path:
        return
    if not os.path.exists(path):
        os.makedirs(path)


def write_csv(filepath, header, rows):
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


def compute_all_output_dirs():
    input_path, input_name = get_input_paths()
    base_no_ext, _ = os.path.splitext(input_name)
    safe_base = sanitize_filename(base_no_ext)
    root_dir = os.path.dirname(input_path) if input_path else os.getcwd()
    root_dir = root_dir or "."
    info_dir = os.path.join(root_dir, safe_base + "_output")
    xref_dir = os.path.join(info_dir, "xrefs")
    disasm_dir = os.path.join(root_dir, safe_base + "_disassembly")
    pseudo_dir = os.path.join(root_dir, safe_base + "_pseudocode")
    ensure_dir(info_dir)
    ensure_dir(xref_dir)
    ensure_dir(disasm_dir)
    ensure_dir(pseudo_dir)
    return safe_base, info_dir, xref_dir, disasm_dir, pseudo_dir


def wait_for_auto_analysis():
    try:
        log("[*] Waiting for IDA auto-analysis to finish ...")
        ida_auto.auto_wait()
    except Exception:
        try:
            auto_wait = getattr(idc, "auto_wait", None)
            if callable(auto_wait):
                auto_wait()
        except Exception:
            log("[!] auto_wait failed; continuing anyway")


def want_force_rerun():
    env = (os.environ.get("IDA_EXTRACT_FORCE") or "").strip().lower()
    if env in ("1", "true", "yes", "on"):
        return True
    for src in (getattr(idc, "ARGV", None), sys.argv):
        if not src:
            continue
        for a in src:
            if isinstance(a, str) and a.strip() == "--force":
                return True
    return False


def get_work_root_dir():
    input_path, _ = get_input_paths()
    root = os.path.dirname(input_path) if input_path else os.getcwd()
    return root or "."


def state_path_for(root_dir):
    return os.path.join(root_dir, STATE_FILENAME)


def default_state(safe_base, input_name):
    return {
        "version": STATE_VERSION,
        "safe_base": safe_base,
        "input_name": input_name,
        "input_fingerprint": None,
        "phases": {
            "binary_info": False,
            "disassembly": False,
            "pseudocode": False,
        },
        "pseudocode_skip_reason": None,
    }


def _input_fingerprint():
    """
    仅对「原始可执行文件」记录体积+mtime；打开 .idb/.i64 续跑时不记录（返回 None），
    避免 IDB 自身变化导致误伤进度。
    """
    ip, _ = get_input_paths()
    if not ip:
        return None
    ext = os.path.splitext(ip)[1].lower()
    if ext in (".idb", ".i64", ".nam", ".til"):
        return None
    try:
        st = os.stat(ip)
        return [int(st.st_size), int(st.st_mtime)]
    except Exception:
        return None


def _phase_binary_info_done(safe_base, info_dir):
    sym = os.path.join(info_dir, safe_base + "_symbols.csv")
    return os.path.isfile(sym) and os.path.getsize(sym) > 0


def _phase_disassembly_done(safe_base, disasm_dir):
    all_asm = os.path.join(disasm_dir, safe_base + "_all.asm")
    return os.path.isfile(all_asm) and os.path.getsize(all_asm) > 0


def _phase_pseudocode_done(safe_base, pseudo_dir, state):
    if state.get("pseudocode_skip_reason") == "no_hexrays":
        return True
    whole = os.path.join(pseudo_dir, safe_base + "_decompiled.c")
    if os.path.isfile(whole) and os.path.getsize(whole) > 0:
        return True
    try:
        for n in os.listdir(pseudo_dir):
            if n.endswith(".c") and n.startswith("0x"):
                return True
    except Exception:
        pass
    return False


def reconcile_state_with_disk(state, safe_base, info_dir, disasm_dir, pseudo_dir):
    """若磁盘上缺少已标记完成阶段的产物，则回滚后续阶段标记。"""
    p = state.setdefault("phases", {})
    if p.get("binary_info") and not _phase_binary_info_done(safe_base, info_dir):
        log("[*] State: binary_info 标记完成但缺少 symbols.csv，将重跑自阶段 1")
        p["binary_info"] = False
        p["disassembly"] = False
        p["pseudocode"] = False
        state["pseudocode_skip_reason"] = None
        return
    if p.get("disassembly") and not _phase_disassembly_done(safe_base, disasm_dir):
        log("[*] State: disassembly 标记完成但缺少 *_all.asm，将重跑阶段 2/3")
        p["disassembly"] = False
        p["pseudocode"] = False
        state["pseudocode_skip_reason"] = None
        return
    if p.get("pseudocode") and not _phase_pseudocode_done(safe_base, pseudo_dir, state):
        log("[*] State: pseudocode 标记完成但缺少伪代码产物，将重跑阶段 3")
        p["pseudocode"] = False


def load_state(root_dir, safe_base, input_name, force):
    path = state_path_for(root_dir)
    if force and os.path.isfile(path):
        try:
            os.remove(path)
            log("[*] --force: 已删除进度文件 %s" % path)
        except Exception as e:
            log("[!] 无法删除进度文件: %s" % e)
    if force:
        return default_state(safe_base, input_name)
    if not os.path.isfile(path):
        return default_state(safe_base, input_name)
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        log("[!] 进度文件损坏，将重新开始: %s" % e)
        return default_state(safe_base, input_name)
    if data.get("version") != STATE_VERSION or data.get("safe_base") != safe_base:
        log("[*] 进度文件与当前样本不匹配，将重新开始")
        return default_state(safe_base, input_name)
    data.setdefault("phases", {})
    data.setdefault("pseudocode_skip_reason", None)
    data.setdefault("input_fingerprint", None)
    cur_fp = _input_fingerprint()
    old_fp = data.get("input_fingerprint")
    if old_fp is not None and cur_fp is not None and old_fp != cur_fp:
        log("[*] 检测到输入文件与上次记录不一致（体积/修改时间），将重新开始")
        return default_state(safe_base, input_name)
    return data


def write_state(root_dir, state):
    path = state_path_for(root_dir)
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2, sort_keys=True)
            f.write("\n")
        os.replace(tmp, path)
    except Exception as e:
        log("[!] 写入进度文件失败: %s" % e)
        try:
            if os.path.isfile(tmp):
                os.remove(tmp)
        except Exception:
            pass


def save_idb_to_disk():
    """
    将当前数据库写入磁盘，便于 headless 下 .i64/.idb 及附属文件正常落盘。
    优先 idc.save_database；失败则尝试 ida_loader.save_database。
    """
    idb_path = None
    for getter in (
        getattr(ida_nalt, "get_idb_path", None),
        getattr(idc, "get_idb_path", None),
    ):
        if not callable(getter):
            continue
        try:
            idb_path = getter()
            if idb_path:
                break
        except Exception:
            pass
    save_fn = getattr(idc, "save_database", None)
    last_err = None
    if callable(save_fn):
        candidates = []
        if idb_path:
            candidates.append(idb_path)
        candidates.append("")  # IDC：空串表示当前库路径
        seen = set()
        for cand in candidates:
            key = cand if cand else "\0"
            if key in seen:
                continue
            seen.add(key)
            try:
                save_fn(cand, 0)
                log("[*] Database saved (%s)." % (cand or "current idb"))
                return True
            except Exception as e:
                last_err = e
        if last_err is not None:
            log("[!] idc.save_database failed: %s" % last_err)
    if ida_loader is not None and idb_path:
        ldr_save = getattr(ida_loader, "save_database", None)
        if callable(ldr_save):
            try:
                ldr_save(idb_path, 0)
                log("[*] Database saved via ida_loader.")
                return True
            except Exception as e:
                log("[!] ida_loader.save_database failed: %s" % e)
    return False


def shutdown_ida(exit_code=0):
    """退出 IDA 进程（调用前应先 save_idb_to_disk）。"""
    try:
        qe = getattr(idc, "qexit", None)
        if callable(qe):
            qe(exit_code)
            return
    except Exception:
        pass
    try:
        ex = getattr(idc, "Exit", None)
        if callable(ex):
            ex(exit_code)
    except Exception:
        pass


# ----- Phase 1: binary info -----

def extract_symbols(symbol_csv_path):
    log("[*] Extracting symbols ...")
    rows = []
    header = ["Name", "Address", "Type", "Source", "Is Global", "Is Primary", "Is External", "Namespace"]
    try:
        for ea, name in idautils.Names():
            addr_str = "0x%X" % ea
            func = ida_funcs.get_func(ea)
            sym_type = "FUNC" if func else "LABEL"
            source = "auto"
            is_global = "True" if func else "False"
            is_primary = "True"
            is_external = "False"
            namespace = "Global"
            rows.append([name, addr_str, sym_type, source, is_global, is_primary, is_external, namespace])
    except Exception as e:
        log("[!] Error while enumerating symbols: %s" % e)
        log(traceback.format_exc())
    write_csv(symbol_csv_path, header, rows)
    return [(ea, name) for ea, name in idautils.Names()]


def extract_strings(strings_csv_path):
    log("[*] Extracting strings ...")
    header = ["String", "Address", "Length"]
    rows = []
    try:
        s_iter = idautils.Strings()
        s_iter.setup()
        for s in s_iter:
            try:
                value = str(s)
            except Exception:
                value = repr(s)
            rows.append([value, "0x%X" % s.ea, str(s.length)])
    except Exception as e:
        log("[!] Error while extracting strings: %s" % e)
        log(traceback.format_exc())
    write_csv(strings_csv_path, header, rows)


def extract_segments_and_sections(segments_csv_path, sections_csv_path):
    """
    一次遍历 Segments()，写入 segments / sections 两个 CSV。
    """
    log("[*] Extracting segments & sections (single pass) ...")
    seg_header = ["Name", "Start Address", "End Address", "Length", "Perm"]
    sec_header = ["Name", "Start Address", "End Address", "Length"]
    seg_rows = []
    sec_rows = []
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
            seg_rows.append([name, "0x%X" % start, "0x%X" % end, str(length), "0x%X" % perm])
            sec_rows.append([name, "0x%X" % start, "0x%X" % end, str(length)])
    except Exception as e:
        log("[!] Error while extracting segments/sections: %s" % e)
        log(traceback.format_exc())
    write_csv(segments_csv_path, seg_header, seg_rows)
    write_csv(sections_csv_path, sec_header, sec_rows)


def extract_xrefs(all_symbols, safe_base, xrefs_dir):
    log("[*] Extracting cross-references (may take a while) ...")
    header = ["Reference From Address", "Reference Type", "Containing Function"]
    generated_files = 0
    processed = 0
    for ea, name in all_symbols:
        processed += 1
        if LIMIT_REFS_TO_FUNCTIONS_ONLY:
            if not ida_funcs.get_func(ea):
                continue
        refs = []
        try:
            for xref in idautils.XrefsTo(ea, 0):
                from_ea = xref.frm
                func = ida_funcs.get_func(from_ea)
                func_name = ida_funcs.get_func_name(func.start_ea) if func else ""
                try:
                    ref_type = ida_xref.get_xref_type_name(xref.type)
                except Exception:
                    ref_type = str(xref.type)
                refs.append(["0x%X" % from_ea, ref_type, func_name])
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


def run_phase_binary_info(safe_base, info_dir, xref_dir):
    log("=== Phase 1/3: Binary info & xrefs ===")
    symbol_file = os.path.join(info_dir, safe_base + "_symbols.csv")
    strings_file = os.path.join(info_dir, safe_base + "_strings.csv")
    segments_file = os.path.join(info_dir, safe_base + "_segments.csv")
    sections_file = os.path.join(info_dir, safe_base + "_sections.csv")
    all_symbols = extract_symbols(symbol_file)
    extract_strings(strings_file)
    extract_segments_and_sections(segments_file, sections_file)
    extract_xrefs(all_symbols, safe_base, xref_dir)
    log("[+] Binary info CSVs under: %s" % info_dir)


# ----- Phase 2: disassembly -----

def _strip_tags(text):
    if not text:
        return ""
    tr = None
    if ida_lines is not None:
        tr = getattr(ida_lines, "tag_remove", None)
    if tr is None:
        tr = getattr(idc, "tag_remove", None)
    if callable(tr):
        try:
            return tr(text)
        except Exception:
            return text
    return text


def format_instr(ea):
    try:
        try:
            if not ida_bytes.is_code(ida_bytes.get_full_flags(ea)):
                return ""
        except Exception:
            pass
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


def export_full_asm(out_dir, safe_base):
    input_path, input_name = get_input_paths()
    filename = "%s_all.asm" % safe_base
    path = os.path.join(out_dir, filename)
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
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("; Full disassembly (fallback)\n")
            f.write("; Input file: %s\n" % (input_name or "unknown"))
            f.write("; Generated by ExtractAll_IDA.py\n\n")
            for seg_start in idautils.Segments():
                seg_name = ""
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


def run_phase_disassembly(disasm_dir, safe_base):
    log("=== Phase 2/3: Disassembly ===")
    log("[*] Output directory: %s" % disasm_dir)
    export_full_asm(disasm_dir, safe_base)
    count_funcs = 0
    count_ok = 0
    count_err = 0
    for func_ea in idautils.Functions():
        count_funcs += 1
        func_name = ida_funcs.get_func_name(func_ea)
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue
        safe_name = sanitize_filename_disasm(func_name)
        filename = "0x%X_%s.asm" % (func_ea, safe_name)
        path = os.path.join(disasm_dir, filename)
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
    log("[+] Disassembly done. total=%d ok=%d err=%d" % (count_funcs, count_ok, count_err))


# ----- Phase 3: pseudocode -----

def decompile_function(ea):
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
                    line_text = item.line if hasattr(item, "line") else str(item)
                    if ida_lines is not None:
                        clean_text = ida_lines.tag_remove(line_text)
                    else:
                        tr = getattr(idc, "tag_remove", None)
                        clean_text = tr(line_text) if callable(tr) else line_text
                    clean_text = clean_text.rstrip("\r\n")
                    if clean_text.strip() and not clean_text.lstrip().startswith("JUMPOUT"):
                        result_lines.append(clean_text)
                except Exception:
                    pass
    except Exception:
        pass
    if result_lines:
        return "\n".join(result_lines)
    return ""


def export_whole_program_pseudocode(out_dir, safe_base):
    """整库 decompile_many；main() 里已 auto_wait，此处不再等待。"""
    try:
        c_output = os.path.join(out_dir, "%s_decompiled.c" % safe_base)
        log("[*] Generating whole-program pseudocode: %s" % c_output)
        rc = ida_hexrays.decompile_many(
            c_output,
            None,
            ida_hexrays.VDRUN_NEWFILE | ida_hexrays.VDRUN_SILENT | ida_hexrays.VDRUN_MAYSTOP,
        )
        log("[+] decompile_many finished (rc=%s)" % rc)
        if not rc and not os.path.exists(c_output):
            log("[!] decompile_many returned false and output file not found.")
        elif os.path.exists(c_output):
            log("[+] Whole-program pseudocode written to: %s" % c_output)
    except Exception as e:
        log("[!] Error in export_whole_program_pseudocode: %s" % e)
        log(traceback.format_exc())


def run_phase_pseudocode(pseudo_dir, safe_base):
    """
    返回 (success, skip_reason)。
    skip_reason 为 'no_hexrays' 表示无反编译器，阶段仍视为已完成（续跑不再重试）。
    """
    log("=== Phase 3/3: Pseudocode ===")
    log("[!] WARNING: Hex-Rays decompiler has known limitations in headless mode.")
    if not ida_hexrays.init_hexrays_plugin():
        log("[!] Hex-Rays decompiler is not available. Skipping pseudocode extraction.")
        return True, "no_hexrays"
    log("[*] Output directory: %s" % pseudo_dir)
    export_whole_program_pseudocode(pseudo_dir, safe_base)
    total_funcs = 0
    decompiled = 0
    failed = 0
    empty = 0
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
        safe_name = sanitize_filename_disasm(func_name)
        filename = "0x%X_%s.c" % (func_ea, safe_name)
        path = os.path.join(pseudo_dir, filename)
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
    log("[+] Pseudocode done. total=%d ok=%d empty_or_fail=%d" % (total_funcs, decompiled, empty + failed))
    log("[!] NOTE: Hex-Rays in headless mode may produce incomplete results.")
    return True, None


def main():
    exit_code = 0
    try:
        log("--- IDA Extract All ---")
        wait_for_auto_analysis()
        root_dir = get_work_root_dir()
        _, input_name = get_input_paths()
        safe_base, info_dir, xref_dir, disasm_dir, pseudo_dir = compute_all_output_dirs()
        force = want_force_rerun()
        if force:
            log("[*] 强制全量重跑（--force 或 IDA_EXTRACT_FORCE=1）")
        state = load_state(root_dir, safe_base, input_name, force)
        reconcile_state_with_disk(state, safe_base, info_dir, disasm_dir, pseudo_dir)
        write_state(root_dir, state)

        if not state["phases"].get("binary_info"):
            run_phase_binary_info(safe_base, info_dir, xref_dir)
            state["phases"]["binary_info"] = True
            state["pseudocode_skip_reason"] = None
            fp = _input_fingerprint()
            if fp is not None:
                state["input_fingerprint"] = fp
            write_state(root_dir, state)
            save_idb_to_disk()
        else:
            log("[*] 断点续跑：跳过阶段 1 (binary_info)")

        if not state["phases"].get("disassembly"):
            run_phase_disassembly(disasm_dir, safe_base)
            state["phases"]["disassembly"] = True
            write_state(root_dir, state)
            save_idb_to_disk()
        else:
            log("[*] 断点续跑：跳过阶段 2 (disassembly)")

        if not state["phases"].get("pseudocode"):
            _ok, skip_reason = run_phase_pseudocode(pseudo_dir, safe_base)
            if _ok:
                state["phases"]["pseudocode"] = True
                state["pseudocode_skip_reason"] = skip_reason
                write_state(root_dir, state)
                save_idb_to_disk()
        else:
            log("[*] 断点续跑：跳过阶段 3 (pseudocode)")

        log("[+] ExtractAll_IDA finished.")
    except Exception as _e:
        exit_code = 1
        log("[!] ExtractAll_IDA 异常中止: %s" % _e)
        log(traceback.format_exc())
    finally:
        try:
            save_idb_to_disk()
        except Exception as _fe:
            log("[!] 退出前保存 IDB 失败: %s" % _fe)
        try:
            shutdown_ida(exit_code)
        except Exception:
            try:
                idc.Exit(exit_code)
            except Exception:
                pass


if __name__ == "__main__":
    try:
        main()
    except Exception as _e:
        log("[!] Fatal (pre-shutdown): %s" % _e)
        log(traceback.format_exc())
        try:
            save_idb_to_disk()
            shutdown_ida(1)
        except Exception:
            try:
                idc.Exit(1)
            except Exception:
                pass
