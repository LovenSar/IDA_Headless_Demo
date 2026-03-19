# IDA_Headless_Demo

一个基于 **IDA Pro (idat.exe)** 的自动化二进制分析示例，用于在命令行 / 无头模式下批量提取：

- 符号信息（大致等价于符号表）
- 字符串（Strings）
- 段/节信息（Segments/Sections）
- 符号交叉引用（Xrefs）
- 函数级反汇编（Disassembly）
- 函数级伪代码（Pseudocode，依赖 Hex-Rays）

整体功能逻辑与 `Ghidra_Headless_Demo` 一致，只是将后端从 Ghidra Headless 换成了 IDA 的 `idat.exe`。

## 文件结构

```text
IDA_Headless_Demo/
├── README.md
├── input_prehandle_start.bat     # Windows 主入口（拖拽文件）
├── input_prehandle_start.sh      # macOS/Linux 同上
├── single_test.bat               # Windows 直连 idat + 脚本（不调工作目录逻辑）
└── ExtractAll_IDA.py             # 唯一 IDAPython：单次 idat 完成全部导出
```

## 逻辑特点（对照 Ghidra 版本）

- 采用「批处理 / Shell 入口 + IDAPython」结构：
  - 入口脚本负责：拖拽或传参、创建工作目录、复制 `ExtractAll_IDA.py`、调用 **一次** `idat.exe`。
  - `ExtractAll_IDA.py` 在同一次 IDA 会话内依次导出：二进制信息 → 反汇编 → 伪代码。
  - **断点续跑**：进度写在 `[文件名]_idademo/.ida_extract_state.json`；中断后应打开已有 **`.i64`/`.idb`** 再跑脚本，且**不要**加 `-c`（否则会新建空库）。示例：  
    `idat -A -S"ExtractAll_IDA.py" "D:\work\sample_idademo\sample.i64"`  
    **强制全量重跑**：脚本参数加 `--force`，或环境变量 `IDA_EXTRACT_FORCE=1`（会删除进度文件）。  
    若同名二进制被替换（体积/修改时间变化），会自动忽略旧进度并从头导出。  
  - **安全退出**：每个阶段完成后与进程结束前会 `save_database`，尽量保证 IDB 与缓存文件正常落盘；退出时优先 `qexit`，回退为 `Exit`。  
  - 流程优化：仅启动 IDA 一次、`auto_wait` 一次；段表与节表一次遍历写出两份 CSV。
- 输出风格尽量与 Ghidra 版保持一致：
  - 为每个输入文件创建独立的工作目录：`[文件名]_idademo`。
  - 在该目录中按功能拆分子目录：
    - `[文件名]_disassembly/`  ：每个函数一个 `.asm` 文件。
    - `[文件名]_output/`       ：符号、字符串、段/节信息、交叉引用（CSV）。
    - `[文件名]_pseudocode/`   ：每个函数一个 `.c` 伪代码文件（需要 Hex-Rays）。
- 所有脚本都尽量使用稳定、常见的 IDAPython API，避免依赖过多版本细节。

## 环境要求

1. **IDA Pro 9.2**（或兼容版本）  
   默认路径示例：
   `E:\WorkSpace\ReBind\tools\IDA_Pro_Terminal_Demo\IDA Professional 9.2\idat.exe`
2. **Windows 或 macOS**（Windows 用 `.bat`，macOS 用 `input_prehandle_start.sh` 并配置其中的 `IDA_CMD`）
3. （可选）**Hex-Rays Decompiler 插件**：用于生成伪代码

> 如果 Hex-Rays 不可用，`ExtractAll_IDA.py` 会跳过伪代码阶段，其它 CSV / 反汇编照常生成。

## 配置步骤

1. 打开 `IDA_Headless_Demo\input_prehandle_start.bat`，确认 / 修改：

   ```batch
   set "IDA_CMD=E:\WorkSpace\ReBind\tools\IDA_Pro_Terminal_Demo\IDA Professional 9.2\idat.exe"
   ```

   将路径改为你本地安装的 `idat.exe`。

2. 如需自定义输出结构或过滤条件，在 `ExtractAll_IDA.py` 顶部修改配置：

   - `LIMIT_REFS_TO_FUNCTIONS_ONLY`  
   - `MIN_REFS_TO_CREATE_FILE`

## 使用方法

### 方法一：拖拽（推荐）

1. 将待分析的二进制文件（`.exe` / `.dll` / 其它）拖拽到  
   `IDA_Headless_Demo\input_prehandle_start.bat` 上。
2. 批处理会自动：
   - 在原文件目录创建 `[文件名]_idademo` 工作目录。
   - 复制 `ExtractAll_IDA.py` 与输入文件到工作目录。
   - 在工作目录调用一次：`idat.exe -A -c -S"ExtractAll_IDA.py" 复制后的文件`
3. 处理完成后，批处理会清理临时脚本与复制的样本文件，仅保留：
   - IDA 数据库文件（如 `.i64`），便于后续用 GUI 打开。
   - 导出的反汇编 / 伪代码 / CSV 结果。

### 方法二：命令行调用

在 `IDA_Headless_Demo` 目录下执行：

```batch
input_prehandle_start.bat "C:\path\to\binary.exe"
```

macOS / Linux：

```bash
chmod +x input_prehandle_start.sh
./input_prehandle_start.sh "/path/to/binary"
```

## 输出结构

完成分析后，在输入文件所在目录会出现一个工作目录：

```text
[文件名]_idademo/
├── .ida_extract_state.json    # 导出阶段进度（断点续跑，可选删除或 --force）
├── [文件名]_disassembly/      # 每个函数一个 .asm 文件
├── [文件名]_output/           # 各类 CSV 输出
│   ├── [base]_symbols.csv     # 名称/地址/类型 等符号信息
│   ├── [base]_strings.csv     # 字符串（内容/地址/长度）
│   ├── [base]_segments.csv    # 段信息（名称/起止/大小）
│   ├── [base]_sections.csv    # 以段视图表示的“节”信息
│   └── xrefs/                 # 每个符号一个交叉引用 CSV
└── [文件名]_pseudocode/      # 每个函数一个 .c 伪代码文件（若 Hex-Rays 可用）
```

`[base]` 为输入文件名去掉扩展名后，再经过简单清理（去掉非法文件名字符）得到的安全名称。

## 与 Ghidra_Headless_Demo 的对应关系总结

- **入口方式一致**：  
  两者都是「拖拽到批处理」作为入口，自动创建独立工作目录，避免多个样本混在一起。
- **分析维度对应**：Ghidra 的 `ExtractBinaryInfo.py` / `ExtractDisassembly.py` / `ExtractPseudocode.py` 三者的导出内容，在本项目中由 **`ExtractAll_IDA.py` 一次完成**。
- **输出思路一致**：
  - 都是按「一个样本一套目录结构」组织。
  - 都是「函数粒度拆分」反汇编和伪代码。
  - 交叉引用也同样按符号拆分为多个 CSV 文件，便于后续按需加载。
- **实现细节差异**：
  - Ghidra 使用 Java API（SymbolTable / DefinedDataIterator / Decompiler 等）。
  - IDA 使用 IDAPython API（idautils / ida_funcs / ida_bytes / ida_hexrays 等）。
  - 某些字段（例如符号来源 Source、命名空间 Namespace）在 IDA 中难以一一对应，
    这里采用较为保守的填充值（如 `"auto"`、`"Global"`），但列结构基本兼容。

## 故障排除

1. **批处理提示找不到 idat.exe**
   - 检查 `input_prehandle_start.bat` 中 `IDA_CMD` 路径是否正确。
2. **伪代码目录为空 / 生成很少**
   - 确认已安装并授权 Hex-Rays 插件；
   - 部分函数可能因反编译失败或格式异常被跳过。
3. **CSV / ASM / C 文件中有乱码**
   - 默认使用 UTF‑8 编码输出；如果样本使用特殊编码，可按需修改脚本中的 `encoding`。


