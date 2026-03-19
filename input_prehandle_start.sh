#!/bin/bash

# IDA Headless 分析脚本 - macOS版本
# 使用方法: ./input_prehandle_start.sh <二进制文件路径>

# 配置IDA路径
IDA_CMD="/Applications/IDA Professional 9.2.app/Contents/MacOS/idat"

# 检查参数
if [ $# -eq 0 ]; then
    echo "Error: 请拖放二进制文件到本脚本上"
    echo "Usage: $0 <binary_file>"
    exit 1
fi

# 检查文件是否存在
if [ ! -f "$1" ]; then
    echo "Error: 文件不存在: $1"
    exit 1
fi

# 检查是否是目录
if [ -d "$1" ]; then
    echo "Error: 输入是目录，请提供文件"
    exit 1
fi

# 获取文件信息
INPUT_FILE="$1"
FILE_DIR=$(dirname "$INPUT_FILE")
FILE_NAME=$(basename "$INPUT_FILE")
BASE_NAME="${FILE_NAME%.*}"

# 工作根目录（与样本基名一致；内部 *_output / *_disassembly / *_pseudocode 由 ExtractAll_IDA.py
# 用 sanitize_filename 生成，勿在此用原始 BASE_NAME 预建子目录，否则特殊字符会导致空目录残留）
OUTPUT_DIR="${FILE_DIR}/${BASE_NAME}_idademo"
mkdir -p "$OUTPUT_DIR"

echo "开始分析: $FILE_NAME"
echo "输出目录: $OUTPUT_DIR"

# 复制合并后的 IDAPython 脚本
cp "$(dirname "$0")/ExtractAll_IDA.py" "$OUTPUT_DIR/"

# 复制二进制文件到输出目录（使用复制，避免移动）
cp "$INPUT_FILE" "$OUTPUT_DIR/"

# 进入输出目录
cd "$OUTPUT_DIR"

# 运行 IDA（单次会话：二进制信息 + 反汇编 + 伪代码）
echo "运行 ExtractAll_IDA.py（单进程）..."
"$IDA_CMD" -A -c -S"ExtractAll_IDA.py" "$OUTPUT_DIR/$FILE_NAME"

# 清理临时文件
rm -f "$OUTPUT_DIR/$FILE_NAME"
rm -f "$OUTPUT_DIR/ExtractAll_IDA.py"

echo "分析完成!"
echo "结果保存在: $OUTPUT_DIR"
echo "子目录由 ExtractAll_IDA.py 按清理后的基名生成，请在该目录下查看 *_disassembly、*_output、*_pseudocode"
