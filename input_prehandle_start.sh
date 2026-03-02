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

# 创建输出目录
OUTPUT_DIR="${FILE_DIR}/${BASE_NAME}_idademo"
mkdir -p "$OUTPUT_DIR"

# 创建子目录
DISASSEMBLY_DIR="${OUTPUT_DIR}/${BASE_NAME}_disassembly"
OUTPUT_CSV_DIR="${OUTPUT_DIR}/${BASE_NAME}_output"
PSEUDOCODE_DIR="${OUTPUT_DIR}/${BASE_NAME}_pseudocode"

mkdir -p "$DISASSEMBLY_DIR"
mkdir -p "$OUTPUT_CSV_DIR"
mkdir -p "$PSEUDOCODE_DIR"
mkdir -p "${OUTPUT_CSV_DIR}/xrefs"

echo "开始分析: $FILE_NAME"
echo "输出目录: $OUTPUT_DIR"

# 复制脚本到输出目录
cp "$(dirname "$0")/ExtractBinaryInfo_IDA.py" "$OUTPUT_DIR/"
cp "$(dirname "$0")/ExtractDisassembly_IDA.py" "$OUTPUT_DIR/"
cp "$(dirname "$0")/ExtractPseudocode_IDA.py" "$OUTPUT_DIR/"

# 复制二进制文件到输出目录（使用复制，避免移动）
cp "$INPUT_FILE" "$OUTPUT_DIR/"

# 进入输出目录
cd "$OUTPUT_DIR"

# 运行IDA分析
echo "步骤1: 提取二进制信息..."
"$IDA_CMD" -A -S"ExtractBinaryInfo_IDA.py $OUTPUT_CSV_DIR" "$OUTPUT_DIR/$FILE_NAME"

echo "步骤2: 提取反汇编代码..."
"$IDA_CMD" -A -S"ExtractDisassembly_IDA.py $DISASSEMBLY_DIR" "$OUTPUT_DIR/$FILE_NAME"

echo "步骤3: 提取伪代码..."
"$IDA_CMD" -A -S"ExtractPseudocode_IDA.py $PSEUDOCODE_DIR" "$OUTPUT_DIR/$FILE_NAME"

# 清理临时文件
rm -f "$OUTPUT_DIR/$FILE_NAME"
rm -f "$OUTPUT_DIR/ExtractBinaryInfo_IDA.py"
rm -f "$OUTPUT_DIR/ExtractDisassembly_IDA.py"
rm -f "$OUTPUT_DIR/ExtractPseudocode_IDA.py"

echo "分析完成!"
echo "结果保存在: $OUTPUT_DIR"
echo "包含以下子目录:"
echo "  - ${BASE_NAME}_disassembly/: 反汇编代码"
echo "  - ${BASE_NAME}_output/: 二进制信息CSV"
echo "  - ${BASE_NAME}_pseudocode/: 伪代码"