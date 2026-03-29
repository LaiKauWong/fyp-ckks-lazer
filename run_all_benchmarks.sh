#!/bin/bash

# 设定汇总输出文件的绝对路径
OUTPUT_FILE="$(pwd)/benchmark_summary.txt"

# 初始化/清空输出文件，并写入头部信息
echo "=================================================================" > "$OUTPUT_FILE"
echo "           Traditional PKE Benchmarks Summary" >> "$OUTPUT_FILE"
echo "           Date: $(date)" >> "$OUTPUT_FILE"
echo "=================================================================" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# 定义一个运行测试的通用函数
run_benchmark() {
    DIR=$1
    BIN=$2
    NAME=$3

    echo "[*] Processing $NAME..."
    
    # 进入对应目录
    cd "$DIR" || { echo "Directory $DIR not found!" ; exit 1; }

    # 清理并重新编译 (忽略编译过程的标准输出，保持终端干净)
    make clean > /dev/null 2>&1
    make > /dev/null 2>&1

    # 如果他们的 Makefile 里面包含 bench target，也可以调用 make bench
    # 这里我们直接执行生成的二进制文件，确保输出被准确重定向
    
    echo "-----------------------------------------------------------------" >> "$OUTPUT_FILE"
    echo "--> Executing: $NAME" >> "$OUTPUT_FILE"
    echo "-----------------------------------------------------------------" >> "$OUTPUT_FILE"

    # 检查是否成功生成可执行文件，并运行重定向
    if [ -x "$BIN" ]; then
        $BIN >> "$OUTPUT_FILE"
        echo "    - $NAME completed successfully."
    else
        echo "    ! ERROR: $BIN not found or not executable. Compilation failed?"
        echo "Compilation failed for $NAME" >> "$OUTPUT_FILE"
    fi

    echo "" >> "$OUTPUT_FILE"
    
    # 返回上级目录
    cd - > /dev/null
}

# 依次调用三个方案的测试目录和对应的执行文件
# 请确保这里的相对路径和二进制文件名与你的实际环境一致
run_benchmark "benchmarks/libsodium_x25519" "./bench_libsodium" "Libsodium X25519"
run_benchmark "benchmarks/openssl_rsa3072" "./bench_rsa" "OpenSSL RSA-3072"
run_benchmark "benchmarks/openssl_sm2" "./bench_sm2" "OpenSSL SM2"

echo ""
echo "[+] All done! The complete results have been saved to:"
echo "    -> $OUTPUT_FILE"
