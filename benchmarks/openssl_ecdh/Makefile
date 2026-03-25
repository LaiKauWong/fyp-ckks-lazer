# Compiler settings
CC = gcc
CFLAGS = -O3 -march=native -Wall
LDFLAGS = -lcrypto

# Files and directories
TARGET = bench_openssl
SRC = bench_openssl.c
RESULT_DIR = results
RESULT_FILE = $(RESULT_DIR)/openssl_ecdh.txt

.PHONY: all bench clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

bench: $(TARGET)
	@echo "Running OpenSSL ECDH benchmark (NIST P-256)..."
	@mkdir -p $(RESULT_DIR)
	./$(TARGET) > $(RESULT_FILE)
	@echo "========================================================="
	@echo "Benchmark complete! Results saved to $(RESULT_FILE)"
	@echo "========================================================="
	@cat $(RESULT_FILE)

clean:
	rm -f $(TARGET)