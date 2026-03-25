# Compiler settings
CC = gcc
CFLAGS = -O3 -march=native -Wall -I./liboqs/build/include
# Note: -Wl,-rpath is used so the executable can find liboqs.so at runtime
LDFLAGS = -L./liboqs/build/lib -loqs -Wl,-rpath=./liboqs/build/lib

# Files and directories
TARGET = bench_liboqs
SRC = bench_liboqs.c
RESULT_DIR = results
RESULT_FILE = $(RESULT_DIR)/liboqs_baseline.txt

.PHONY: all bench clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

bench: $(TARGET)
	@echo "Running liboqs benchmark (Kyber512 & FrodoKEM)..."
	@mkdir -p $(RESULT_DIR)
	./$(TARGET) > $(RESULT_FILE)
	@echo "========================================================="
	@echo "Benchmark complete! Results saved to $(RESULT_FILE)"
	@echo "========================================================="
	@cat $(RESULT_FILE)

clean:
	rm -f $(TARGET)