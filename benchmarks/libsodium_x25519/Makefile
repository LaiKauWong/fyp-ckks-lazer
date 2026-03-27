CC = gcc
CFLAGS = -O3 -march=native -Wall
LDFLAGS = -lsodium

TARGET = bench_libsodium
SRC = bench_libsodium.c
RESULT_DIR = results
RESULT_FILE = $(RESULT_DIR)/libsodium_x25519.txt

.PHONY: all bench clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

bench: $(TARGET)
	@echo "Running Libsodium X25519 PKE benchmark..."
	@mkdir -p $(RESULT_DIR)
	./$(TARGET) > $(RESULT_FILE)
	@echo "========================================================="
	@echo "Benchmark complete! Results saved to $(RESULT_FILE)"
	@echo "========================================================="
	@cat $(RESULT_FILE)

clean:
	rm -f $(TARGET)