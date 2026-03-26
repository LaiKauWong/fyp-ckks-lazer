CC = gcc
CFLAGS = -O3 -march=native -Wall
LDFLAGS = -lssl -lcrypto

TARGET = bench_sm2
SRC = bench_sm2.c
RESULT_DIR = results
RESULT_FILE = $(RESULT_DIR)/openssl_sm2.txt

.PHONY: all bench clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

bench: $(TARGET)
	@mkdir -p $(RESULT_DIR)
	./$(TARGET) > $(RESULT_FILE)
	@cat $(RESULT_FILE)

clean:
	rm -f $(TARGET)