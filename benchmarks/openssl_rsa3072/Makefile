CC = gcc
CFLAGS = -O3 -march=native -Wall
LDFLAGS = -lssl -lcrypto

TARGET = bench_rsa
SRC = bench_rsa.c
RESULT_DIR = results
RESULT_FILE = $(RESULT_DIR)/openssl_rsa3072.txt

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