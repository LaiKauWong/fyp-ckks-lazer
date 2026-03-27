CC ?= gcc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wno-unused-parameter -fgnu89-inline -fcommon
CPPFLAGS += -I../../third_party/bench_ref/libntru/src
LDFLAGS += -L../../third_party/bench_ref/libntru
LDLIBS += -lntru -lrt -lm

BIN := libntru_bench
SRC := libntru_bench.c
RESULT_DIR := results
RESULT_FILE := $(RESULT_DIR)/libntru.txt
LIBNTRU_DIR := ../../third_party/bench_ref/libntru

.PHONY: all build run results clean libntru-lib

all: build

libntru-lib:
	$(MAKE) -C $(LIBNTRU_DIR) static-lib

build: libntru-lib
	$(CC) $(CFLAGS) $(CPPFLAGS) $(SRC) $(LDFLAGS) $(LDLIBS) -o $(BIN)

run: build
	LD_LIBRARY_PATH=$(LIBNTRU_DIR) ./$(BIN)

results: build
	mkdir -p $(RESULT_DIR)
	LD_LIBRARY_PATH=$(LIBNTRU_DIR) ./$(BIN) > $(RESULT_FILE)

clean:
	rm -f $(BIN)
