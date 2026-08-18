CC ?= gcc
AFL_CC ?= afl-gcc
CFLAGS = -O2 -g -fsanitize=address
AFL_CFLAGS = -O2 -g
HARNESS_CFLAGS = $(CFLAGS) -DBUILDING_HARNESS
AFL_HARNESS_CFLAGS = $(AFL_CFLAGS) -DBUILDING_HARNESS
SRC_DIR = targets
BIN_DIR = bin

SINGLE_SOURCES = $(SRC_DIR)/buffer_overflow.c $(SRC_DIR)/heap_corruption.c $(SRC_DIR)/image_parser.c
SINGLE_BINS = $(patsubst $(SRC_DIR)/%.c,$(BIN_DIR)/%,$(SINGLE_SOURCES))

.PHONY: all clean afl afl_harness

all: $(BIN_DIR) $(SINGLE_BINS) $(BIN_DIR)/standalone_harness

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(BIN_DIR)/buffer_overflow: $(SRC_DIR)/buffer_overflow.c
	$(CC) $(CFLAGS) -o $@ $<

$(BIN_DIR)/heap_corruption: $(SRC_DIR)/heap_corruption.c
	$(CC) $(CFLAGS) -o $@ $<

$(BIN_DIR)/image_parser: $(SRC_DIR)/image_parser.c
	$(CC) $(CFLAGS) -o $@ $<

$(BIN_DIR)/standalone_harness: $(SRC_DIR)/standalone_harness.c \
    $(SRC_DIR)/buffer_overflow.c $(SRC_DIR)/heap_corruption.c $(SRC_DIR)/image_parser.c
	$(CC) $(HARNESS_CFLAGS) -o $@ $(SRC_DIR)/standalone_harness.c \
    $(SRC_DIR)/buffer_overflow.c $(SRC_DIR)/heap_corruption.c $(SRC_DIR)/image_parser.c

afl: $(BIN_DIR)
	$(AFL_CC) $(AFL_CFLAGS) -o $(BIN_DIR)/buffer_overflow $(SRC_DIR)/buffer_overflow.c
	$(AFL_CC) $(AFL_CFLAGS) -o $(BIN_DIR)/heap_corruption $(SRC_DIR)/heap_corruption.c
	$(AFL_CC) $(AFL_CFLAGS) -o $(BIN_DIR)/image_parser $(SRC_DIR)/image_parser.c

afl_harness: $(BIN_DIR)
	$(AFL_CC) $(AFL_HARNESS_CFLAGS) -o $(BIN_DIR)/standalone_harness $(SRC_DIR)/standalone_harness.c \
	    $(SRC_DIR)/buffer_overflow.c $(SRC_DIR)/heap_corruption.c $(SRC_DIR)/image_parser.c

clean:
	rm -rf $(BIN_DIR)/*
	rm -f $(BIN_DIR)/buffer_overflow $(BIN_DIR)/heap_corruption $(BIN_DIR)/image_parser $(BIN_DIR)/standalone_harness
