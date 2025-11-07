CC ?= gcc
CFLAGS ?= -g -O0 -Wall
SANITIZER ?= -fsanitize=address
TARGET := bof
SRC := src/main.c
BUILD_DIR := build

.PHONY: all clean run exploit

all: $(BUILD_DIR)/$(TARGET)

$(BUILD_DIR)/$(TARGET): $(SRC)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $(SANITIZER) -o $@ $<

run: all
	./$(BUILD_DIR)/$(TARGET) safe-input

exploit: all
	./$(BUILD_DIR)/$(TARGET) $(shell python3 -c "print('A'*128)")

clean:
	rm -rf $(BUILD_DIR)
