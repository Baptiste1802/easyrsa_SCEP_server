CC = gcc
CFLAGS = -g -Iinclude #-Wall -Wextra 
LDFLAGS = -lssl -lcrypto
SRC_DIR = src
OBJ_DIR = objects
BIN_DIR = bin
TARGET = $(BIN_DIR)/client

SRC = $(wildcard $(SRC_DIR)/*.c)
OBJ = $(SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

all: $(TARGET)

$(TARGET): $(OBJ)
	mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ_DIR)/*.o $(BIN_DIR)/*

run: all
	./$(TARGET)

mrproper: clean
	rm -f $(TARGET)
	rm *.cert
	rm *.key

.PHONY: all clean mrproper