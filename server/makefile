CC = gcc
CFLAGS = -Wall -Wextra -g -Iinclude
LDFLAGS = -lssl -lcrypto
SRC_DIR = src
OBJ_DIR = objects
BIN_DIR = bin
TARGET = $(BIN_DIR)/server
EASYRSA_MODIFIED = ./easyrsa_modified

SRC = $(wildcard $(SRC_DIR)/*.c)
OBJ = $(SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

all: $(TARGET)

$(TARGET): $(OBJ)
	mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

fix_easyrsa: $(EASYRSA_MODIFIED)
$(EASYRSA_MODIFIED):
	sh fix_easyrsa.sh

init_pki: fix_easyrsa
	sh init_pki_test.sh

clean:
	rm -f $(OBJ_DIR)/*.o $(BIN_DIR)/*

run: all fix_easyrsa
	./$(TARGET)

mrproper: clean
	rm -f $(TARGET)
	rm -rf easyrsa_modified
	rm -rf ./pki

.PHONY: all clean mrproper fix_easyrsa