include ./Makefile.inc

SRC_DIR := src
UTILS_DIR := $(SRC_DIR)/utils
SERVER_DIR := $(SRC_DIR)/server
CLIENT_DIR := $(SRC_DIR)/client
TEST_DIR := tests

SERVER_SOURCES := $(wildcard $(SERVER_DIR)/*.c)
CLIENT_SOURCES := $(wildcard $(CLIENT_DIR)/*.c)
UTILS_SOURCES := $(wildcard $(UTILS_DIR)/*.c)
TEST_SOURCES := $(wildcard $(TEST_DIR)/*.c)

OBJECTS_FOLDER := ./obj
OUTPUT_FOLDER := ./bin

SERVER_OBJECTS := $(patsubst %.c,$(OBJECTS_FOLDER)/%.o,$(subst $(SRC_DIR)/,,$(SERVER_SOURCES)))
CLIENT_OBJECTS := $(patsubst %.c,$(OBJECTS_FOLDER)/%.o,$(subst $(SRC_DIR)/,,$(CLIENT_SOURCES)))
UTILS_OBJECTS := $(patsubst %.c,$(OBJECTS_FOLDER)/%.o,$(subst $(SRC_DIR)/,,$(UTILS_SOURCES)))
TEST_OBJECTS := $(patsubst %.c,$(OBJECTS_FOLDER)/%.o,$(TEST_SOURCES))

SERVER_OUTPUT_FILE := $(OUTPUT_FOLDER)/socks5
CLIENT_OUTPUT_FILE := $(OUTPUT_FOLDER)/client
TEST_OUTPUTS := $(patsubst $(TEST_DIR)/%.c,$(OUTPUT_FOLDER)/%_test,$(TEST_SOURCES))

ifneq ($(WSL), 0)
COMPILERFLAGS += -D_POSIX_C_SOURCE=200112L
endif

ifneq ($(MAC), 0)
COMPILERFLAGS += -DMSG_NOSIGNAL=0
endif

all: server client 

server: $(SERVER_OUTPUT_FILE)
client: $(CLIENT_OUTPUT_FILE)
tests: $(TEST_OUTPUTS)

$(SERVER_OUTPUT_FILE): $(SERVER_OBJECTS) $(UTILS_OBJECTS)
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILERFLAGS) $(LDFLAGS) $^ -o $@

$(CLIENT_OUTPUT_FILE): $(CLIENT_OBJECTS) $(UTILS_OBJECTS) $(OBJECTS_FOLDER)/server/users.o
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILERFLAGS) $(LDFLAGS) $^ -o $@


$(OUTPUT_FOLDER)/%_test: $(OBJECTS_FOLDER)/tests/%.o $(UTILS_OBJECTS)
	mkdir -p $(OUTPUT_FOLDER)
	$(COMPILER) $(COMPILERFLAGS) $(CHECK_CFLAGS) $(CHECK_LDFLAGS) $^ -o $@

$(OBJECTS_FOLDER)/%.o: $(SRC_DIR)/%.c
	mkdir -p $(dir $@)
	$(COMPILER) $(COMPILERFLAGS) -c $< -o $@

$(OBJECTS_FOLDER)/tests/%.o: $(TEST_DIR)/%.c
	mkdir -p $(dir $@)
	$(COMPILER) $(COMPILERFLAGS) -c $< -o $@

clean:
	rm -rf $(OUTPUT_FOLDER)
	rm -rf $(OBJECTS_FOLDER)

.PHONY: all server client tests clean
