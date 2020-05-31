TOP_DIR = .
INC_DIR = $(TOP_DIR)/inc
SRC_DIR = $(TOP_DIR)/src
BUILD_DIR = $(TOP_DIR)/build
TEST_DIR = $(TOP_DIR)/test

CC=gcc
FLAGS = -pthread -g -ggdb -Wall -DDEBUG -I$(INC_DIR)
OBJS = $(BUILD_DIR)/cmu_packet.o \
	$(BUILD_DIR)/cmu_tcp.o \
	$(BUILD_DIR)/backend.o \
	$(BUILD_DIR)/ringbuffer.o \
	$(BUILD_DIR)/buffer.o \
	$(BUILD_DIR)/log.o \
	$(BUILD_DIR)/timer.o

.PHONY: all server client $(BUILD_DIR)/%.o

default:all
all: server client

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | build_dir
	$(CC) $(FLAGS) -c -o $@ $<

server: $(OBJS)
	$(CC) $(FLAGS) $(SRC_DIR)/server.c -o server $(OBJS)

client: $(OBJS)
	$(CC) $(FLAGS) $(SRC_DIR)/client.c -o client $(OBJS)

build_dir:
	mkdir -p $(BUILD_DIR)

# run tests
test: all testing_server
	head -c 100M </dev/urandom > $(TEST_DIR)/random.input
	sudo python2 -m pytest -vs -p no:warnings $(TEST_DIR)

testing_server: $(OBJS)
	$(CC) $(FLAGS) $(TEST_DIR)/testing_server.c -o $(TEST_DIR)/testing_server $(OBJS)

clean:
	-rm -f $(BUILD_DIR)/*.o client server testing_server $(TEST_DIR)/file.c $(TEST_DIR)/random.input

ringbuffer-test:
	$(CC) $(FLAGS) -c $(SRC_DIR)/ringbuffer.c -o $(BUILD_DIR)/ringbuffer.o
	$(CC) $(FLAGS) $(SRC_DIR)/ringbuffer_test.c -o $(BUILD_DIR)/ringbuffer_test  $(BUILD_DIR)/ringbuffer.o
	$(BUILD_DIR)/ringbuffer_test

timer-test:
	$(CC) $(FLAGS) -c $(SRC_DIR)/timer.c -o $(BUILD_DIR)/timer.o
	$(CC) $(FLAGS) $(SRC_DIR)/timer_test.c -o $(BUILD_DIR)/timer_test  $(BUILD_DIR)/timer.o
	$(BUILD_DIR)/timer_test

backend-test: $(OBJS)
	$(CC) $(FLAGS) $(SRC_DIR)/backend_test.c -o $(BUILD_DIR)/backend_test $(OBJS)
	$(BUILD_DIR)/backend_test
