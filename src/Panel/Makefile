CC=x86_64-w64-mingw32-gcc
CFLAGS=-Iincludes -Wall
TARGET=bin/CrimsonEDRPanel.exe
SRCS=injector/injector.c utils/extractJson.c main.c
OBJS=$(SRCS:%.c=bin/%.o)
	

$(shell mkdir -p bin/injector bin/utils)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

bin/%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf bin

bin/injector/injector.o: includes/injector/injector.h includes/macro.h
bin/main.o: includes/injector/injector.h includes/macro.h

.PHONY: all clean
