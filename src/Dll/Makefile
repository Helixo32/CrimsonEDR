CC=x86_64-w64-mingw32-gcc
CFLAGS=-Iincludes -Wall -D_DLL -D_EXPORTS
BINDIR=bin
TARGET=$(BINDIR)/CrimsonEDR.dll
SRCS=$(wildcard *.c detection/*.c hook/*.c utils/*.c)
OBJS=$(SRCS:%.c=$(BINDIR)/%.o)
LDFLAGS=-shared -Wl,--out-implib,$(BINDIR)/libCrimsonEDR.a



all: $(TARGET)

$(TARGET): $(OBJS)
	mkdir -p $(@D)
	$(CC) -o $@ $(OBJS) $(LDFLAGS) -lpsapi -ldbghelp
	@echo "DLL generated."

$(BINDIR)/%.o: %.c
	mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "Compiled "$<


clean:
	rm -rf $(BINDIR)

.PHONY: all clean
