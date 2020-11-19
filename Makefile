CFILES   = $(wildcard *.c)
OBJFILES = $(CFILES:.c=.o)
OUT      = yapofw

CC      = gcc
CFLAGS  = -flto -Wall
LDFLAGS = -flto
GDB     = gdb

.depend: $(CFILES)
	rm -f ./.depend
	$(CC) $(CFLAGS) -MM $(CFILES) > ./.depend

include .depend

$(OUT): $(OBJFILES)

.PHONY: clean run release debug
clean:
	rm -f $(OBJFILES) $(OUT)
	rm -f ./.depend

run: $(OUT)
	-./$(OUT) $(conf) $(stats)

debug: CFLAGS += -g
debug: $(OUT)
	- $(GDB) --args ./$(OUT) $(conf) $(stats)

release: CFLAGS += -O3
release: LDFLAGS += -O3
release: $(OUT)