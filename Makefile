CFILES   = $(wildcard *.c)
OBJFILES = $(CFILES:.c=.o)
OUT      = yapofw

CC      = gcc
CFLAGS  = -Wall

$(OUT): $(OBJFILES)

.PHONY: clean run
clean:
	rm -f $(OBJFILES) $(OUT)

run: $(OUT)
	-./$(OUT) $(conf)