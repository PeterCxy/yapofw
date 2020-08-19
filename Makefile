CFILES   = $(wildcard *.c)
OBJFILES = $(CFILES:.c=.o)
OUT      = yapofw

CC      = gcc
CFLAGS  = -Wall

.depend: $(CFILES)
	rm -f ./.depend
	$(CC) $(CFLAGS) -MM $(CFILES) > ./.depend

include .depend

$(OUT): $(OBJFILES)

.PHONY: clean run
clean:
	rm -f $(OBJFILES) $(OUT)
	rm -f ./.depend

run: $(OUT)
	-./$(OUT) $(conf) $(stats)