CC ?= gcc
CFLAGS ?= -Os
LDFLAGS ?=
LDLIBS ?= -lmicrohttpd -ljson-c

TARGET := openwrt-mcpd
OBJS := openwrt-mcpd.o

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -Wall -Wextra -c -o $@ $<

clean:
	rm -f $(TARGET) $(OBJS)
