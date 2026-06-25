CC ?= cc
CFLAGS ?= -O2
LDFLAGS ?=
LDLIBS ?=

TARGET := wltp
SRCS := main.c net.c proto.c stats.c clock.c \
	proto_artnet.c proto_sacn.c proto_osc.c proto_manet2.c \
	proto_rtpmidi.c proto_psn.c proto_klingnet.c proto_citp.c \
	proto_kinet.c
OBJS := $(SRCS:.c=.o)

CPPFLAGS += -D_GNU_SOURCE

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) -pthread $(LDLIBS)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -pthread -c -o $@ $<

clean:
	rm -f $(TARGET) $(OBJS)
