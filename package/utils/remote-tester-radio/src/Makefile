CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -Werror
TARGET_CFLAGS ?= $(CFLAGS)
TARGET_LDFLAGS ?=
CPPFLAGS += -I. -Ivendor/sx126x
DAEMON_OBJS = remote-tester-radio.o radio_core.o radio_linux.o vendor/sx126x/sx126x.o

all: remote-tester-radio
remote-tester-radio: $(DAEMON_OBJS)
	$(CC) $(TARGET_LDFLAGS) -o $@ $^ -lubus -lubox -lgpiod -luci

test: /tmp/remote-tester-radio-core-test
	/tmp/remote-tester-radio-core-test
/tmp/remote-tester-radio-core-test: ../tests/test_radio_core.c radio_core.c radio_core.h
	$(CC) $(CFLAGS) -I. -o $@ ../tests/test_radio_core.c radio_core.c
clean:
	rm -f $(DAEMON_OBJS) remote-tester-radio /tmp/remote-tester-radio-core-test
