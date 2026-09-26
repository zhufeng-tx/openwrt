CC ?= cc
CXX ?= c++
CFLAGS ?= -O2 -Wall -Wextra -Werror
CXXFLAGS ?= -O2 -Wall -Wextra -Werror -std=gnu++20
TARGET_CFLAGS ?= $(CFLAGS)
TARGET_CXXFLAGS ?= $(CXXFLAGS)
TARGET_CPPFLAGS ?= $(CPPFLAGS)
TARGET_LDFLAGS ?=
TARGET_LIBS ?= -lubus -lubox -lblobmsg_json -lgpiod -luci -lmbedcrypto -lz
NATIVE_CRYPTO_CFLAGS ?= $(shell pkg-config --cflags openssl zlib 2>/dev/null)
NATIVE_CRYPTO_LIBS ?= $(shell pkg-config --libs openssl zlib 2>/dev/null)
NATIVE_STAGE_DIR ?= $(abspath ../../../../staging_dir/host)
NATIVE_PTY_LIBS = $(if $(filter Linux,$(shell uname -s)),-lutil,)
NATIVE_IPERF_STUB = /tmp/remote-tester-radio-iperf-stub
NATIVE_RUNTIME_CFLAGS = $(CFLAGS) -ffunction-sections -fdata-sections \
	$(NATIVE_CRYPTO_CFLAGS) -I../tests/stubs -I. -I$(NATIVE_STAGE_DIR)/include
NATIVE_RUNTIME_LDFLAGS = -L$(NATIVE_STAGE_DIR)/lib \
	-Wl,-rpath,$(NATIVE_STAGE_DIR)/lib
CPPFLAGS += -I. -Ivendor/sx126x
RADIOLIB_SRC = vendor/RadioLib/src
RADIOLIB_SRCS = $(RADIOLIB_SRC)/Hal.cpp $(RADIOLIB_SRC)/Module.cpp \
	$(RADIOLIB_SRC)/protocols/PhysicalLayer/PhysicalLayer.cpp \
	$(wildcard $(RADIOLIB_SRC)/utils/*.cpp) \
	$(RADIOLIB_SRC)/modules/SX126x/SX1262.cpp \
	$(RADIOLIB_SRC)/modules/SX126x/SX126x.cpp \
	$(RADIOLIB_SRC)/modules/SX126x/SX126x_commands.cpp \
	$(RADIOLIB_SRC)/modules/SX126x/SX126x_config.cpp \
	$(RADIOLIB_SRC)/modules/SX126x/SX126x_LR_FHSS.cpp
RADIOLIB_OBJS = $(RADIOLIB_SRCS:.cpp=.o)
DAEMON_OBJS = remote-tester-radio.o radio_core.o radio_linux.o radiolib_backend.o \
	rt_network_runtime.o rt_ip_offload.o rt_command.o \
	host/rt_host_framing.o host/rt_host_auth.o host/rt_host_secure.o host/rt_host_server.o \
	network/network_wire.o network/network_schedule.o network/network_transport.o $(RADIOLIB_OBJS)

all: remote-tester-radio
remote-tester-radio: $(DAEMON_OBJS)
	$(CXX) $(TARGET_LDFLAGS) -o $@ $^ $(TARGET_LIBS)

%.o: %.c
	$(CC) $(TARGET_CPPFLAGS) $(CPPFLAGS) $(TARGET_CFLAGS) -c -o $@ $<

%.o: %.cpp
	$(CXX) $(TARGET_CPPFLAGS) $(CPPFLAGS) $(TARGET_CXXFLAGS) -std=gnu++20 -c -o $@ $<

test: /tmp/remote-tester-radio-core-test /tmp/remote-tester-radio-host-framing-test \
	/tmp/remote-tester-radio-network-core-test /tmp/remote-tester-radio-runtime-test \
	/tmp/remote-tester-radio-capacity-test /tmp/remote-tester-radio-command-test \
	/tmp/remote-tester-radio-host-secure-test /tmp/remote-tester-radio-host-server-test \
	/tmp/remote-tester-radio-host-uart-test /tmp/remote-tester-radio-ip-offload-test
	/tmp/remote-tester-radio-core-test
	/tmp/remote-tester-radio-host-framing-test
	/tmp/remote-tester-radio-network-core-test
	/tmp/remote-tester-radio-runtime-test
	/tmp/remote-tester-radio-capacity-test
	/tmp/remote-tester-radio-command-test
	/tmp/remote-tester-radio-host-secure-test
	/tmp/remote-tester-radio-host-server-test
	/tmp/remote-tester-radio-host-uart-test
	/tmp/remote-tester-radio-ip-offload-test

test-sanitize: /tmp/remote-tester-radio-network-core-test-asan \
	/tmp/remote-tester-radio-runtime-test-asan \
	/tmp/remote-tester-radio-capacity-test-asan
	ASAN_OPTIONS=detect_leaks=0 /tmp/remote-tester-radio-network-core-test-asan
	ASAN_OPTIONS=detect_leaks=0 /tmp/remote-tester-radio-runtime-test-asan
	ASAN_OPTIONS=detect_leaks=0 /tmp/remote-tester-radio-capacity-test-asan
/tmp/remote-tester-radio-core-test: ../tests/test_radio_core.c radio_core.c radio_core.h
	$(CC) $(CFLAGS) -I. -o $@ ../tests/test_radio_core.c radio_core.c

/tmp/remote-tester-radio-host-framing-test: ../tests/test_host_framing.c host/rt_host_framing.c host/rt_host_framing.h
	$(CC) $(CFLAGS) -I. -o $@ ../tests/test_host_framing.c host/rt_host_framing.c

/tmp/remote-tester-radio-network-core-test: ../tests/test_network_core.c network/network_wire.c network/network_schedule.c network/network_transport.c network/network.h
	$(CC) $(CFLAGS) $(NATIVE_CRYPTO_CFLAGS) -DNETWORK_TEST_USE_OPENSSL -I. -Inetwork -o $@ \
		../tests/test_network_core.c network/network_wire.c network/network_schedule.c \
		network/network_transport.c $(NATIVE_CRYPTO_LIBS)

/tmp/remote-tester-radio-runtime-test: ../tests/test_network_runtime.c rt_network_runtime.c \
	rt_network_runtime.h radio_core.h network/network.h rt_command.h rt_ip_offload.h \
	rt_command.c network/network_wire.c network/network_schedule.c network/network_transport.c \
	radio_core.c ../tests/stubs/mbedtls_shim.c
	$(CC) $(NATIVE_RUNTIME_CFLAGS) -o $@ ../tests/test_network_runtime.c rt_network_runtime.c \
		rt_command.c network/network_wire.c network/network_schedule.c network/network_transport.c \
		radio_core.c ../tests/stubs/mbedtls_shim.c $(NATIVE_RUNTIME_LDFLAGS) \
		-lubox -lblobmsg_json -ljson-c -lz -lcrypto $(NATIVE_PTY_LIBS)

/tmp/remote-tester-radio-capacity-test: ../tests/test_network_capacity.c rt_network_runtime.c \
	rt_network_runtime.h radio_core.h network/network.h rt_command.h rt_ip_offload.h \
	rt_command.c network/network_wire.c network/network_schedule.c network/network_transport.c \
	radio_core.c ../tests/stubs/mbedtls_shim.c
	$(CC) $(NATIVE_RUNTIME_CFLAGS) -o $@ ../tests/test_network_capacity.c rt_network_runtime.c \
		rt_command.c network/network_wire.c network/network_schedule.c network/network_transport.c \
		radio_core.c ../tests/stubs/mbedtls_shim.c $(NATIVE_RUNTIME_LDFLAGS) \
		-lubox -lblobmsg_json -ljson-c -lz -lcrypto

/tmp/remote-tester-radio-runtime-test-asan: ../tests/test_network_runtime.c rt_network_runtime.c \
	rt_network_runtime.h radio_core.h network/network.h rt_command.h rt_ip_offload.h \
	rt_command.c network/network_wire.c network/network_schedule.c network/network_transport.c \
	radio_core.c ../tests/stubs/mbedtls_shim.c
	$(CC) -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined \
		-fno-omit-frame-pointer -ffunction-sections -fdata-sections $(NATIVE_CRYPTO_CFLAGS) \
		-I../tests/stubs -I. -I$(NATIVE_STAGE_DIR)/include -o $@ \
		../tests/test_network_runtime.c rt_network_runtime.c rt_command.c network/network_wire.c \
		network/network_schedule.c network/network_transport.c radio_core.c \
		../tests/stubs/mbedtls_shim.c $(NATIVE_RUNTIME_LDFLAGS) \
		-lubox -lblobmsg_json -ljson-c -lz -lcrypto $(NATIVE_PTY_LIBS)

/tmp/remote-tester-radio-capacity-test-asan: ../tests/test_network_capacity.c rt_network_runtime.c \
	rt_network_runtime.h radio_core.h network/network.h rt_command.h rt_ip_offload.h \
	rt_command.c network/network_wire.c network/network_schedule.c network/network_transport.c \
	radio_core.c ../tests/stubs/mbedtls_shim.c
	$(CC) -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined \
		-fno-omit-frame-pointer -ffunction-sections -fdata-sections $(NATIVE_CRYPTO_CFLAGS) \
		-I../tests/stubs -I. -I$(NATIVE_STAGE_DIR)/include -o $@ \
		../tests/test_network_capacity.c rt_network_runtime.c rt_command.c network/network_wire.c \
		network/network_schedule.c network/network_transport.c radio_core.c \
		../tests/stubs/mbedtls_shim.c $(NATIVE_RUNTIME_LDFLAGS) \
		-lubox -lblobmsg_json -ljson-c -lz -lcrypto

$(NATIVE_IPERF_STUB): ../tests/iperf_stub.c
	$(CC) $(CFLAGS) -o $@ $<

/tmp/remote-tester-radio-command-test: ../tests/test_command.c rt_command.c rt_command.h \
		$(NATIVE_IPERF_STUB)
	$(CC) $(NATIVE_RUNTIME_CFLAGS) \
		-DRT_COMMAND_IPERF_PATH=\"$(NATIVE_IPERF_STUB)\" -I. -o $@ \
		../tests/test_command.c rt_command.c $(NATIVE_RUNTIME_LDFLAGS) \
		-lubox -lblobmsg_json -ljson-c -lcrypto

/tmp/remote-tester-radio-host-secure-test: ../tests/test_host_secure.c \
		host/rt_host_auth.c host/rt_host_secure.c ../tests/stubs/mbedtls_shim.c
	$(CC) $(NATIVE_RUNTIME_CFLAGS) -o $@ $^ $(NATIVE_RUNTIME_LDFLAGS) -lcrypto

/tmp/remote-tester-radio-host-server-test: ../tests/test_host_server.c \
		host/rt_host_framing.c host/rt_host_auth.c host/rt_host_secure.c \
		host/rt_host_server.c ../tests/stubs/mbedtls_shim.c \
		../tests/stubs/host_key_shim.c
	$(CC) $(NATIVE_RUNTIME_CFLAGS) -DRT_HOST_TEST_HOOKS -o $@ $^ $(NATIVE_RUNTIME_LDFLAGS) \
		-lubox -lblobmsg_json -ljson-c -lz -lcrypto

/tmp/remote-tester-radio-host-uart-test: ../tests/test_host_uart.c \
		host/rt_host_framing.c host/rt_host_auth.c host/rt_host_secure.c \
		host/rt_host_server.c ../tests/stubs/mbedtls_shim.c \
		../tests/stubs/host_key_shim.c
	$(CC) $(NATIVE_RUNTIME_CFLAGS) -DRT_HOST_TEST_HOOKS -o $@ $^ $(NATIVE_RUNTIME_LDFLAGS) \
		-lubox -lblobmsg_json -ljson-c -lz -lcrypto $(NATIVE_PTY_LIBS)

/tmp/remote-tester-radio-ip-offload-test: ../tests/test_ip_offload.c rt_ip_offload.c \
		rt_ip_offload.h host/rt_host_auth.c host/rt_host_framing.c \
		../tests/stubs/mbedtls_shim.c
	$(CC) $(NATIVE_RUNTIME_CFLAGS) -o $@ ../tests/test_ip_offload.c \
		rt_ip_offload.c host/rt_host_auth.c host/rt_host_framing.c \
		../tests/stubs/mbedtls_shim.c $(NATIVE_RUNTIME_LDFLAGS) \
		-lubox -lblobmsg_json -ljson-c -lz -lcrypto

/tmp/remote-tester-radio-network-core-test-asan: ../tests/test_network_core.c \
		network/network_wire.c network/network_schedule.c network/network_transport.c network/network.h
	$(CC) -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined \
		-fno-omit-frame-pointer -I. -Inetwork -DNETWORK_TEST_USE_OPENSSL \
		$(NATIVE_CRYPTO_CFLAGS) -o $@ ../tests/test_network_core.c \
		network/network_wire.c network/network_schedule.c network/network_transport.c \
		$(NATIVE_CRYPTO_LIBS)

clean:
	rm -f $(DAEMON_OBJS) remote-tester-radio /tmp/remote-tester-radio-core-test \
		/tmp/remote-tester-radio-host-framing-test /tmp/remote-tester-radio-network-core-test \
		/tmp/remote-tester-radio-runtime-test /tmp/remote-tester-radio-capacity-test \
		/tmp/remote-tester-radio-runtime-test-asan /tmp/remote-tester-radio-capacity-test-asan \
		/tmp/remote-tester-radio-command-test /tmp/remote-tester-radio-host-secure-test \
		/tmp/remote-tester-radio-host-server-test /tmp/remote-tester-radio-host-uart-test \
		/tmp/remote-tester-radio-ip-offload-test /tmp/remote-tester-radio-network-core-test-asan \
		$(NATIVE_IPERF_STUB)
