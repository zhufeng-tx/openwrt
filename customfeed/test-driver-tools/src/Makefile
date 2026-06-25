TOOLS = tcp_test udp_test dsleep_test hgpriv hgota libnetat bw_test_bwc

all: $(TOOLS)

tcp_test: tcp_test.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

udp_test: udp_test.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

dsleep_test: dsleep_test.c iwpriv.c hgic.h
	$(CC) $(CFLAGS) $(LDFLAGS) -lpthread -o $@ dsleep_test.c

hgpriv: hgpriv.c iwpriv.c hgic.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ hgpriv.c

hgota: hgota.c libota.c fwinfo.c libota.h fwinfo.h
	$(CC) $(CFLAGS) $(LDFLAGS) -lm -o $@ hgota.c libota.c fwinfo.c

libnetat: libnetat.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

bw_test_bwc: bw_test_bwc.c
	$(CC) $(CFLAGS) $(LDFLAGS) -lutil -o $@ $<

clean:
	rm -f $(TOOLS) *.o
