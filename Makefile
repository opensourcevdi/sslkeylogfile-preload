all: LD_PRELOAD_sslkeylogfile.so

LD_PRELOAD_%.so: LD_PRELOAD_%.c
	$(CC) $(CFLAGS) -fPIC -shared -o $@ $< -ldl -Wl,--no-as-needed $(LDFLAGS)
