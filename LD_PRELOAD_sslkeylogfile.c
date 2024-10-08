#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>

#include <openssl/ssl.h>

#define PRELOAD(sym_t, sym)                                                    \
  static sym_t (*_##sym)();                                                    \
  __attribute__((constructor)) static void _##sym##_init() {                   \
    _##sym = dlsym(RTLD_NEXT, #sym);                                           \
  }                                                                            \
  sym_t(sym)

static void cb(const SSL *ssl, const char *line) {
  char *SSLKEYLOGFILE = getenv("SSLKEYLOGFILE");
  if (!SSLKEYLOGFILE || !*SSLKEYLOGFILE)
    return;
  FILE *file = fopen(SSLKEYLOGFILE, "a");
  if (!file)
    return;
  fprintf(file, "%s\n", line);
  fclose(file);
}

PRELOAD(SSL *, SSL_new)(SSL_CTX *ctx) {
  SSL *ret = _SSL_new(ctx);
  SSL_CTX_set_keylog_callback(ctx, cb);
  return ret;
}
