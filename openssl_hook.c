#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <unistd.h>
#include <netinet/in.h>
#include <stdint.h>
#include <sys/uio.h>
#include <string.h>
#include <openssl/evp.h>

#define HOOK_LOG "hooklog.log"

#define _CONSTRUCTOR __attribute__((constructor))
#define _DESTRUCTOR __attribute__ ((destructor))
#define _FORCEINLINE __attribute__ ((always_inline))

#define LOADORDIE(var, name) \
	do {\
		const char *err; \
		(var) = dlsym(RTLD_NEXT, (name)); \
		if ((err = dlerror()) != NULL) { \
			fprintf(stderr, "dlsym %s: %s\n", (name), err); \
			exit(EXIT_FAILURE); \
		} \
	} while(0)

#ifdef __owur
#undef __owur
#endif 
#define __owur
#define STRLEN(s) ((s) ? strlen((const char *)(s)) : 0)
static void __dump(const uint8_t *buf, const char *func_name, const char *tag);
static void __dump_hex(const uint8_t *buf, int len, const char *func_name, const char *tag);
#define dump_hex(buf, len, tag) do {__dump_hex((const uint8_t *)buf, len, __FUNCTION__, tag);} while(0)
// #define dump_hex(buf, len, tag) printf("buf:%s %s %s\n", buf, __FUNCTION__, tag)
#define dump(buf, tag) do {__dump(buf, __FUNCTION__, tag);} while(0)
#define dump_func_name() do {__dump((const uint8_t*)"", __FUNCTION__, "FUNC");} while(0)


struct hook_ctx { 
    int logfd;
    __owur int (*EVP_DigestInit_ex)(EVP_MD_CTX *ctx, const EVP_MD *type,
                                    ENGINE *impl);
    __owur int (*EVP_DigestUpdate)(EVP_MD_CTX *ctx, const void *d,
                                    size_t cnt);
    __owur int (*EVP_DigestFinal_ex)(EVP_MD_CTX *ctx, unsigned char *md,
                                    unsigned int *s);
    __owur int (*EVP_Digest)(const void *data, size_t count,
                            unsigned char *md, unsigned int *size,
                            const EVP_MD *type, ENGINE *impl);

    __owur int (*EVP_MD_CTX_copy)(EVP_MD_CTX *out, const EVP_MD_CTX *in);
    __owur int (*EVP_DigestInit)(EVP_MD_CTX *ctx, const EVP_MD *type);
    __owur int (*EVP_DigestFinal)(EVP_MD_CTX *ctx, unsigned char *md,
                            unsigned int *s);

    __owur int (*EVP_EncryptInit)(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                            const unsigned char *key, const unsigned char *iv);
    /*__owur*/ int (*EVP_EncryptInit_ex)(EVP_CIPHER_CTX *ctx,
                                    const EVP_CIPHER *cipher, ENGINE *impl,
                                    const unsigned char *key,
                                    const unsigned char *iv);
    /*__owur*/ int (*EVP_EncryptUpdate)(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                    int *outl, const unsigned char *in, int inl);
    /*__owur*/ int (*EVP_EncryptFinal_ex)(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                    int *outl);
    /*__owur*/ int (*EVP_EncryptFinal)(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                    int *outl);

    __owur int (*EVP_DecryptInit)(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                            const unsigned char *key, const unsigned char *iv);
    /*__owur*/ int (*EVP_DecryptInit_ex)(EVP_CIPHER_CTX *ctx,
                                    const EVP_CIPHER *cipher, ENGINE *impl,
                                    const unsigned char *key,
                                    const unsigned char *iv);
    /*__owur*/ int (*EVP_DecryptUpdate)(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                    int *outl, const unsigned char *in, int inl);
    __owur int (*EVP_DecryptFinal)(EVP_CIPHER_CTX *ctx, unsigned char *outm,
                                int *outl);
    /*__owur*/ int (*EVP_DecryptFinal_ex)(EVP_CIPHER_CTX *ctx, unsigned char *outm,
                                    int *outl);

    __owur int (*EVP_CipherInit)(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                            const unsigned char *key, const unsigned char *iv,
                            int enc);
    /*__owur*/ int (*EVP_CipherInit_ex)(EVP_CIPHER_CTX *ctx,
                                    const EVP_CIPHER *cipher, ENGINE *impl,
                                    const unsigned char *key,
                                    const unsigned char *iv, int enc);
    __owur int (*EVP_CipherUpdate)(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                int *outl, const unsigned char *in, int inl);
    __owur int (*EVP_CipherFinal)(EVP_CIPHER_CTX *ctx, unsigned char *outm,
                            int *outl);
    __owur int (*EVP_CipherFinal_ex)(EVP_CIPHER_CTX *ctx, unsigned char *outm,
                                int *outl);

    __owur int (*EVP_SignFinal)(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s,
                            EVP_PKEY *pkey);

    __owur int (*EVP_VerifyFinal)(EVP_MD_CTX *ctx, const unsigned char *sigbuf,
                            unsigned int siglen, EVP_PKEY *pkey);

    /*__owur*/ int (*EVP_DigestSignInit)(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
                                    const EVP_MD *type, ENGINE *e,
                                    EVP_PKEY *pkey);
    __owur int (*EVP_DigestSignFinal)(EVP_MD_CTX *ctx, unsigned char *sigret,
                                size_t *siglen);

    __owur int (*EVP_DigestVerifyInit)(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
                                    const EVP_MD *type, ENGINE *e,
                                    EVP_PKEY *pkey);
    __owur int (*EVP_DigestVerifyFinal)(EVP_MD_CTX *ctx, unsigned char *sig,
                                    size_t siglen);

};
static struct hook_ctx _ctx;

#if 0 
/* =============================================================== */
/* copyed declare */

__owur int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type,
                                 ENGINE *impl);
__owur int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d,
                                size_t cnt);
__owur int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md,
                                  unsigned int *s);
__owur int EVP_Digest(const void *data, size_t count,
                          unsigned char *md, unsigned int *size,
                          const EVP_MD *type, ENGINE *impl);

__owur int EVP_MD_CTX_copy(EVP_MD_CTX *out, const EVP_MD_CTX *in);
__owur int EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type);
__owur int EVP_DigestFinal(EVP_MD_CTX *ctx, unsigned char *md,
                           unsigned int *s);


__owur int EVP_EncryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                           const unsigned char *key, const unsigned char *iv);
/*__owur*/ int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx,
                                  const EVP_CIPHER *cipher, ENGINE *impl,
                                  const unsigned char *key,
                                  const unsigned char *iv);
/*__owur*/ int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                 int *outl, const unsigned char *in, int inl);
/*__owur*/ int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                   int *outl);
/*__owur*/ int EVP_EncryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                int *outl);

__owur int EVP_DecryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                           const unsigned char *key, const unsigned char *iv);
/*__owur*/ int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx,
                                  const EVP_CIPHER *cipher, ENGINE *impl,
                                  const unsigned char *key,
                                  const unsigned char *iv);
/*__owur*/ int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                 int *outl, const unsigned char *in, int inl);
__owur int EVP_DecryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm,
                            int *outl);
/*__owur*/ int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm,
                                   int *outl);

__owur int EVP_CipherInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                          const unsigned char *key, const unsigned char *iv,
                          int enc);
/*__owur*/ int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx,
                                 const EVP_CIPHER *cipher, ENGINE *impl,
                                 const unsigned char *key,
                                 const unsigned char *iv, int enc);
__owur int EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                            int *outl, const unsigned char *in, int inl);
__owur int EVP_CipherFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm,
                           int *outl);
__owur int EVP_CipherFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm,
                              int *outl);

__owur int EVP_SignFinal(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s,
                         EVP_PKEY *pkey);

__owur int EVP_VerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sigbuf,
                           unsigned int siglen, EVP_PKEY *pkey);

/*__owur*/ int EVP_DigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
                                  const EVP_MD *type, ENGINE *e,
                                  EVP_PKEY *pkey);
__owur int EVP_DigestSignFinal(EVP_MD_CTX *ctx, unsigned char *sigret,
                               size_t *siglen);

__owur int EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
                                const EVP_MD *type, ENGINE *e,
                                EVP_PKEY *pkey);
__owur int EVP_DigestVerifyFinal(EVP_MD_CTX *ctx, unsigned char *sig,
                                 size_t siglen);
#endif
static const char* get_logfile() {
    const char *s = getenv("HOOK_LOG");
    if (!s || STRLEN(s) <= 0) {
        return HOOK_LOG;
    }
    return s;
}

unsigned int session_id = 0;
void _CONSTRUCTOR hook_init(void) {
	const char *fp = get_logfile();
	session_id = rand()%0xffff;
	_ctx.logfd = open(fp, O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
	if (_ctx.logfd < 0) {
        _ctx.logfd = dup(fileno(stderr));
        if (_ctx.logfd < 0) {
            fprintf(stderr, "[HOOK] unable to create %s or stderr\n", fp);
		    exit(EXIT_FAILURE);
        }
		fprintf(stderr, "[HOOK] unable to create %s, using stderr\n", fp);
	}
    fprintf(stderr, "[HOOK] redirect session 0x%x output to %s\n", session_id, fp);
	dump((const uint8_t *)"===================", "INIT");
	dlerror();
	// LOADORDIE(_ctx.SSL_read, "SSL_read");
	// LOADORDIE(_ctx.SSL_write, "SSL_write");
	// LOADORDIE(_ctx.SSL_get_rfd, "SSL_get_rfd");
	// LOADORDIE(_ctx.SSL_get_wfd, "SSL_get_wfd");
    LOADORDIE(_ctx.EVP_DigestInit_ex     , "EVP_DigestInit_ex");
    LOADORDIE(_ctx.EVP_DigestUpdate      , "EVP_DigestUpdate");
    LOADORDIE(_ctx.EVP_DigestFinal_ex    , "EVP_DigestFinal_ex");
    LOADORDIE(_ctx.EVP_Digest            , "EVP_Digest");
    LOADORDIE(_ctx.EVP_MD_CTX_copy       , "EVP_MD_CTX_copy");
    LOADORDIE(_ctx.EVP_DigestInit        , "EVP_DigestInit");
    LOADORDIE(_ctx.EVP_DigestFinal       , "EVP_DigestFinal");
    LOADORDIE(_ctx.EVP_EncryptInit       , "EVP_EncryptInit");
    LOADORDIE(_ctx.EVP_EncryptInit_ex    , "EVP_EncryptInit_ex");
    LOADORDIE(_ctx.EVP_EncryptUpdate     , "EVP_EncryptUpdate");
    LOADORDIE(_ctx.EVP_EncryptFinal_ex   , "EVP_EncryptFinal_ex");
    LOADORDIE(_ctx.EVP_EncryptFinal      , "EVP_EncryptFinal");
    LOADORDIE(_ctx.EVP_DecryptInit       , "EVP_DecryptInit");
    LOADORDIE(_ctx.EVP_DecryptInit_ex    , "EVP_DecryptInit_ex");
    LOADORDIE(_ctx.EVP_DecryptUpdate     , "EVP_DecryptUpdate");
    LOADORDIE(_ctx.EVP_DecryptFinal      , "EVP_DecryptFinal");
    LOADORDIE(_ctx.EVP_DecryptFinal_ex   , "EVP_DecryptFinal_ex");
    LOADORDIE(_ctx.EVP_CipherInit        , "EVP_CipherInit");
    LOADORDIE(_ctx.EVP_CipherInit_ex     , "EVP_CipherInit_ex");
    LOADORDIE(_ctx.EVP_CipherUpdate      , "EVP_CipherUpdate");
    LOADORDIE(_ctx.EVP_CipherFinal       , "EVP_CipherFinal");
    LOADORDIE(_ctx.EVP_CipherFinal_ex    , "EVP_CipherFinal_ex");
    LOADORDIE(_ctx.EVP_SignFinal         , "EVP_SignFinal");
    LOADORDIE(_ctx.EVP_VerifyFinal       , "EVP_VerifyFinal");
    LOADORDIE(_ctx.EVP_DigestSignInit    , "EVP_DigestSignInit");
    LOADORDIE(_ctx.EVP_DigestSignFinal   , "EVP_DigestSignFinal");
    LOADORDIE(_ctx.EVP_DigestVerifyInit  , "EVP_DigestVerifyInit");
    LOADORDIE(_ctx.EVP_DigestVerifyFinal , "EVP_DigestVerifyFinal");
}

void _DESTRUCTOR hook_fini(void) {
	close(_ctx.logfd);
}


/* =============================================================== */
/* realize */

#define __CALL_RETURN(name, args...) do {return _ctx.#name(##args)} while(0)
#define CALL_RETURN(ctx, args...) __CALL_RETURN(__FUNCTION__, ctx, ##args)

__owur int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type,
                                 ENGINE *impl) {
	dump_func_name();
    return _ctx.EVP_DigestInit_ex(ctx, type, impl);
}
__owur int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d,
                                size_t cnt) {
	dump_func_name();
    dump_hex((const uint8_t*)d, cnt, NULL);
    return _ctx.EVP_DigestUpdate(ctx, d, cnt);
}
__owur int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md,
                                  unsigned int *s) {
    dump_func_name();
	int ret = _ctx.EVP_DigestFinal_ex(ctx, md, s);
    dump_hex(md, *s, NULL);
    return ret;
}
__owur int EVP_Digest(const void *data, size_t count,
                          unsigned char *md, unsigned int *size,
                          const EVP_MD *type, ENGINE *impl) {
    dump_func_name();
	dump_hex((const char*)data, STRLEN(data), "data");
    int ret = _ctx.EVP_Digest(data, count, md, size, type, impl);
    dump_hex(md, *size, "md");
    return ret;
}

__owur int EVP_MD_CTX_copy(EVP_MD_CTX *out, const EVP_MD_CTX *in) {
    dump_func_name();
	return _ctx.EVP_MD_CTX_copy(out, in);
}
__owur int EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type) {
    dump_func_name();
	return _ctx.EVP_DigestInit(ctx, type);
}
__owur int EVP_DigestFinal(EVP_MD_CTX *ctx, unsigned char *md,
                           unsigned int *s) {
    dump_func_name();
	int ret = _ctx.EVP_DigestFinal(ctx, md, s);
    dump_hex(md, *s, NULL);
    return ret;
}


__owur int EVP_EncryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                           const unsigned char *key, const unsigned char *iv) {
    dump_func_name();
	dump_hex(key, STRLEN(key), "key");
    dump_hex(iv, STRLEN(iv), "iv");
    return _ctx.EVP_EncryptInit(ctx, cipher, key, iv);
}
/*__owur*/ int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx,
                                  const EVP_CIPHER *cipher, ENGINE *impl,
                                  const unsigned char *key,
                                  const unsigned char *iv) {
    dump_func_name();
	dump_hex(key, STRLEN(key), "key");
    dump_hex(iv, STRLEN(iv), "iv");
    return _ctx.EVP_EncryptInit_ex(ctx, cipher, impl, key, iv);
}
/*__owur*/ int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                 int *outl, const unsigned char *in, int inl) {
    dump_func_name();
	dump_hex(in, inl, "in");
    return _ctx.EVP_EncryptUpdate(ctx, out, outl, in, inl);
}
/*__owur*/ int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                   int *outl) {
    dump_func_name();
	int ret = _ctx.EVP_EncryptFinal_ex(ctx, out, outl);
    dump_hex(out, *outl, "out");
    return ret;
}
/*__owur*/ int EVP_EncryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                int *outl) {
    dump_func_name();
	int ret = _ctx.EVP_EncryptFinal(ctx, out, outl);
    dump_hex(out, *outl, "out");
    return ret;
}

__owur int EVP_DecryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                           const unsigned char *key, const unsigned char *iv) {
    dump_func_name();
	dump_hex(key, STRLEN(key), "key");
    dump_hex(iv, STRLEN(iv), "iv");
    return _ctx.EVP_DecryptInit(ctx, cipher, key, iv);
}
/*__owur*/ int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx,
                                  const EVP_CIPHER *cipher, ENGINE *impl,
                                  const unsigned char *key,
                                  const unsigned char *iv) {
    dump_func_name();
	dump_hex(key, STRLEN(key), "key");
    dump_hex(iv, STRLEN(iv), "iv");
    return _ctx.EVP_DecryptInit_ex(ctx, cipher, impl, key, iv);
}
/*__owur*/ int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                 int *outl, const unsigned char *in, int inl) {
    dump_func_name();
	dump_hex(in, inl, "in");
    return _ctx.EVP_DecryptUpdate(ctx, out, outl, in, inl);
}
__owur int EVP_DecryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm,
                            int *outl) {
    dump_func_name();
	int ret = _ctx.EVP_DecryptFinal(ctx, outm, outl);
    dump_hex(outm, *outl, "outm");
    return ret;
}
/*__owur*/ int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm,
                                   int *outl) {
    dump_func_name();
	int ret = _ctx.EVP_DecryptFinal_ex(ctx, outm, outl);
    dump_hex(outm, *outl, "outm");
    return ret;
}

__owur int EVP_CipherInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                          const unsigned char *key, const unsigned char *iv,
                          int enc) {
    dump_func_name();
	dump((const uint8_t *)(enc ? "Encrypt": "Decrypt"), NULL);
    dump_hex(key, STRLEN(key), "key");
    dump_hex(iv, STRLEN(iv), "iv");
    return _ctx.EVP_CipherInit(ctx, cipher, key, iv, enc);
}
/*__owur*/ int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx,
                                 const EVP_CIPHER *cipher, ENGINE *impl,
                                 const unsigned char *key,
                                 const unsigned char *iv, int enc) {
    dump_func_name();
	dump((const uint8_t *)(enc ? "Encrypt": "Decrypt"), NULL);
    dump_hex(key, STRLEN(key), "key");
    dump_hex(iv, STRLEN(iv), "iv");
    return _ctx.EVP_CipherInit_ex(ctx, cipher, impl, key, iv, enc);
}
__owur int EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                            int *outl, const unsigned char *in, int inl) {
    dump_func_name();
	dump_hex(in, inl, "in");
    return _ctx.EVP_CipherUpdate(ctx, out, outl, in, inl);
}
__owur int EVP_CipherFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm,
                           int *outl) {
    dump_func_name();
	int ret = _ctx.EVP_CipherFinal(ctx, outm, outl);
    dump_hex(outm, *outl, "outm");
    return ret;
}
__owur int EVP_CipherFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm,
                              int *outl) {
    dump_func_name();
	int ret = _ctx.EVP_CipherFinal_ex(ctx, outm, outl);
    dump_hex(outm, *outl, "outm");
    return ret;
}

__owur int EVP_SignFinal(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s,
                         EVP_PKEY *pkey) {
    dump_func_name();
	int ret = _ctx.EVP_SignFinal(ctx, md, s, pkey);
    dump_hex(md, *s, NULL);
    return ret;
}

__owur int EVP_VerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sigbuf,
                           unsigned int siglen, EVP_PKEY *pkey) {
    dump_func_name();
	dump_hex(sigbuf, siglen, NULL);
    return _ctx.EVP_VerifyFinal(ctx, sigbuf, siglen, pkey);
}

/*__owur*/ int EVP_DigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
                                  const EVP_MD *type, ENGINE *e,
                                  EVP_PKEY *pkey) {
    dump_func_name();
	return _ctx.EVP_DigestSignInit(ctx, pctx, type, e, pkey);
}
__owur int EVP_DigestSignFinal(EVP_MD_CTX *ctx, unsigned char *sigret,
                               size_t *siglen) {
    dump_func_name();
	int ret = _ctx.EVP_DigestSignFinal(ctx, sigret, siglen);
    dump_hex(sigret, *siglen, NULL);
    return ret;
}

__owur int EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
                                const EVP_MD *type, ENGINE *e,
                                EVP_PKEY *pkey) {
    dump_func_name();
	return _ctx.EVP_DigestVerifyInit(ctx, pctx, type, e, pkey);
}

__owur int EVP_DigestVerifyFinal(EVP_MD_CTX *ctx,
                        unsigned char *sig, size_t siglen) {
    dump_func_name();
	dump_hex(sig, siglen, NULL);
    return _ctx.EVP_DigestVerifyFinal(ctx, sig, siglen);
}

/* ================================ */
/* debug func */

static void __dump(const uint8_t *buf, const char *func_name, const char *tag) {
    char obuf[256] = {0};
    sprintf(obuf, "[HOOK][%4x][%6s][%7s] %s\n", session_id, func_name, tag, buf);
    write(_ctx.logfd, obuf, strlen(obuf));
}

static void __dump_hex(const uint8_t *buf, int len, const char *func_name, const char *tag) {
    int i = 0;
    char obuf[256] = {0};
    sprintf(obuf, "[HOOK][%4x][%6s][%7s] ", session_id, func_name, tag);
    write(_ctx.logfd, obuf, strlen(obuf));
    for (; i < len; i++) {
        sprintf((char *)obuf, "%02x", buf[i]);
        obuf[3] = 0;
        write(_ctx.logfd, obuf, 2);
    }
    write(_ctx.logfd, "\n", 1);
}

void * malloc2(size_t len) {
	return NULL;
}
