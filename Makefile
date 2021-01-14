SRC=openssl_hook.c
OUT=libhook.so
CFLAGS=-Wall
LDFLGAS=-shared -fPIC -lssl -lcrypto -lc -ldl
CC=gcc
all:
	$(CC) $(SRC) $(CFLAGS) $(LDFLGAS) -o $(OUT)
