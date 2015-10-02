CC    = gcc
CFLAGS       = -I include/ -fPIC -O3 -D NDEBUG
DEBUGFLAGS   = -I include/ -fPIC -O0 -D _DEBUG -DDEBUG -g -Wall

TARGET  = libskylogin.so
SSLLIB  = openssl
SOURCES = src/common.c src/crc.c src/login.c src/objects.c src/platform_unix.c src/random.c src/skylogin.c src/uic.c src/credentials.c
LDFLAGS = -shared `pkg-config --cflags --libs $(SSLLIB)`
OBJECTS = $(SOURCES:.c=.o)

PREFIX = $(DESTDIR)/usr/local
BINDIR = $(PREFIX)/bin

all: $(TARGET)
	make -C test

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJECTS) $(LDFLAGS)

debug: CFLAGS := $(DEBUGFLAGS)
debug: $(TARGET)
	make -C test debug

wolfssl: SSLLIB := wolfssl
wolfssl: CFLAGS := $(CFLAGS) -DCRYPT_WOLFSSL
wolfssl: $(TARGET)


clean:
	rm -f $(TARGET) src/*.o
	make -C test clean

.PHONY: all debug clean
