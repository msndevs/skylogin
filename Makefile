CC    = gcc
CFLAGS       = -I include/ -fPIC -O3 -D NDEBUG
DEBUGFLAGS   = -I include/ -fPIC -O0 -D _DEBUG -DDEBUG -g

TARGET  = libskylogin.so
SOURCES = src/common.c src/crc.c src/login.c src/objects.c src/platform_unix.c src/random.c src/skylogin.c src/uic.c
LDFLAGS = -shared `pkg-config --cflags --libs openssl`
OBJECTS = $(SOURCES:.c=.o)

PREFIX = $(DESTDIR)/usr/local
BINDIR = $(PREFIX)/bin

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) $(OBJECTS)

debug: CFLAGS := $(DEBUGFLAGS)
debug: $(TARGET)

clean:
	rm -f $(TARGET) src/*.o
	make -C test clean

.PHONY: all debug clean
