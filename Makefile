CC    = gcc
CFLAGS       = -I include/
DEBUGFLAGS   = -O0 -D _DEBUG -DDEBUG
RELEASEFLAGS = -O3 -D NDEBUG -combine -fwhole-program

TARGET  = libskylogin.so
SOURCES = src/common.c src/crc.c src/login.c src/objects.c src/platform_unix.c src/random.c src/skylogin.c src/uic.c
LDFLAGS = -shared -pipe `pkg-config --cflags --libs openssl`
OBJECTS = $(SOURCES:.c=.o)

PREFIX = $(DESTDIR)/usr/local
BINDIR = $(PREFIX)/bin

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(RELEASEFLAGS) -o $(TARGET) $(OBJECTS)

debug: $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(DEBUGFLAGS) -o $(TARGET) $(OBJECTS)

clean:
	rm -f $(TARGET) src/*.o

