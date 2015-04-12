CC    = gcc
CFLAGS       = -I ../include/
DEBUGFLAGS   = -O0 -D _DEBUG -DDEBUG
RELEASEFLAGS = -O3 -D NDEBUG -combine -fwhole-program

TARGET  = test
SOURCES = test.c
LDFLAGS = -lskylogin -L..
OBJECTS = $(SOURCES:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(RELEASEFLAGS) -o $(TARGET) $(OBJECTS)

debug: $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(DEBUGFLAGS) -o $(TARGET) $(OBJECTS)

clean:
	rm -f $(TARGET) *.o
