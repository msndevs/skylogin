CC    = gcc
CFLAGS       = -I ../include/ -O3 -D NDEBUG
DEBUGFLAGS   = -I ../include/ -O0 -D _DEBUG -DDEBUG -g

TARGET  = test
SOURCES = test.c
LDFLAGS = -lskylogin -L..
OBJECTS = $(SOURCES:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJECTS) $(LDFLAGS)

debug: CFLAGS := $(DEBUGFLAGS)
debug: $(TARGET)

clean:
	rm -f $(TARGET) *.o

.PHONY: all debug clean
