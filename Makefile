# CFLAGS = -O3 -Wall -fprofile-generate / -fprofile-use
CFLAGS = -Wall -O2 -ggdb -g

INCLUDE = -Isrc/

MODULES = src/expand_aff.c mmap_wrapper.o hash.o list.o

TARGET = expand_aff

all: $(TARGET)

clean:
	rm -f *.o
	rm -f src/*~
	rm -f $(TARGET)

mmap_wrapper.o: src/mmap_wrapper.c
	$(CC) $(CFLAGS) $(INCLUDE) -c src/mmap_wrapper.c

hash.o: src/hash.c
	$(CC) $(CFLAGS) $(INCLUDE) -c src/hash.c

list.o: src/list.c
	$(CC) $(CFLAGS) $(INCLUDE) -c src/list.c

$(TARGET): $(MODULES)
	$(CC) $(CFLAGS) $(INCLUDE) $(MODULES) -o $(TARGET) $(LIBS)
