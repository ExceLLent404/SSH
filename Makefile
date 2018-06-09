.PHONY: all clean

CC = gcc
CFLAGS = -c -Wall -pedantic
TARGET = ssh

all: $(TARGET)

$(TARGET): main.o sha1.o dh.o rsa.o
	$(CC) $^ -o $(TARGET) -lgmp

main.o: source/main.c
	$(CC) $(CFLAGS) $< -o $@

sha1.o: source/sha1.c
	$(CC) $(CFLAGS) $< -o $@

dh.o: source/dh.c
	$(CC) $(CFLAGS) $< -o $@

rsa.o: source/rsa.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf *.o $(TARGET)