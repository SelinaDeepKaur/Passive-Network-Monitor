CC = g++
SOURCE= src/mydump.cpp
OUTPUT= bin/mydump
LIB= -lpcap

all:
	$(CC) $(SOURCE) -o $(OUTPUT) $(LIB)
clean:
	rm -vf $(OUTPUT)
