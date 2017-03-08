CC = gcc
TARGET = libpcap.so
FLAGS = -c -fPIC

all:
	$(CC) $(FLAGS) fkpcap.c
	$(CC) -shared -o $(TARGET) fkpcap.o

clean: 
	rm -f *.o *.so
		
