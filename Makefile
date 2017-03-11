CC = gcc
TARGET = libpcap.so
FLAGS = -c -fPIC
LIBS = -ltrace

all:
	$(CC) $(FLAGS) fkpcap.c
	$(CC) -shared -o $(TARGET) fkpcap.o $(LIBS)

clean: 
	rm -f *.o *.so
		
