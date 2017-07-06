CC=gcc
CFLAGS=-g -w
LDFLAGS=-lrt -lpthread
SRC=delay.c
OBJECTS=$(SRC:.c=.o)
EXECUTABLE=wansim

all: $(SRC) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(EXECUTABLE) $(LDFLAGS)

.c.o:
	$(CC) -c $(CFLAGS) $<

clean:
	rm *.o wansim
