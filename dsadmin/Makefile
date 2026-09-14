.PHONY: clean install uninstall

CC = g++

CFLAGS = -Wall -c -O2 -std=c++17
CPPFLAGS = -Wall -c -O2 -std=c++17
LDFLAGS = `fox-config --libs`

PREFIX = /usr/local

ICONS = res/*/*.gif res/*/*.png res/*.gif
SOURCES = dsadmin.cpp
OBJECTS = $(SOURCES:.cpp=.o)
EXECUTABLE = dsadmin

CPPFLAGS += `fox-config --cflags`

all: $(EXECUTABLE)

$(OBJECTS): res/foxres.h

res/foxres.h: $(ICONS)
	reswrap -s -p resico_ -z -d -o res/foxres.h $(ICONS)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

clean:
	rm -f res/foxres.h $(OBJECTS) $(EXECUTABLE)

install:
	cp $(EXECUTABLE) $(PREFIX)/bin/$(EXECUTABLE)

uninstall:
	rm -f $(PREFIX)/bin/$(EXECUTABLE)
