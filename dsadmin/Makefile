.PHONY: clean install uninstall

CC = g++

CFLAGS = -Wall -c -O2 -std=c++17
CPPFLAGS = -Wall -c -O2 -std=c++17
LDFLAGS = `fox-config --libs`

PREFIX = /usr/local

ICONS = res/*/*.gif res/*/*.png res/*.gif
SOURCES = dsadmin.cpp admparser.cpp
OBJECTS = $(SOURCES:.cpp=.o)
EXECUTABLE = dsadmin

CPPFLAGS += `fox-config --cflags`

all: $(EXECUTABLE)

$(OBJECTS): res/foxres.h

res/foxres.h: $(ICONS)
	reswrap -s -p resico_ -z -d -o res/foxres.h $(ICONS)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

test_admparser: test_admparser.cpp admparser.cpp
	$(CC) -Wall -std=c++17 -o test_admparser test_admparser.cpp admparser.cpp

clean:
	rm -f res/foxres.h $(OBJECTS) $(EXECUTABLE) test_admparser

install:
	cp $(EXECUTABLE) $(PREFIX)/bin/$(EXECUTABLE)

uninstall:
	rm -f $(PREFIX)/bin/$(EXECUTABLE)
