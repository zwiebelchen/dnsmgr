.PHONY: clean install uninstall

CC = g++

CFLAGS = -Wall -c -O2 -std=c++17
CPPFLAGS = -Wall -c -O2 -std=c++17
LDFLAGS = `fox-config --libs`

PREFIX = /usr/local

ICONS = res/*/*.gif res/*/*.png res/*.gif
SOURCES = dsadmin.cpp admparser.cpp regpol.cpp aas.cpp
OBJECTS = $(SOURCES:.cpp=.o)
EXECUTABLE = dsadmin

CPPFLAGS += `fox-config --cflags`

all: $(EXECUTABLE)

$(OBJECTS): res/foxres.h

res/foxres.h: $(ICONS)
	reswrap -s -p resico_ -z -d -o res/foxres.h $(ICONS)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

test_aas_struct: test_aas_struct.cpp aas.cpp aas.h
	$(CC) -Wall -std=c++17 -o test_aas_struct test_aas_struct.cpp aas.cpp

test_admenc: test_admenc.cpp admparser.cpp admparser.h
	$(CC) -Wall -std=c++17 -o test_admenc test_admenc.cpp admparser.cpp

test_admparser: test_admparser.cpp admparser.cpp
	$(CC) -Wall -std=c++17 -o test_admparser test_admparser.cpp admparser.cpp

test_regpol: test_regpol.cpp regpol.cpp
	$(CC) -Wall -std=c++17 -o test_regpol test_regpol.cpp regpol.cpp

test_aas: test_aas.cpp aas.cpp
	$(CC) -Wall -std=c++17 -o test_aas test_aas.cpp aas.cpp

clean:
	rm -f res/foxres.h $(OBJECTS) $(EXECUTABLE) test_admparser test_admenc test_regpol test_aas test_aas_struct

install:
	cp $(EXECUTABLE) $(PREFIX)/bin/$(EXECUTABLE)

uninstall:
	rm -f $(PREFIX)/bin/$(EXECUTABLE)
