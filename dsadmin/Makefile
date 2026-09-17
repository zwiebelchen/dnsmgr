.PHONY: clean install uninstall

CC = g++

CFLAGS = -Wall -c -O2 -std=c++17
CPPFLAGS = -Wall -c -O2 -std=c++17
LDFLAGS = `fox-config --libs`

PREFIX = /usr/local

ICONS = res/*/*.gif res/*/*.png res/*.gif
SOURCES = dsadmin.cpp admparser.cpp regpol.cpp aas.cpp ../common/svc/svccore.cpp ../common/svc/svcpanel.cpp
OBJECTS = $(SOURCES:.cpp=.o)
DEPS = $(OBJECTS:.o=.d)

# Header-Abhaengigkeiten automatisch: der Compiler schreibt zu jeder .o eine
# .d mit allen eingebundenen Headern. Ohne das baut make eine .o nach einer
# Header-Aenderung nicht neu -- z.B. compmgmt.o nach der Aenderung des
# SvcPanel-Konstruktors in ../common/svc/svcpanel.h ("undefined reference").
DEPFLAGS = -MMD -MP
EXECUTABLE = dsadmin

CPPFLAGS += `fox-config --cflags`
CPPFLAGS += $(DEPFLAGS)

all: $(EXECUTABLE)

# Makefile: geaenderte Flags (und der erste Build mit -MMD, zu dem es noch
# keine .d gibt) bauen alles neu.
$(OBJECTS): res/foxres.h Makefile

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
	rm -f res/foxres.h $(OBJECTS) $(DEPS) $(EXECUTABLE) test_admparser test_admenc test_regpol test_aas test_aas_struct

install:
	cp $(EXECUTABLE) $(PREFIX)/bin/$(EXECUTABLE)

uninstall:
	rm -f $(PREFIX)/bin/$(EXECUTABLE)

-include $(DEPS)
