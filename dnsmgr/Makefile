.PHONY: clean install uninstall

CC = g++

CFLAGS = -Wall -c -O2
CPPFLAGS = -Wall -c -O2
LDFLAGS = `fox-config --libs`

PREFIX = /usr/local

ICONS = res/*/*.gif res/*/*.png res/*.gif
SOURCES = dnsmgr.cpp
OBJECTS = $(SOURCES:.cpp=.o)
DEPS = $(OBJECTS:.o=.d)

# Header-Abhaengigkeiten automatisch: der Compiler schreibt zu jeder .o eine
# .d mit allen eingebundenen Headern. Ohne das baut make eine .o nach einer
# Header-Aenderung nicht neu -- z.B. compmgmt.o nach der Aenderung des
# SvcPanel-Konstruktors in ../common/svc/svcpanel.h ("undefined reference").
DEPFLAGS = -MMD -MP
EXECUTABLE = dnsmgr

CPPFLAGS += `fox-config --cflags`
CPPFLAGS += $(DEPFLAGS)

all: $(EXECUTABLE)

# Makefile: geaenderte Flags (und der erste Build mit -MMD, zu dem es noch
# keine .d gibt) bauen alles neu.
$(OBJECTS): res/foxres.h Makefile

# Icons als C-Resourcen einbetten, genau wie bei devmgmt
res/foxres.h: $(ICONS)
	reswrap -s -p resico_ -z -d -o res/foxres.h $(ICONS)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

clean:
	rm -f res/foxres.h $(OBJECTS) $(DEPS) $(EXECUTABLE)

install:
	cp $(EXECUTABLE) $(PREFIX)/bin/$(EXECUTABLE)

uninstall:
	rm -f $(PREFIX)/bin/$(EXECUTABLE)

-include $(DEPS)
