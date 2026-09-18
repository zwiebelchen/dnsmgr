# Sicherheitsrichtlinien-Konsolen. Gleiche Quelle wie dsadmin -- das
# Fenster ist dasselbe, nur auf den Zweig "Sicherheitseinstellungen" eines
# festen Gruppenrichtlinienobjekts beschraenkt (SECPOL_BUILD waehlt den
# passenden Einstiegspunkt in dsadmin.cpp).
.PHONY: clean install uninstall

CC = g++

CPPFLAGS = -Wall -c -O2 -std=c++17 -DSECPOL_BUILD -I../dsadmin
LDFLAGS = `fox-config --libs`

PREFIX = /usr/local

SOURCES = ../dsadmin/dsadmin.cpp ../dsadmin/admparser.cpp ../dsadmin/regpol.cpp ../dsadmin/aas.cpp \
          ../common/svc/svccore.cpp ../common/svc/svcpanel.cpp
OBJECTS = $(notdir $(SOURCES:.cpp=.o))
DEPS = $(OBJECTS:.o=.d)
DEPFLAGS = -MMD -MP
EXECUTABLE = secpol

CPPFLAGS += `fox-config --cflags`
CPPFLAGS += $(DEPFLAGS)

vpath %.cpp ../dsadmin ../common/svc

all: $(EXECUTABLE)

# Eigene Objektdateien, damit sich die Programme nicht in die Quere kommen
# (dsadmin baut dieselben Quellen ohne SECPOL_BUILD).
%.o: %.cpp ../dsadmin/res/foxres.h Makefile
	$(CC) $(CPPFLAGS) -o $@ $<

../dsadmin/res/foxres.h:
	$(MAKE) -C ../dsadmin res/foxres.h

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

clean:
	rm -f $(OBJECTS) $(DEPS) $(EXECUTABLE)

install:
	cp $(EXECUTABLE) $(PREFIX)/bin/$(EXECUTABLE)

uninstall:
	rm -f $(PREFIX)/bin/$(EXECUTABLE)

-include $(DEPS)
