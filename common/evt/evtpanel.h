// evtpanel.h -- Ereignisliste als FOX-Widget.
//
// Zeigt ein Protokoll (Anwendung, Sicherheit, System) mit den Spalten des
// Originals, oeffnet die Ereigniseigenschaften und kennt den Filter.
// Wird von eventvwr (eigenes Fenster) und compmgmt (Zweig
// "Systemprogramme") verwendet.
#pragma once

#include <fx.h>
#include <FXPNGIcon.h>
#include <vector>
#include "../evt/evtcore.h"

struct EventFilter {
	bool showInfo = true, showWarning = true, showError = true;
	std::string source;   // Teilstring der Quelle
	int maxEntries = 500;
};

class EvtPanel : public FXVerticalFrame {
	FXDECLARE(EvtPanel)
private:
	FXIconList* list;
	FXIcon *icoInfo, *icoWarning, *icoError;
	std::vector<evt::EventEntry> allEvents, shown;
	EventFilter filter;
	evt::LogKind current;
	bool fromJournal;
protected:
	EvtPanel() : list(NULL), icoInfo(NULL), icoWarning(NULL), icoError(NULL), current(evt::LOG_APPLICATION), fromJournal(true) {}
public:
	enum { ID_LIST = FXVerticalFrame::ID_LAST, ID_LAST };

	EvtPanel(FXComposite* p, FXuint opts = LAYOUT_FILL_X | LAYOUT_FILL_Y);
	long onListDouble(FXObject*, FXSelector, void*);

	void reload();                       // Ereignisse neu einlesen
	void showLog(evt::LogKind kind);     // Protokoll waehlen
	void openProperties();               // Eigenschaften des markierten Ereignisses
	bool editFilter(FXWindow* owner);    // Filterdialog; true = neu eingelesen
	void clearLog(FXWindow* owner);      // "Alle Ereignisse loeschen"
	FXString statusText() const;         // Text fuer die Statuszeile
	bool journalUsed() const { return fromJournal; }
	virtual ~EvtPanel() {}
};
