// svcpanel.h
//
// Die komplette Dienste-Ansicht als einhaengbares FOX-Widget: Liste im
// MMC-Look, Kontextmenue und der vierteilige Eigenschaften-Dialog.
// Beide Programme -- das eigenstaendige "Dienste" und der Zweig
// "Dienste und Anwendungen" der Computerverwaltung -- benutzen genau
// diese Klasse, es gibt also keine zweite Umsetzung.
//
// Bewusst ohne Bezug auf res/foxres.h: die Icons kommen vom Aufrufer,
// damit das Widget nicht an die Ressourcen eines bestimmten Programms
// gebunden ist.

#ifndef SVCPANEL_H
#define SVCPANEL_H

#include <fx.h>
#include <vector>
#include "svccore.h"

// Wer die Dienstliste fuer etwas anderes als die lokale Verwaltung
// braucht -- etwa die Gruppenrichtlinie ("Systemdienste") --, haengt
// sich hier ein: eigene Spalten, eigener Zeileninhalt, eigene Aktion bei
// Doppelklick bzw. "Eigenschaften". Starten/Beenden entfaellt dann.
class SvcPanelDelegate {
public:
	virtual ~SvcPanelDelegate() {}
	virtual std::vector<std::pair<FXString, FXint> > svcColumns() = 0;
	virtual FXString svcRowText(const svc::ServiceInfo& info) = 0;
	virtual void svcActivate(FXWindow* owner, const svc::ServiceInfo& info) = 0;
};

class SvcPanel : public FXVerticalFrame {
	FXDECLARE(SvcPanel)
private:
	FXIconList* list;
	FXIcon* icoService;
	SvcPanelDelegate* delegate;
	std::vector<svc::ServiceInfo> services;
protected:
	SvcPanel() : list(NULL), icoService(NULL), delegate(NULL) {}
public:
	enum {
		ID_LIST = FXVerticalFrame::ID_LAST,
		ID_START, ID_STOP, ID_RESTART, ID_PROPERTIES, ID_REFRESH,
		ID_LAST
	};

	// delegate: optional, siehe SvcPanelDelegate. Ohne Delegate verhaelt
	// sich das Panel wie in "Dienste".
	SvcPanel(FXComposite* parent, FXIcon* serviceIcon, SvcPanelDelegate* delegate = NULL, FXuint opts = 0);

	// Liste neu einlesen -- liest jedes Mal alle installierten Dienste
	// aus; behaelt die Markierung nach Moeglichkeit bei.
	void reload();

	// Zeilen neu beschriften, ohne systemd erneut zu fragen (z.B. nachdem
	// der Delegate eigene Daten geaendert hat).
	void relabel();

	// Vom Host (Toolbar/Menue) aufrufbar.
	void startSelected();
	void stopSelected();
	void restartSelected();
	void propertiesForSelected();
	bool hasSelection() const;

	long onListDoubleClick(FXObject*, FXSelector, void*);
	long onListRightClick(FXObject*, FXSelector, void*);
	long onStart(FXObject*, FXSelector, void*);
	long onStop(FXObject*, FXSelector, void*);
	long onRestart(FXObject*, FXSelector, void*);
	long onProperties(FXObject*, FXSelector, void*);
	long onRefresh(FXObject*, FXSelector, void*);

	virtual ~SvcPanel() {}
};

#endif
