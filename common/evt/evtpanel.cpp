// evtpanel.cpp -- siehe evtpanel.h
#include "evtpanel.h"

#include <algorithm>
#include <cstdlib>

using evt::EventEntry;
using evt::LogKind;

// Symbole fuer Fehler, Warnung und Informationen (eigene Nachbauten).
#include "evticons.h"

static std::string trimStr(const std::string& x) {
	size_t a = x.find_first_not_of(" \t\r\n");
	if (a == std::string::npos) return "";
	size_t b = x.find_last_not_of(" \t\r\n");
	return x.substr(a, b - a + 1);
}

// ---------------------------------------------------------------------
// Dialog "Ereigniseigenschaften" -- Aufbau wie im Original, mit den
// Pfeiltasten zum Blaettern und "Kopieren".
// ---------------------------------------------------------------------
class EventPropertiesDialog : public FXDialogBox {
	FXDECLARE(EventPropertiesDialog)
private:
	const std::vector<evt::EventEntry>* events = nullptr;
	int index = 0;
	FXLabel *dateL = nullptr, *timeL = nullptr, *typeL = nullptr, *userL = nullptr,
	        *computerL = nullptr, *sourceL = nullptr, *catL = nullptr, *idL = nullptr;
	FXText* description = nullptr;
protected:
	EventPropertiesDialog() {}
public:
	enum { ID_PREV = FXDialogBox::ID_LAST, ID_NEXT, ID_COPY };
	EventPropertiesDialog(FXWindow* owner, const std::vector<evt::EventEntry>& events_, int index_)
		: FXDialogBox(owner, "Ereigniseigenschaften", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE | DECOR_RESIZE, 0,0,520,420),
		  events(&events_), index(index_) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 12,12,12,12, 0,6);
		FXHorizontalFrame* top = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 20,0);
		FXMatrix* left = new FXMatrix(top, 2, MATRIX_BY_COLUMNS | LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 10,3);
		auto row = [&](FXComposite* p, const char* label) {
			new FXLabel(p, label, NULL, JUSTIFY_LEFT);
			return new FXLabel(p, "", NULL, JUSTIFY_LEFT);
		};
		dateL = row(left, "Datum:");
		timeL = row(left, "Zeit:");
		typeL = row(left, "Typ:");
		userL = row(left, "Benutzer:");
		computerL = row(left, "Computer:");
		FXMatrix* right = new FXMatrix(top, 2, MATRIX_BY_COLUMNS | LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 10,3);
		sourceL = row(right, "Quelle:");
		catL = row(right, "Kategorie:");
		idL = row(right, "Ereigniskennung:");

		// Rechts daneben die Pfeiltasten wie im Original.
		FXVerticalFrame* buttons = new FXVerticalFrame(top, LAYOUT_TOP, 0,0,0,0, 0,0,0,0, 0,2);
		new FXArrowButton(buttons, this, ID_PREV, ARROW_UP | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH | LAYOUT_FIX_HEIGHT, 0,0,26,22);
		new FXArrowButton(buttons, this, ID_NEXT, ARROW_DOWN | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH | LAYOUT_FIX_HEIGHT, 0,0,26,22);
		new FXButton(buttons, "&Kopieren", NULL, this, ID_COPY, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 6,6,3,3);

		new FXLabel(main, "&Beschreibung:", NULL, JUSTIFY_LEFT);
		FXPacker* df = new FXPacker(main, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0);
		description = new FXText(df, NULL, 0, TEXT_READONLY | TEXT_WORDWRAP | LAYOUT_FILL_X | LAYOUT_FILL_Y);

		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 6,0);
		new FXFrame(btnf, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		new FXButton(btnf, "OK", NULL, this, FXDialogBox::ID_ACCEPT, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
		show();
	}
	void show() {
		if (index < 0 || index >= (int)events->size()) return;
		const evt::EventEntry& e = (*events)[index];
		dateL->setText(evt::formatDate(e.when).c_str());
		timeL->setText(evt::formatTime(e.when).c_str());
		typeL->setText(evt::typeName(e.type));
		userL->setText(e.user.empty() ? "Nicht zutreffend" : FXString(e.user.c_str()));
		computerL->setText(e.computer.c_str());
		sourceL->setText(e.source.empty() ? "Unbekannt" : FXString(e.source.c_str()));
		catL->setText("Keine");
		idL->setText(e.eventId.empty() ? "-" : FXString(e.eventId.c_str()));
		description->setText(e.message.c_str());
	}
	long onPrev(FXObject*, FXSelector, void*) { if (index > 0) { index--; show(); } return 1; }
	long onNext(FXObject*, FXSelector, void*) { if (index + 1 < (int)events->size()) { index++; show(); } return 1; }
	long onCopy(FXObject*, FXSelector, void*) {
		const evt::EventEntry& e = (*events)[index];
		FXString text = FXString("Ereignistyp:\t") + evt::typeName(e.type) + "\nEreignisquelle:\t" + e.source.c_str() +
		                "\nDatum:\t\t" + FXString(evt::formatDate(e.when).c_str()) + "\nZeit:\t\t" + FXString(evt::formatTime(e.when).c_str()) +
		                "\nBenutzer:\t" + (e.user.empty() ? "Nicht zutreffend" : FXString(e.user.c_str())) +
		                "\nComputer:\t" + e.computer.c_str() + "\nBeschreibung:\n" + e.message.c_str() + "\n";
		FXDragType types[1] = { FXWindow::stringType };
		if (acquireClipboard(types, 1)) clipped = text;
		return 1;
	}
	long onClipboardRequest(FXObject* sender, FXSelector sel, void* ptr) {
		FXEvent* event = (FXEvent*)ptr;
		if (event->target == FXWindow::stringType) {
			setDNDData(FROM_CLIPBOARD, FXWindow::stringType, clipped);
			return 1;
		}
		return FXDialogBox::onClipboardRequest(sender, sel, ptr);
	}
	FXString clipped;
	virtual ~EventPropertiesDialog() {}
};
FXDEFMAP(EventPropertiesDialog) EventPropertiesDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, EventPropertiesDialog::ID_PREV, EventPropertiesDialog::onPrev),
	FXMAPFUNC(SEL_COMMAND, EventPropertiesDialog::ID_NEXT, EventPropertiesDialog::onNext),
	FXMAPFUNC(SEL_COMMAND, EventPropertiesDialog::ID_COPY, EventPropertiesDialog::onCopy),
	FXMAPFUNC(SEL_CLIPBOARD_REQUEST, 0, EventPropertiesDialog::onClipboardRequest),
};
FXIMPLEMENT(EventPropertiesDialog, FXDialogBox, EventPropertiesDialogMap, ARRAYNUMBER(EventPropertiesDialogMap))

// ---------------------------------------------------------------------
// Dialog "Filter" (im Original der Reiter "Filter" der
// Protokolleigenschaften).
// ---------------------------------------------------------------------
class FilterDialog : public FXDialogBox {
	FXDECLARE(FilterDialog)
private:
	FXCheckButton *info = nullptr, *warning = nullptr, *error = nullptr;
	FXTextField *source = nullptr, *maxEntries = nullptr;
protected:
	FilterDialog() {}
public:
	FilterDialog(FXWindow* owner, const EventFilter& f)
		: FXDialogBox(owner, "Filter", DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,400,0) {
		FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 12,12,12,12, 0,6);
		FXGroupBox* types = new FXGroupBox(main, "Ereignistypen", GROUPBOX_TITLE_LEFT | FRAME_GROOVE | LAYOUT_FILL_X, 0,0,0,0, 10,10,6,8, 0,2);
		info = new FXCheckButton(types, "&Informationen");
		warning = new FXCheckButton(types, "&Warnung");
		error = new FXCheckButton(types, "&Fehler");
		info->setCheck(f.showInfo);
		warning->setCheck(f.showWarning);
		error->setCheck(f.showError);
		auto row = [&](const char* label, const char* value) {
			FXHorizontalFrame* r = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
			new FXLabel(r, label, NULL, LAYOUT_CENTER_Y | LAYOUT_FIX_WIDTH | JUSTIFY_LEFT, 0,0,150,0);
			FXTextField* tf = new FXTextField(r, 16, NULL, 0, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X);
			tf->setText(value);
			return tf;
		};
		source = row("&Ereignisquelle:", f.source.c_str());
		maxEntries = row("&Anzahl der Ereignisse:", std::to_string(f.maxEntries).c_str());
		FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,8,0, 6,0);
		new FXFrame(btnf, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
		new FXButton(btnf, "OK", NULL, this, FXDialogBox::ID_ACCEPT, BUTTON_NORMAL | BUTTON_DEFAULT | BUTTON_INITIAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
		new FXButton(btnf, "Abbrechen", NULL, this, FXDialogBox::ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK | LAYOUT_FIX_WIDTH, 0,0,88,0, 4,4,3,3);
	}
	EventFilter filter() const {
		EventFilter f;
		f.showInfo = info->getCheck();
		f.showWarning = warning->getCheck();
		f.showError = error->getCheck();
		f.source = trimStr(source->getText().text());
		f.maxEntries = std::max(10, atoi(maxEntries->getText().text()));
		return f;
	}
	virtual ~FilterDialog() {}
};
FXIMPLEMENT(FilterDialog, FXDialogBox, NULL, 0)



// ---------------------------------------------------------------------
// EvtPanel
// ---------------------------------------------------------------------
FXDEFMAP(EvtPanel) EvtPanelMap[] = {
	FXMAPFUNC(SEL_DOUBLECLICKED, EvtPanel::ID_LIST, EvtPanel::onListDouble),
};
FXIMPLEMENT(EvtPanel, FXVerticalFrame, EvtPanelMap, ARRAYNUMBER(EvtPanelMap))

EvtPanel::EvtPanel(FXComposite* p, FXuint opts)
	: FXVerticalFrame(p, opts, 0,0,0,0, 0,0,0,0, 0,0),
	  current(evt::LOG_APPLICATION), fromJournal(true) {
	icoInfo = new FXPNGIcon(getApp(), evticon_info, IMAGE_NEAREST);
	icoWarning = new FXPNGIcon(getApp(), evticon_warning, IMAGE_NEAREST);
	icoError = new FXPNGIcon(getApp(), evticon_error, IMAGE_NEAREST);
	for (FXIcon* i : { icoInfo, icoWarning, icoError }) i->create();

	FXPacker* frame = new FXPacker(this, FRAME_SUNKEN | FRAME_THICK | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0);
	list = new FXIconList(frame, this, ID_LIST, ICONLIST_DETAILED | ICONLIST_BROWSESELECT | LAYOUT_FILL_X | LAYOUT_FILL_Y);
	// Spalten wie im Original.
	list->appendHeader("Typ", NULL, 100);
	list->appendHeader("Datum", NULL, 90);
	list->appendHeader("Zeit", NULL, 80);
	list->appendHeader("Quelle", NULL, 150);
	list->appendHeader("Kategorie", NULL, 80);
	list->appendHeader("Ereignis", NULL, 70);
	list->appendHeader("Benutzer", NULL, 90);
	list->appendHeader("Computer", NULL, 110);
}

void EvtPanel::reload() {
	getApp()->beginWaitCursor();
	allEvents = evt::readAllEvents(filter.maxEntries, fromJournal);
	getApp()->endWaitCursor();
	// Neueste zuerst, wie im Original.
	std::sort(allEvents.begin(), allEvents.end(),
	          [](const evt::EventEntry& a, const evt::EventEntry& b) { return a.when > b.when; });
	showLog(current);
}

void EvtPanel::showLog(evt::LogKind kind) {
	current = kind;
	shown.clear();
	list->clearItems();
	for (auto& e : allEvents) {
		if (e.log != kind) continue;
		if (e.type == evt::EVT_INFO && !filter.showInfo) continue;
		if (e.type == evt::EVT_WARNING && !filter.showWarning) continue;
		if (e.type == evt::EVT_ERROR && !filter.showError) continue;
		if (!filter.source.empty() && e.source.find(filter.source) == std::string::npos) continue;
		shown.push_back(e);
	}
	for (auto& e : shown) {
		FXIcon* ic = e.type == evt::EVT_ERROR ? icoError : e.type == evt::EVT_WARNING ? icoWarning : icoInfo;
		list->appendItem(FXString(evt::typeName(e.type)) + "\t" + evt::formatDate(e.when).c_str() + "\t" +
		                 evt::formatTime(e.when).c_str() + "\t" + e.source.c_str() + "\tKeine\t" +
		                 (e.eventId.empty() ? "-" : e.eventId.c_str()) + "\t" +
		                 (e.user.empty() ? "-" : e.user.c_str()) + "\t" + e.computer.c_str(), ic, ic);
	}
}

FXString EvtPanel::statusText() const {
	char buf[160];
	snprintf(buf, sizeof(buf), " %d Ereignis(se)%s", (int)shown.size(),
	         fromJournal ? "" : "  --  Quelle: Logdateien unter /var/log (kein Journal gefunden)");
	return buf;
}

long EvtPanel::onListDouble(FXObject*, FXSelector, void* ptr) {
	FXint idx = (FXint)(FXival)ptr;
	if (idx < 0 || idx >= (int)shown.size()) return 1;
	EventPropertiesDialog dlg(this, shown, idx);
	dlg.execute(PLACEMENT_OWNER);
	return 1;
}

void EvtPanel::openProperties() {
	int idx = list->getCurrentItem();
	if (idx < 0 || idx >= (int)shown.size()) return;
	EventPropertiesDialog dlg(this, shown, idx);
	dlg.execute(PLACEMENT_OWNER);
}

bool EvtPanel::editFilter(FXWindow* owner) {
	FilterDialog dlg(owner, filter);
	if (!dlg.execute(PLACEMENT_OWNER)) return false;
	int oldMax = filter.maxEntries;
	filter = dlg.filter();
	if (filter.maxEntries != oldMax) { reload(); return true; }
	showLog(current);
	return false;
}

// Das Original leert genau ein Protokoll. Journald kennt diese Trennung
// nicht -- deshalb wird das ganze Journal geleert, und die Rueckfrage
// sagt das auch.
void EvtPanel::clearLog(FXWindow* owner) {
	if (!fromJournal) {
		FXMessageBox::information(owner, MBOX_OK, "Ereignisanzeige",
			"Die Ereignisse stammen aus den Logdateien unter /var/log.\n\n"
			"Diese werden von logrotate verwaltet und hier nicht gelöscht.");
		return;
	}
	if (FXMessageBox::question(owner, MBOX_YES_NO, "Ereignisanzeige",
	        "Möchten Sie wirklich alle Ereignisse löschen?\n\n"
	        "Das systemd-Journal kennt die Trennung in Anwendung, Sicherheit und System\n"
	        "nicht: Es wird vollständig geleert, nicht nur das gewählte Protokoll.") != MBOX_CLICKED_YES)
		return;
	std::string out;
	if (!evt::clearJournal(out))
		FXMessageBox::error(owner, MBOX_OK, "Ereignisanzeige", "Das Journal konnte nicht geleert werden:\n\n%s", trimStr(out).c_str());
	reload();
}
