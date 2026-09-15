// svcpanel.cpp -- siehe svcpanel.h

#include "svcpanel.h"
#include <cstdio>

using namespace svc;

// ---------------------------------------------------------------------
// Eigenschaften-Dialog -- vier Reiter wie im Original: Allgemein,
// Anmelden, Wiederherstellen, Abhaengigkeiten.
// ---------------------------------------------------------------------
class SvcPropsDialog : public FXDialogBox {
	FXDECLARE(SvcPropsDialog)
private:
	std::string unit;
	ServiceInfo info;
	RecoverySettings recovery;
	Dependencies deps;

	FXComboBox* startTypeCombo;
	FXLabel* statusLabel;
	FXButton *btnStart, *btnStop, *btnPause, *btnResume;

	FXRadioButton *rbSystem, *rbAccount;
	FXTextField* accountField;

	FXComboBox *recFirst, *recSecond, *recFurther;
	FXSpinner *resetDaysSpin, *restartSecsSpin;

protected:
	SvcPropsDialog() : startTypeCombo(NULL), statusLabel(NULL), btnStart(NULL), btnStop(NULL),
	                   btnPause(NULL), btnResume(NULL), rbSystem(NULL), rbAccount(NULL),
	                   accountField(NULL), recFirst(NULL), recSecond(NULL), recFurther(NULL),
	                   resetDaysSpin(NULL), restartSecsSpin(NULL) {}
public:
	enum { ID_START = FXDialogBox::ID_LAST, ID_STOP, ID_APPLY, ID_LOGON_CHOICE, ID_REC_FIRST };

	long onStart(FXObject*, FXSelector, void*);
	long onStop(FXObject*, FXSelector, void*);
	long onApply(FXObject*, FXSelector, void*);
	long onAccept(FXObject*, FXSelector, void*);
	long onLogonChoice(FXObject*, FXSelector, void*);
	long onRecFirstChanged(FXObject*, FXSelector, void*);

	SvcPropsDialog(FXWindow* owner, const std::string& unit_, const ServiceInfo& info_,
	               const RecoverySettings& rec_, const Dependencies& deps_);

	void refreshStatus();
	bool apply();
	virtual ~SvcPropsDialog() {}
};

FXDEFMAP(SvcPropsDialog) SvcPropsDialogMap[] = {
	FXMAPFUNC(SEL_COMMAND, SvcPropsDialog::ID_START, SvcPropsDialog::onStart),
	FXMAPFUNC(SEL_COMMAND, SvcPropsDialog::ID_STOP, SvcPropsDialog::onStop),
	FXMAPFUNC(SEL_COMMAND, SvcPropsDialog::ID_APPLY, SvcPropsDialog::onApply),
	FXMAPFUNC(SEL_COMMAND, SvcPropsDialog::ID_ACCEPT, SvcPropsDialog::onAccept),
	FXMAPFUNC(SEL_COMMAND, SvcPropsDialog::ID_LOGON_CHOICE, SvcPropsDialog::onLogonChoice),
	FXMAPFUNC(SEL_COMMAND, SvcPropsDialog::ID_REC_FIRST, SvcPropsDialog::onRecFirstChanged),
};
FXIMPLEMENT(SvcPropsDialog, FXDialogBox, SvcPropsDialogMap, ARRAYNUMBER(SvcPropsDialogMap))

static FXTextField* readOnlyField(FXComposite* p, const FXString& text) {
	FXTextField* f = new FXTextField(p, 40, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X | TEXTFIELD_READONLY);
	f->setText(text);
	f->setBackColor(p->getApp()->getBaseColor());
	return f;
}

SvcPropsDialog::SvcPropsDialog(FXWindow* owner, const std::string& unit_, const ServiceInfo& info_,
                               const RecoverySettings& rec_, const Dependencies& deps_)
	: FXDialogBox(owner, FXString("Eigenschaften von ") + info_.displayName().c_str() + " (Lokaler Computer)",
	              DECOR_TITLE | DECOR_BORDER | DECOR_CLOSE, 0,0,460,470),
	  unit(unit_), info(info_), recovery(rec_), deps(deps_) {

	FXVerticalFrame* main = new FXVerticalFrame(this, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 8,8,8,8);
	FXTabBook* tabs = new FXTabBook(main, NULL, 0, LAYOUT_FILL_X | LAYOUT_FILL_Y);

	// ---------------- Allgemein ----------------
	new FXTabItem(tabs, "Allgemein");
	FXVerticalFrame* gen = new FXVerticalFrame(tabs, FRAME_THICK | FRAME_RAISED | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10);
	FXMatrix* gm = new FXMatrix(gen, 2, MATRIX_BY_COLUMNS | LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 6,4);

	new FXLabel(gm, "Dienstname:");
	new FXLabel(gm, info.unit.c_str(), NULL, JUSTIFY_LEFT | LAYOUT_FILL_X);
	new FXLabel(gm, "Anzeigename:");
	readOnlyField(gm, info.displayName().c_str());
	new FXLabel(gm, "Beschreibung:");
	readOnlyField(gm, info.description.c_str());
	new FXLabel(gm, "Pfad zur EXE-Datei:");
	readOnlyField(gm, info.execStart.c_str());

	new FXLabel(gm, "Starttyp:");
	startTypeCombo = new FXComboBox(gm, 20, NULL, 0, COMBOBOX_STATIC | FRAME_SUNKEN | LAYOUT_FILL_X);
	startTypeCombo->appendItem("Automatisch");
	startTypeCombo->appendItem("Manuell");
	startTypeCombo->appendItem("Deaktiviert");
	startTypeCombo->setNumVisible(3);
	switch (info.startType()) {
		case START_AUTO: startTypeCombo->setCurrentItem(0); break;
		case START_DISABLED: startTypeCombo->setCurrentItem(2); break;
		default: startTypeCombo->setCurrentItem(1); break;
	}

	new FXHorizontalSeparator(gen, SEPARATOR_GROOVE | LAYOUT_FILL_X);
	FXHorizontalFrame* statusRow = new FXHorizontalFrame(gen, LAYOUT_FILL_X, 0,0,0,0, 0,0,6,6);
	new FXLabel(statusRow, "Dienststatus:");
	statusLabel = new FXLabel(statusRow, "", NULL, JUSTIFY_LEFT | LAYOUT_FILL_X);

	FXHorizontalFrame* actionRow = new FXHorizontalFrame(gen, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
	btnStart = new FXButton(actionRow, "&Starten", NULL, this, ID_START, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 12,12,4,4);
	btnStop = new FXButton(actionRow, "&Beenden", NULL, this, ID_STOP, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 12,12,4,4);
	btnPause = new FXButton(actionRow, "&Anhalten", NULL, NULL, 0, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 12,12,4,4);
	btnResume = new FXButton(actionRow, "&Fortsetzen", NULL, NULL, 0, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 12,12,4,4);
	// systemd kennt kein Anhalten/Fortsetzen -- die Schaltflaechen bleiben
	// wie im Original vorhanden, aber dauerhaft inaktiv.
	btnPause->disable();
	btnResume->disable();

	new FXLabel(gen, "Anhalten und Fortsetzen kennt systemd nicht; zum vorübergehenden\n"
	                 "Stoppen bitte \"Beenden\" verwenden.", NULL, JUSTIFY_LEFT | LAYOUT_FILL_X);

	// ---------------- Anmelden ----------------
	new FXTabItem(tabs, "Anmelden");
	FXVerticalFrame* log = new FXVerticalFrame(tabs, FRAME_THICK | FRAME_RAISED | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10);
	new FXLabel(log, "Anmelden als:");
	rbSystem = new FXRadioButton(log, "Lokales S&ystemkonto", this, ID_LOGON_CHOICE);
	rbAccount = new FXRadioButton(log, "Dieses &Konto:", this, ID_LOGON_CHOICE);

	FXHorizontalFrame* accRow = new FXHorizontalFrame(log, LAYOUT_FILL_X, 0,0,0,0, 20,0,0,0);
	accountField = new FXTextField(accRow, 24, NULL, 0, FRAME_SUNKEN | LAYOUT_FILL_X);

	bool custom = !(info.user.empty() || info.user == "root");
	rbSystem->setCheck(!custom);
	rbAccount->setCheck(custom);
	if (custom) accountField->setText(info.user.c_str());
	accountField->enable();
	if (!custom) accountField->disable();

	new FXHorizontalSeparator(log, SEPARATOR_GROOVE | LAYOUT_FILL_X);
	new FXLabel(log,
		"Das Konto muss auf dem System bereits existieren; es wird als\n"
		"User= in einer eigenen Erweiterungsdatei hinterlegt, die\n"
		"mitgelieferte Unit-Datei bleibt unverändert.\n\n"
		"Kennwort, Datenaustausch mit dem Desktop und Hardwareprofile\n"
		"haben unter Linux keine Entsprechung.",
		NULL, JUSTIFY_LEFT | LAYOUT_FILL_X);

	// ---------------- Wiederherstellen ----------------
	new FXTabItem(tabs, "Wiederherstellen");
	FXVerticalFrame* rec = new FXVerticalFrame(tabs, FRAME_THICK | FRAME_RAISED | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10);
	new FXLabel(rec, "Wählen Sie, was bei Dienstausfall durchgeführt werden soll.");

	FXMatrix* rm = new FXMatrix(rec, 2, MATRIX_BY_COLUMNS | LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0, 6,4);
	const char* recOptions[] = { "Keinen Vorgang durchführen", "Dienst neu starten" };

	new FXLabel(rm, "Erster Fehlschlag:");
	recFirst = new FXComboBox(rm, 24, this, ID_REC_FIRST, COMBOBOX_STATIC | FRAME_SUNKEN | LAYOUT_FILL_X);
	new FXLabel(rm, "Zweiter Fehlschlag:");
	recSecond = new FXComboBox(rm, 24, NULL, 0, COMBOBOX_STATIC | FRAME_SUNKEN | LAYOUT_FILL_X);
	new FXLabel(rm, "Weitere Fehlschläge:");
	recFurther = new FXComboBox(rm, 24, NULL, 0, COMBOBOX_STATIC | FRAME_SUNKEN | LAYOUT_FILL_X);

	FXComboBox* recBoxes[] = { recFirst, recSecond, recFurther };
	for (int i = 0; i < 3; i++) {
		for (int j = 0; j < 2; j++) recBoxes[i]->appendItem(recOptions[j]);
		recBoxes[i]->setNumVisible(2);
		recBoxes[i]->setCurrentItem(recovery.action == REC_RESTART ? 1 : 0);
	}
	// systemd hat nur EINE Regel pro Dienst, nicht drei Stufen -- die
	// beiden unteren Felder zeigen deshalb dasselbe und sind gesperrt.
	recSecond->disable();
	recFurther->disable();

	new FXLabel(rm, "Fehlerzähler nach");
	FXHorizontalFrame* resetRow = new FXHorizontalFrame(rm, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
	resetDaysSpin = new FXSpinner(resetRow, 6, NULL, 0, FRAME_SUNKEN | SPIN_NOMAX);
	resetDaysSpin->setRange(0, 3650);
	resetDaysSpin->setValue(recovery.resetDays);
	new FXLabel(resetRow, "Tagen auf Null zurücksetzen");

	new FXLabel(rm, "Dienst neu starten nach");
	FXHorizontalFrame* restartRow = new FXHorizontalFrame(rm, LAYOUT_FILL_X, 0,0,0,0, 0,0,0,0);
	restartSecsSpin = new FXSpinner(restartRow, 6, NULL, 0, FRAME_SUNKEN | SPIN_NOMAX);
	restartSecsSpin->setRange(1, 86400);
	restartSecsSpin->setValue(recovery.restartSecs > 0 ? recovery.restartSecs : 100);
	new FXLabel(restartRow, "Sekunden");

	new FXHorizontalSeparator(rec, SEPARATOR_GROOVE | LAYOUT_FILL_X);
	new FXLabel(rec,
		"\"Dienst neu starten\" entspricht Restart=on-failure. Die Wartezeit\n"
		"zählt systemd in Sekunden, nicht in Minuten. \"Programm ausführen\"\n"
		"und \"Computer neu starten\" gibt es hier nicht.",
		NULL, JUSTIFY_LEFT | LAYOUT_FILL_X);

	// ---------------- Abhaengigkeiten ----------------
	new FXTabItem(tabs, "Abhängigkeiten");
	FXVerticalFrame* dep = new FXVerticalFrame(tabs, FRAME_THICK | FRAME_RAISED | LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 10,10,10,10);
	new FXLabel(dep, "Einige Dienste können von anderen Diensten abhängig sein. Falls ein\n"
	                 "Dienst anhält oder nicht einwandfrei ausgeführt wird, kann dies\n"
	                 "Auswirkungen auf abhängige Dienste haben.", NULL, JUSTIFY_LEFT | LAYOUT_FILL_X);

	FXString name = FXString("\"") + info.displayName().c_str() + "\"";
	new FXLabel(dep, name + " ist von diesen Diensten abhängig:");
	FXList* upper = new FXList(dep, NULL, 0, LIST_NORMAL | FRAME_SUNKEN | LAYOUT_FILL_X | LAYOUT_FILL_Y);
	for (auto& d : deps.dependsOn) upper->appendItem(d.c_str());

	new FXLabel(dep, FXString("Diese Dienste sind von ") + name + " abhängig:");
	FXList* lower = new FXList(dep, NULL, 0, LIST_NORMAL | FRAME_SUNKEN | LAYOUT_FILL_X | LAYOUT_FILL_Y);
	for (auto& d : deps.dependents) lower->appendItem(d.c_str());

	// ---------------- Schaltflaechen ----------------
	FXHorizontalFrame* btnf = new FXHorizontalFrame(main, LAYOUT_FILL_X, 0,0,0,0, 0,0,10,0);
	new FXFrame(btnf, LAYOUT_FILL_X);
	new FXButton(btnf, "OK", NULL, this, ID_ACCEPT, BUTTON_NORMAL | BUTTON_DEFAULT | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
	new FXButton(btnf, "Abbrechen", NULL, this, ID_CANCEL, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);
	new FXButton(btnf, "Übernehmen", NULL, this, ID_APPLY, BUTTON_NORMAL | FRAME_RAISED | FRAME_THICK, 0,0,0,0, 14,14,3,3);

	refreshStatus();
}

void SvcPropsDialog::refreshStatus() {
	ServiceInfo fresh;
	RecoverySettings r;
	Dependencies d;
	if (loadService(unit, fresh, r, d)) info = fresh;

	FXString text = info.running() ? "Gestartet" : "Beendet";
	if (info.activeState == "failed") text = "Fehlgeschlagen";
	statusLabel->setText(text);

	if (info.running()) { btnStart->disable(); btnStop->enable(); }
	else { btnStart->enable(); btnStop->disable(); }
}

long SvcPropsDialog::onStart(FXObject*, FXSelector, void*) {
	std::string err;
	if (!startService(unit, err))
		FXMessageBox::error(this, MBOX_OK, "Dienst starten", "%s", err.c_str());
	refreshStatus();
	return 1;
}

long SvcPropsDialog::onStop(FXObject*, FXSelector, void*) {
	std::string err;
	if (!stopService(unit, err))
		FXMessageBox::error(this, MBOX_OK, "Dienst beenden", "%s", err.c_str());
	refreshStatus();
	return 1;
}

long SvcPropsDialog::onLogonChoice(FXObject* sender, FXSelector, void*) {
	bool custom = (sender == rbAccount);
	rbSystem->setCheck(!custom);
	rbAccount->setCheck(custom);
	if (custom) accountField->enable(); else accountField->disable();
	return 1;
}

long SvcPropsDialog::onRecFirstChanged(FXObject*, FXSelector, void*) {
	// Die gesperrten Felder spiegeln immer die erste Wahl, damit der
	// Dialog nicht drei verschiedene Werte suggeriert.
	recSecond->setCurrentItem(recFirst->getCurrentItem());
	recFurther->setCurrentItem(recFirst->getCurrentItem());
	return 1;
}

bool SvcPropsDialog::apply() {
	std::string err;

	StartType wanted = START_MANUAL;
	if (startTypeCombo->getCurrentItem() == 0) wanted = START_AUTO;
	else if (startTypeCombo->getCurrentItem() == 2) wanted = START_DISABLED;

	if (wanted != info.startType() && !setStartType(unit, wanted, err)) {
		FXMessageBox::error(this, MBOX_OK, "Starttyp ändern", "%s", err.c_str());
		return false;
	}

	std::string account;
	if (rbAccount->getCheck()) {
		account = accountField->getText().text();
		if (account.empty()) {
			FXMessageBox::error(this, MBOX_OK, "Anmelden", "Bitte einen Kontonamen eingeben.");
			return false;
		}
	}

	RecoverySettings r;
	r.action = (recFirst->getCurrentItem() == 1) ? REC_RESTART : REC_NONE;
	r.restartSecs = restartSecsSpin->getValue();
	r.resetDays = resetDaysSpin->getValue();

	if (!applySettings(unit, account, r, err)) {
		FXMessageBox::error(this, MBOX_OK, "Einstellungen speichern", "%s", err.c_str());
		return false;
	}

	recovery = r;
	refreshStatus();
	return true;
}

long SvcPropsDialog::onApply(FXObject*, FXSelector, void*) { apply(); return 1; }

long SvcPropsDialog::onAccept(FXObject* sender, FXSelector sel, void* ptr) {
	if (!apply()) return 1;
	return FXDialogBox::onCmdAccept(sender, sel, ptr);
}

// ---------------------------------------------------------------------
// SvcPanel
// ---------------------------------------------------------------------
FXDEFMAP(SvcPanel) SvcPanelMap[] = {
	FXMAPFUNC(SEL_DOUBLECLICKED, SvcPanel::ID_LIST, SvcPanel::onListDoubleClick),
	FXMAPFUNC(SEL_RIGHTBUTTONRELEASE, SvcPanel::ID_LIST, SvcPanel::onListRightClick),
	FXMAPFUNC(SEL_COMMAND, SvcPanel::ID_START, SvcPanel::onStart),
	FXMAPFUNC(SEL_COMMAND, SvcPanel::ID_STOP, SvcPanel::onStop),
	FXMAPFUNC(SEL_COMMAND, SvcPanel::ID_RESTART, SvcPanel::onRestart),
	FXMAPFUNC(SEL_COMMAND, SvcPanel::ID_PROPERTIES, SvcPanel::onProperties),
	FXMAPFUNC(SEL_COMMAND, SvcPanel::ID_REFRESH, SvcPanel::onRefresh),
};
FXIMPLEMENT(SvcPanel, FXVerticalFrame, SvcPanelMap, ARRAYNUMBER(SvcPanelMap))

SvcPanel::SvcPanel(FXComposite* parent, FXIcon* serviceIcon)
	: FXVerticalFrame(parent, LAYOUT_FILL_X | LAYOUT_FILL_Y, 0,0,0,0, 0,0,0,0, 0,0),
	  icoService(serviceIcon) {
	list = new FXIconList(this, this, ID_LIST,
	                       ICONLIST_DETAILED | ICONLIST_BROWSESELECT | LAYOUT_FILL_X | LAYOUT_FILL_Y | FRAME_NORMAL);
	list->appendHeader("Name", NULL, 200);
	list->appendHeader("Beschreibung", NULL, 240);
	list->appendHeader("Status", NULL, 90);
	list->appendHeader("Autostarttyp", NULL, 110);
	list->appendHeader("Anmelden als", NULL, 120);
}

void SvcPanel::reload() {
	FXint keep = list->getCurrentItem();
	list->clearItems();
	services = listServices();
	for (auto& s : services) {
		FXString txt = FXString(s.displayName().c_str()) + "\t" + s.description.c_str() + "\t"
		             + s.statusLabel().c_str() + "\t" + s.startTypeLabel().c_str() + "\t"
		             + s.logonLabel().c_str();
		list->appendItem(txt, icoService, icoService);
	}
	if (keep >= 0 && keep < list->getNumItems()) {
		list->setCurrentItem(keep);
		list->selectItem(keep);
	}
}

bool SvcPanel::hasSelection() const {
	FXint idx = list->getCurrentItem();
	return idx >= 0 && idx < (FXint)services.size();
}

void SvcPanel::startSelected() {
	if (!hasSelection()) return;
	std::string err;
	if (!startService(services[list->getCurrentItem()].unit, err))
		FXMessageBox::error(this, MBOX_OK, "Dienst starten", "%s", err.c_str());
	reload();
}

void SvcPanel::stopSelected() {
	if (!hasSelection()) return;
	std::string err;
	if (!stopService(services[list->getCurrentItem()].unit, err))
		FXMessageBox::error(this, MBOX_OK, "Dienst beenden", "%s", err.c_str());
	reload();
}

void SvcPanel::restartSelected() {
	if (!hasSelection()) return;
	std::string err;
	if (!restartService(services[list->getCurrentItem()].unit, err))
		FXMessageBox::error(this, MBOX_OK, "Dienst neu starten", "%s", err.c_str());
	reload();
}

void SvcPanel::propertiesForSelected() {
	if (!hasSelection()) return;
	std::string unit = services[list->getCurrentItem()].unit;

	ServiceInfo info;
	RecoverySettings rec;
	Dependencies deps;
	if (!loadService(unit, info, rec, deps)) {
		FXMessageBox::error(this, MBOX_OK, "Eigenschaften",
			"Die Eigenschaften von %s konnten nicht gelesen werden.", unit.c_str());
		return;
	}

	SvcPropsDialog dlg(this, unit, info, rec, deps);
	dlg.execute(PLACEMENT_OWNER);
	reload();
}

long SvcPanel::onListDoubleClick(FXObject*, FXSelector, void*) { propertiesForSelected(); return 1; }

long SvcPanel::onListRightClick(FXObject*, FXSelector, void* ptr) {
	FXEvent* ev = (FXEvent*)ptr;
	FXint idx = list->getItemAt(ev->win_x, ev->win_y);
	if (idx < 0) return 1;
	list->setCurrentItem(idx);
	list->selectItem(idx);

	FXMenuPane menu(this);
	bool running = services[idx].running();
	FXMenuCommand* mcStart = new FXMenuCommand(&menu, "&Starten", NULL, this, ID_START);
	FXMenuCommand* mcStop = new FXMenuCommand(&menu, "&Beenden", NULL, this, ID_STOP);
	FXMenuCommand* mcRestart = new FXMenuCommand(&menu, "Neu s&tarten", NULL, this, ID_RESTART);
	if (running) mcStart->disable(); else { mcStop->disable(); mcRestart->disable(); }
	new FXMenuSeparator(&menu);
	new FXMenuCommand(&menu, "&Aktualisieren", NULL, this, ID_REFRESH);
	new FXMenuSeparator(&menu);
	new FXMenuCommand(&menu, "&Eigenschaften", NULL, this, ID_PROPERTIES);

	menu.create();
	menu.popup(NULL, ev->root_x, ev->root_y);
	getApp()->runModalWhileShown(&menu);
	return 1;
}

long SvcPanel::onStart(FXObject*, FXSelector, void*) { startSelected(); return 1; }
long SvcPanel::onStop(FXObject*, FXSelector, void*) { stopSelected(); return 1; }
long SvcPanel::onRestart(FXObject*, FXSelector, void*) { restartSelected(); return 1; }
long SvcPanel::onProperties(FXObject*, FXSelector, void*) { propertiesForSelected(); return 1; }
long SvcPanel::onRefresh(FXObject*, FXSelector, void*) { reload(); return 1; }
