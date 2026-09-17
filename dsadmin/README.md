# dsadmin -- Active Directory-Benutzer und -Computer für ice2k

Ein Nachbau des echten `dsa.msc`-Snapins für
[ice2k](https://github.com/comdlg32/ice2k). Backend: **Samba-AD-
Domäne via `samba-tool`** (`user`/`group`/`ou`/`computer`/`gpo`).

![Baumstruktur: Domäne -> Builtin/Computers/Users/Domain Controllers](../docs/dsadmin/screenshots/screenshot-baumstruktur.png)

## Einordnung im Projekt

Sobald ein Server per `dcpromo` zum Domänencontroller wird, verwaltet
`compmgmt` ("Lokale Benutzer und Gruppen") keine echten Konten mehr --
genau wie im Original wandern Benutzer/Gruppen in die
Domänendatenbank. `dsadmin` übernimmt genau das: die Verwaltung von
**Domänenkonten** statt lokaler Konten.

## Funktionsumfang
- Baumstruktur: Domäne -> Builtin/Computers/Users/Domain Controllers
  + eigene Organisationseinheiten, beliebig tief verschachtelt (ein
  einziger `samba-tool ou list`-Aufruf für den ganzen Baum, die OUs
  werden nach Tiefe sortiert eingehängt)
- Container-Anzeige mit Typ-Klassifizierung (Benutzer/Sicherheits-
  gruppe/Computer/Organisationseinheit/Container) und passenden Icons
- Beschreibung und genauer Gruppentyp in der Liste ("Sicherheitsgruppe
  - Global", "- Lokal (in Domäne)", "- Universal", "- Lokal
  (vordefiniert)", Verteilergruppen entsprechend) -- gelesen mit einer
  einzigen Abfrage pro Container über Sambas privilegierten
  ldapi-Socket, der root ohne Anmeldedaten lesen (nicht schreiben)
  lässt
- **Doppelklick** öffnet bei Benutzern und Gruppen die Eigenschaften;
  Container und Organisationseinheiten werden wie im Original im Baum
  geöffnet
- **Benutzereigenschaften** mit Reitern, geschrieben wird erst bei
  OK/Übernehmen:
  - *Allgemein*: Vorname, Initialen, Nachname, Anzeigename,
    Beschreibung, Büro, Rufnummer, E-Mail, Webseite. Nur geänderte
    Attribute werden per LDAP geschrieben; ein geleertes Feld entfernt
    das Attribut (ein leerer Wert wäre in AD ein Syntaxfehler), Werte
    mit Umlauten gehen base64-kodiert (`attr:: ...`) raus
  - *Konto*: Anmeldenamen, "Konto ist deaktiviert"
  - *Mitglied von*: Gruppen mit Active Directory-Ordner, Hinzufügen
    über den Dialog **"Gruppen auswählen"** (Liste mit Mehrfachauswahl
    plus Eingabefeld, "Namen überprüfen" löst auch eindeutige
    Namensanfänge auf und unterstreicht sie), Entfernen, **primäre
    Gruppe festlegen** (nur globale/universelle Sicherheitsgruppen;
    die primäre Gruppe selbst lässt sich nicht entfernen). Backend
    `samba-tool user getgroups --full-dn` (primäre Gruppe steht immer
    zuerst) und `user setprimarygroup`. Reihenfolge beim Schreiben:
    erst hinzufügen, dann primäre Gruppe umstellen, zuletzt entfernen;
    danach wird der echte Stand neu gelesen, weil AD die bisherige
    primäre Gruppe selbst als normale Mitgliedschaft weiterführt
- **Kennwort zurücksetzen...** im Kontextmenü eines Benutzers (wie im
  Original, nicht in den Eigenschaften)
- **Neu**: Benutzer/Gruppe/Organisationseinheit anlegen
- **Löschen** für Benutzer/Gruppe/Organisationseinheit
- **Umbenennen...** -- bei Benutzern/Gruppen über `samba-tool ...
  rename --force-new-cn`, ändert also nur den Anzeigenamen (CN) und
  lässt den Anmeldenamen unberührt, genau wie das einfache
  F2-Umbenennen im echten Active Directory; bei
  Organisationseinheiten über `samba-tool ou rename`
- **Verschieben...** zwischen Containern/Organisationseinheiten
  (`samba-tool <user|group|ou> move`), mit Zielauswahl über eine Liste
  aller OUs -- die Domänenwurzel selbst ist ebenfalls als Ziel wählbar
- **Sicherheitseinstellungen**: domänenweite Kennwort- und
  Kontosperrungsrichtlinie (`samba-tool domain passwordsettings`) --
  Komplexität, Mindestlänge, Kennwortchronik, Mindest-/Höchstalter,
  Sperrschwelle, Sperrdauer und Zurücksetzungsfenster. In AD gibt es
  davon (vor den granularen Richtlinien von 2008) nur genau eine
- **Eigenschaften** mit dem **"Gruppenrichtlinie"**-Reiter (GPOs
  anlegen/verknüpfen/lösen über `samba-tool gpo`) und dem
  vollständigen Gruppenrichtlinienobjekt-Editor dahinter (siehe unten)

## Eigenschaften von Organisationseinheit und Domäne

Wie im Original drei Reiter:

- *Allgemein*: Beschreibung, Straße (mehrzeilig, in AD mit CRLF),
  Stadt, Bundesland/Kanton, PLZ, Land/Region. Die Länderliste kommt
  aus dem Debian-Paket `iso-codes` (`iso_3166-1.json`), die deutschen
  Namen direkt aus dessen `.mo`-Datei; geschrieben werden `c`, `co`
  und `countryCode`. Bei der Domäne selbst stattdessen der
  Prä-Windows-2000-Name und der Domänenmodus.
- *Verwaltet von*: `managedBy` über die Objektauswahl, dazu Büro,
  Adresse und Rufnummern des Verantwortlichen (nur lesend).
- *Gruppenrichtlinie*: Verknüpfungen mit "Kein Vorrang" (Option 2) und
  "Deaktiviert" (Option 1), Neu, Hinzufügen..., Bearbeiten, Optionen...,
  Löschen..., Eigenschaften (Erstellt/Geändert/Revisionen, Computer-
  bzw. Benutzerkonfiguration deaktivieren über `flags`), Nach
  oben/unten, "Richtlinienvererbung deaktivieren" (`gPOptions`).
  Doppelklick oder Bearbeiten öffnet das Gruppenrichtlinienfenster.

Gelesen wird über Sambas privilegierten ldapi-Socket (ohne
Anmeldedaten), geschrieben per LDAP mit Administrator-Anmeldedaten.

## Abgleich mit den Originaldateien

Texte und Aufbau der Gruppenrichtlinien-Dialoge sind gegen die
Ressourcen der deutschen `gpedit.dll` aus Windows 2000 SP4
(5.00.2195.6998) abgeglichen: Gruppenrichtlinie-Reiter (Dialog 1025),
"Optionen für ..." (1040), "Löschen" (1050) samt Rückfrage "Soll %s
unwiderruflich gelöscht werden?", Eigenschaften eines GPOs mit
"Zusammenfassung"/"Deaktivieren" (500) inklusive "Deaktivieren
bestätigen" und Reiter "Links" (550), sowie
"Gruppenrichtlinienobjekt-Verknüpfung hinzufügen" mit den Reitern
"Domänen/Organisationseinheiten", "Standorte" und "Alle" (1203). Die
DLL selbst liegt nicht im Repository.

Weitere Abgleiche (alle deutsch, Windows 2000 SP4; die DLLs liegen
nicht im Repository):

- `dsadmin.dll`: Werkzeugleisten-Symbole (Bitmap 242) und Kurzinfos
  (Texte 740-751), Snap-in- und Domänensymbol → `res/dsadmin`.
- `wsecedit.dll`: Namen, Einheiten und Eingabetexte der Kennwort-,
  Kontosperrungs-, Kerberos-, Überwachungs- und Ereignisprotokoll-
  Richtlinien (inklusive Textwechsel bei 0, z.B. "Kennwort läuft nie
  ab:"), die in der DLL stehenden Benutzerrechte und
  Sicherheitsoptionen, Dialogtitel "Sicherheitsrichtlinienvorlage",
  Dialoge für Dienste (195), Datei/Registrierung (197) und eingeschränkte
  Gruppen (107) samt Platzhaltern, Spalten "Start"/"Überwachen".
  Dialog 197 bestätigt die Zuordnung der Vererbungsmodi (0 übermitteln,
  2 ersetzen, 1 Ersetzen nicht zulassen). Die übrigen
  Sicherheitsoptionen und Benutzerrechte stehen nicht in der DLL.
- Sicherheitsoptionen unter `[Registry Values]`: wortgleich aus dem
  Registrierungsschlüssel `HKLM\SOFTWARE\Microsoft\Windows
  NT\CurrentVersion\SeCEdit\Reg Values` eines deutschen Windows 2000 SP4
  (dort statt in `sceregvl.inf`, die es erst ab XP gibt): Anzeigename,
  Anzeigetyp, Werttyp, Einheit und Auswahllisten, 36 Einträge.
- `msprivs.dll`: Namen aller Rechte (Se...Privilege), in der Reihenfolge
  der LSA-Rechtetabelle.
- `aclui.dll`: Aufbau des Berechtigungsdialogs (103) mit "Erweitert"-
  Hinweis, Meldungen beim Entfernen geerbter Konten (Text 20) und bei
  Verweigerungen (31), Rückfrage "Kopieren/Entfernen/Abbrechen" beim
  Abschalten der Vererbung (109).
- `gptext.dll`: Richtliniendialog mit den Reitern "Richtlinie" (200) und
  "Erklärung" (225) sowie "Vorherige/Nächste Richtlinie".
- `dsprop.dll`: Eigenschaftenseiten -- Benutzer "Allgemein" (131) mit
  "Andere..."-Knöpfen, "Konto" (136) mit den Kontooptionen
  (`userAccountControl`-Bits, "Benutzer muss Kennwort bei nächster
  Anmeldung ändern" über `pwdLastSet`), "Konto ist gesperrt"
  (`lockoutTime`), "Ablaufdatum des Kontos" (`accountExpires`, wie im
  Original Beginn des Folgetags) und UPN-Suffix; Gruppe "Allgemein"
  (156), "Verwaltet von" (234), OU "Allgemein" (226). Die Länderliste
  (Texte 4000 ff.) steht in `countries_w2k.h` -- in Großbuchstaben wie im
  Original; das Paket `iso-codes` wird nicht mehr gebraucht. Außerdem die
  Benutzer-Reiter "Adresse" (134: `streetAddress` mit CRLF,
  `postOfficeBox`, `l`, `st`, `postalCode`, Land), "Profil" (315:
  `profilePath`, `scriptPath`, Basisordner als lokaler Pfad oder
  verbundenes Laufwerk über `homeDirectory`/`homeDrive`), "Rufnummern"
  (218: `homePhone`, `pager`, `mobile`, `facsimileTelephoneNumber`,
  `ipPhone`, Anmerkung `info`) und "Organisation" (135: `title`,
  `department`, `company`, Vorgesetzte(r) `manager` mit Ändern/Anzeigen/
  Löschen, Mitarbeiter aus `directReports`) -- Reiterfolge wie im
  Original. Dazu: "Andere..." für die Mehrfachwerte (`otherTelephone`, `url`,
  `otherHomePhone`, `otherPager`, `otherMobile`,
  `otherFacsimileTelephoneNumber`, `otherIpPhone`), "Anmeldezeiten..."
  als Wochenraster (`logonHours`, 21 Bytes, Bit 0 = Sonntag 0 Uhr UTC,
  angezeigt in Ortszeit), "Anmelden..." (`userWorkstations`) und
  "Benutzer kann das Kennwort nicht ändern" -- in AD kein
  `userAccountControl`-Bit, sondern wie bei Windows 2000 zwei
  Verweigerungs-ACEs für das erweiterte Recht "Kennwort ändern"
  (`ab721a53-...`) an SELF und Jeder, gesetzt und entfernt über
  `samba-tool dsacl`. Die Dialoge für Anmeldezeiten, Anmelden und
  "Andere..." stehen nicht in `dsprop.dll` (sondern in `loghours.dll`
  bzw. `dsuiext.dll`) und sind daher noch nicht wortgleich.
- `appmgr.dll`: nach der Paketauswahl der Dialog "Software
  bereitstellen" (Veröffentlicht/Zugewiesen; in der Computerkonfiguration
  nur Zugewiesen), Spalten der Softwareinstallation ("Bereitstellungszustand",
  "Quelle" aus `msiFileList`) und der Dialog "Software entfernen" (211).

Die Symbole unter `res/gpedit` stammen aus derselben DLL (Bitmaps 1 und
1229, Magenta als Transparenz in echtes Alpha umgesetzt): Ordner,
Gruppenrichtlinienobjekt, GPO mit verweigertem Zugriff (für verwaiste
oder nicht lesbare Verknüpfungen), Computer- und Benutzerkonfiguration,
Standort, Domäne, lokaler Computer sowie Übergeordneter Ordner und Neues
Gruppenrichtlinienobjekt. Die Symbole unter `res/dsa` (Neuer
Benutzer/Gruppe/OU, Suchen, Zu Gruppe hinzufügen) sind noch vorläufig.

## Gruppenrichtlinienfenster

Nachbau des Gruppenrichtlinienobjekt-Editors: Baum mit Computer- und
Benutzerkonfiguration, rechts der Inhalt des gewählten Knotens,
Doppelklick bearbeitet.

- **Softwareinstallation** (Computer/Benutzer): Pakete mit
  Bereitstellungsstatus, Rechtsklick für Neu → Paket... und Entfernen...
- **Skripts** (nach `gptext.dll`): unter "Skripts (Start/Herunterfahren)"
  bzw. "(Anmelden/Abmelden)" je Ereignis ein Eintrag; Doppelklick öffnet
  "Skripts zum Anmelden für <GPO>" mit Nach oben/unten,
  Hinzufügen/Bearbeiten/Entfernen und "Dateien anzeigen...".
  Gespeichert in `<Zweig>\Scripts\scripts.ini` (UTF-16, `0CmdLine=`,
  `0Parameters=`); Skriptdateien liegen in `Scripts\<Ereignis>` --
  "Durchsuchen..." kopiert eine Datei von außerhalb dorthin und trägt nur
  den Dateinamen ein, wie im Original.
- **Administrative Vorlagen**: Kategorien direkt im Baum (siehe unten).
- **Sicherheitseinstellungen** in `Machine/Microsoft/Windows
  NT/SecEdit/GptTmpl.inf` (UTF-16LE mit BOM; Abschnitte und Schlüssel,
  die hier nicht bearbeitet werden, bleiben erhalten):
  - Kennwortrichtlinien, Kontosperrungsrichtlinien (`[System Access]`)
  - Überwachungsrichtlinien (`[Event Audit]`, Bit 1 Erfolg, Bit 2 Fehler)
  - Zuweisen von Benutzerrechten (`[Privilege Rights]`, Konten als
    `*SID`; aufgelöst über `objectSid` aus AD plus feste SIDs wie
    Jeder oder Authentifizierte Benutzer)
  - Sicherheitsoptionen (die Liste von Windows 2000, überwiegend
    `[Registry Values]` als `MACHINE\...=4,1` bzw. `=1,"Text"`)
  - Einstellungen für Ereignisprotokolle (`[Application Log]` usw.)
  - Eingeschränkte Gruppen (`[Group Membership]`, `*SID__Members` und
    `*SID__Memberof`; wie im Original legt "Gruppe hinzufügen" beide
    Listen zunächst leer an)

  Beim Speichern werden fehlende Verzeichnisse mit den SYSVOL-Rechten
  des Zweigs angelegt, die Sicherheits-Erweiterung
  `{827D319E-6EAC-11D2-A4EA-00C04F79F83A}` im GPO registriert und die
  Version erhöht.

  Kontorichtlinien (Kennwort, Kontosperrung) wirken für Domänenkonten
  nur aus GPOs, die mit der Domäne selbst verknüpft sind; ein Windows-DC
  übernimmt sie dann ins Domänenobjekt. In einem GPO an einer
  Organisationseinheit gelten sie nur für die lokalen Konten der Computer
  dort -- das Gruppenrichtlinienfenster weist in der Statuszeile darauf
  hin. Samba übernimmt die Werte nicht selbst; dsadmin berechnet deshalb
  die wirksame Richtlinie aus allen aktiven Verknüpfungen an der
  Domänenwurzel (niedrige vor hoher Priorität, spätere Definitionen
  gewinnen, GPOs mit deaktivierter Computerkonfiguration zählen nicht)
  und setzt sie per `samba-tool domain passwordsettings` -- nach jeder
  Änderung einer solchen Richtlinie, nach Verknüpfen, Entfernen,
  Umsortieren oder Deaktivieren an der Domäne und nach "Konfigurations-
  einstellungen des Computers deaktivieren".
- **Systemdienste** (`[Service General Setting]`, Zeilen
  `"Name",Starttyp,"SDDL"` mit 2 = Automatisch, 3 = Manuell,
  4 = Deaktiviert): dieselbe Dienstliste wie im Programm "Dienste"
  (`common/svc/SvcPanel` mit Delegate), bei jedem Öffnen frisch aus
  systemd gelesen. Wie im Original stammen die Dienste vom Rechner, auf
  dem der Editor läuft -- hier also die Dienste dieses Servers; unter
  Windows-Clients wirken nur Einträge, deren Name dort ein Dienst ist.
  Beim ersten Definieren bekommt ein Dienst Standardberechtigungen
  (Administratoren/SYSTEM Vollzugriff, interaktive Benutzer und Dienste
  lesend); "Sicherheit bearbeiten..." öffnet den Berechtigungsdialog.
- **Registrierung** (`[Registry Keys]`) und **Dateisystem**
  (`[File Security]`), Zeilen `"Pfad",Modus,"SDDL"`: Rechtsklick für
  "Schlüssel hinzufügen..." bzw. "Datei hinzufügen...", Sicherheit...
  und Löschen. Pfade werden wie auf dem Client angegeben (unter Linux
  gibt es nichts zu durchsuchen); bei Schlüsseln werden HKLM/HKU/HKCR
  zu MACHINE/USERS/CLASSES_ROOT umgesetzt. Wie im Original erst der
  Berechtigungsdialog, dann die Vererbung.

  Zum Modus widersprechen sich Microsofts Quellen: [MS-GPSB] 2.2.7 nennt
  0 = weitergeben, 1 = ersetzen, 2 = nicht ersetzen; die WMI-Klasse
  `RSOP_RegistryKey` aus der tatsächlichen Implementierung (SceRsop.mof)
  dagegen 0 = Inherit, 1 = Ignore, 2 = Overwrite, und Windows' eigene
  Vorlagen setzen kritische Einträge wie `regedit.exe` auf 2. Wir folgen
  der Implementierung: 0 = vererbbare Berechtigungen weitergeben,
  1 = nicht konfigurieren, 2 = Berechtigungen der Unterobjekte ersetzen.
- Noch ohne Funktion:
  Richtlinien öffentlicher Schlüssel, IP-Sicherheit,
  Internet Explorer-Wartung, Remoteinstallationsdienste.

Die Zweige heißen bei den provisionierten Standard-GPOs `MACHINE`/`USER`,
bei neu angelegten `Machine`/`User`; geschrieben wird immer in das
vorhandene Verzeichnis.

## Berechtigungsdialog

Ein Dialog für alle Objekte mit Berechtigungen (Systemdienste, später
Registrierung und Dateisystem): oben die Konten mit Hinzufügen/Entfernen
über die Objektauswahl, darunter die einfachen Berechtigungen mit
Zulassen/Verweigern -- je Objektart die von Windows 2000 (Dienste:
Vollzugriff, Lesen, Starten/beenden/anhalten, Schreiben, Löschen;
Registrierung: Vollzugriff, Lesen; Dateisystem: Vollzugriff, Ändern,
Lesen/Ausführen, Lesen, Schreiben).

Gespeichert wird SDDL. Der Leser/Schreiber ist verlustfrei: Besitzer,
Gruppe, SACL, DACL-Flags, Hex-Rechte und Objekt-ACEs gehen unverändert
durch, SDDL-Kürzel (`BA`, `SY`, `DA` ...) werden beim Lesen zu SIDs
aufgelöst und beim Schreiben wieder verwendet. Nur Konten, an denen im
Dialog etwas geändert wurde, bekommen neu erzeugte Einträge -- in
kanonischer Reihenfolge (Verweigern vor Zulassen, Geerbtes zuletzt);
alles andere bleibt Zeichen für Zeichen stehen. Generische Rechte
(`GA`/`GR`/`GW`/`GX`) werden für die Anzeige in die Bits der jeweiligen
Objektart übersetzt. Abhaken einer Berechtigung nimmt wie im Original
auch die umfassenderen mit ("Ändern" weg → "Vollzugriff" weg), lässt die
kleineren aber stehen ("Lesen, Ausführen", "Lesen", "Schreiben").
Geerbte Berechtigungen erscheinen grau angehakt;
"Vererbbare übergeordnete Berechtigungen übernehmen" (nicht bei
Diensten) schaltet das `P`-Flag und fragt beim Abschalten wie das
Original, ob die geerbten Einträge übernommen oder entfernt werden.

## Administrative Vorlagen

Die Kategorien aus den zusammengeführten `.adm`-Dateien hängen direkt
im Baum des Gruppenrichtlinienfensters, unter "Computerkonfiguration"
(`CLASS MACHINE`) und "Benutzerkonfiguration" (`CLASS USER`). Rechts
stehen erst die Unterkategorien, dann die Richtlinien mit ihrer
Einstellung. Doppelklick öffnet Nicht konfiguriert/Aktiviert/Deaktiviert
plus das passende Eingabefeld (Checkbox/Textfeld/Zahlenfeld/Dropdown,
auch mehrere Parts je Richtlinie).

Wie im Original wirkt jede Änderung sofort mit OK -- es gibt keinen
eigenen Speichern-Knopf mehr. Geschrieben wird die `Registry.pol` des
jeweiligen Zweigs (vorhandenes `Machine`/`MACHINE` bzw. `User`/`USER`);
eine neu angelegte Datei erbt die SYSVOL-Rechte. Danach wird die
Registry-Erweiterung `{35378EAC-683F-11D2-A89A-00C04FBBCFA2}` mit dem
Tool `{0F6B957D-...}` (Computer) bzw. `{0F6B957E-...}` (Benutzer) im
GPO eingetragen -- das hatte der frühere, separate Editor versäumt --
und die Version genau dieses Zweigs erhöht. Schließt man den Dialog
unverändert mit OK, wird nichts geschrieben.

## Reihenfolge der Erweiterungsliste

`gPCMachineExtensionNames`/`gPCUserExtensionNames` bestehen aus
Blöcken `[{CSE}{Tool}...]`. [MS-GPOL] verlangt die Blöcke nach
CSE-GUID aufsteigend sortiert, die Tool-GUIDs innerhalb eines Blocks
ebenso. Neue Einträge wurden bisher einfach angehängt; jetzt werden
sie einsortiert, und eine vorhandene unsortierte Liste wird bei der
nächsten Änderung richtiggestellt.

## Advertise-Skript (.aas)

Die `.aas`-Datei wird gegen zwei echte, von einem Windows-2000-Server
erzeugte Skripte abgeglichen: für dieselben Eingaben ist die Ausgabe
byteweise identisch (bis auf den Zeitstempel im Kopf).

Die erste, allein aus [MS-GPSI] abgeleitete Fassung war an mehreren
Stellen falsch und hat auf dem Client nichts bewirkt:

| | vorher | richtig |
|---|---|---|
| Produkt- und Dateiname | Unicode | **ASCII** |
| ProductInfo | 16 Argumente | **13** |
| Header-Version | 400 | **200** |
| Ende-Datensatz | 3 Argumente | **2** |
| Quellenliste | voller Pfad zur .msi | nur das **Quellverzeichnis** |
| Features | fehlten ganz | je ein `0x41`-Datensatz |
| PublishFeatures/PublishProduct | fehlten | `0x08` |
| Rollback-Aktionstexte | fehlten | `0x06` |
| UpgradeCode | fehlte | `0x62` |

Entscheidend sind die Feature-Datensätze: ohne sie veröffentlicht das
Skript keine Features, und der Windows Installer weiß nicht, was er
installieren soll. Die Feature-Liste kommt aus der Feature-Tabelle der
`.msi` (`msiinfo export <datei> Feature`), der Package Code aus dem
Summary-Information-Stream (`msiinfo suminfo`) statt aus einer selbst
erzeugten GUID, und Sprache sowie UpgradeCode aus der Property-Tabelle.

## AD-Objekte der Softwareinstallation

Auch diese Objekte sind gegen einen echten Windows-2000-Server
abgeglichen (vollständiger `ldifde`-Export eines zugewiesenen Pakets).
Die aus [MS-GPSI] abgeleitete Fassung wich deutlich ab:

| | vorher | echtes Vorbild |
|---|---|---|
| CN des Pakets | `{GUID}` groß, mit Klammern | GUID **klein, ohne Klammern** |
| `packageFlags` (zugewiesen) | `0x810` | **`0xA0084C70`** |
| `versionNumberHi/Lo` | 0 / 0 | Haupt- / Nebenversion |
| `machineArchitecture` | 0 | **1282** |
| `revision` | 1 | 0 |
| `installUiLevel` | fehlte | 3 |
| `upgradeProductCode` | fehlte | binäre GUID |
| `showInAdvancedViewOnly` | fehlte | TRUE |
| `lastUpdateSequence` | fehlte | Zeitstempel |
| Class Store: `extensionName` | fehlte | `Software` |
| Class Store: `displayName` | fehlte | `LDAP://<GPO-DN>` |
| Class Store: `appSchemaVersion` | fehlte | 1740 |
| Class Store: `lastUpdateSequence` | Unix-Zeit | `yyyymmddhhmmss` |

Beim `displayName` des Class Store gab es zusätzlich eine zweite
Schreibstelle: die Bestätigungsfunktion nach dem Anlegen überschrieb
ihn mit "Application Store" (das gehört in `description`) und
`lastUpdateSequence` mit einer Unix-Zeit -- beide beim Anlegen korrekt
gesetzten Werte waren damit sofort wieder falsch.

`CN=Packages` ist auch auf dem echten Server ein `classStore`, nicht
ein `container` -- das deckt sich mit dem Schema.

Die `packageFlags` stammen alle aus echten Objekten -- keiner der
Werte ist abgeleitet oder geraten:

| Zustand | `msiScriptName` | `packageFlags` |
|---|---|---|
| zugewiesen (Computer) | `A` | `0xA0084C70` |
| zugewiesen (Benutzer) | `A` | `0xA00C0E70` |
| veröffentlicht (Benutzer) | `P` | `0xA0080878` |
| zur Deinstallation vorgemerkt | `R` | `0xA0080110` |

Zwei naheliegende Annahmen haben sich dabei als falsch erwiesen.
Veröffentlichte Pakete tauschen das Assigned-Bit `0x800` **nicht**
gegen `0x8` -- `0x800` bleibt stehen, `0x8` kommt hinzu, `0x400` und
`0x4000` fallen weg. Und die Zuweisung an die Benutzerkonfiguration
benutzt **nicht** denselben Wert wie beim Computer: dort fehlt `0x4000`,
dafür sind `0x200` und `0x40000` gesetzt.

Beim Auslesen muss auf `0x8` geprüft werden, bevor auf `0x800` -- sonst
gilt ein veröffentlichtes Paket als zugewiesen.

### Entfernen mit Deinstallation

Ein echter Windows-2000-Server **löscht das Paketobjekt nicht**, wenn
die Software auch von den Clients verschwinden soll. Es bleibt stehen
und wird umgeschrieben:

| | zugewiesen | zur Deinstallation vorgemerkt |
|---|---|---|
| `msiScriptName` | `A` | `R` |
| `packageFlags` | `0xA0084C70` | `0xA0080110` |

Der Client sieht daran beim nächsten Start, dass er die Anwendung
entfernen soll. Wird das Objekt stattdessen gelöscht -- wie es diese
Umsetzung zuvor tat -- erfährt er davon nie und die Software bleibt
installiert.

Das Entfernen fragt deshalb wie im Original nach: sofort deinstallieren
(Objekt umschreiben) oder auf den Clients belassen (Objekt löschen).
Ein bereits vorgemerkter Auftrag wird in der Liste als "wird
deinstalliert" angezeigt; ihn zu entfernen löscht dann nur noch den
Auftrag selbst.

Die Flags werden von Windows vorzeichenbehaftet geschrieben
(`0xA0084C70` erscheint als `-1610068880`) -- beim Auslesen muss über
`int32_t` geparst werden, `stoul` scheitert daran.

## Schreibweise der SYSVOL-Zweige

`samba-tool gpo create` legt die Zweige als `Machine` und `User` an --
genau so stehen sie auch im `msiScriptPath` und in den Pfaden, die ein
Client anfragt. An mehreren Stellen stand im Code dagegen
`MACHINE`/`USER`. Auf einem groß-/kleinschreibungsempfindlichen
Dateisystem entsteht dadurch ein **zweites** Verzeichnis daneben, das
root gehört und das der Client nie liest. Betroffen waren die
`.aas`-Datei, `Registry.pol` und `scripts.ini` -- also praktisch alles,
was ins SYSVOL geschrieben wird. Die Namen stehen jetzt an einer Stelle
als Konstante.

## Rechte im SYSVOL

Die `.aas`-Datei und ihr `Applications`-Verzeichnis werden per
`mkdir`/`cp` als root angelegt und gehören dann `root:root` ohne
NT-ACL. Das Maschinenkonto des Clients kommt so nicht heran: der
Client meldet beim Kopieren der Skriptdatei "Fehler 3" (Pfad nicht
gefunden), obwohl die Datei existiert. Deshalb werden Besitzer, Modus
und NT-ACL anschließend vom übergeordneten Verzeichnis des GPO-Zweigs
übernommen (`samba-tool ntacl get --as-sddl` → `ntacl set`).

Dieselbe Übernahme greift beim Schreiben der `GPT.INI` durch den
Versionszähler: auch dort setzt `cp` als root Besitzer und Modus neu
und lässt die NT-ACL fallen.

Eine Ebene höher hilft nach einer Neuinstallation oder manuellen
Eingriffen `samba-tool ntacl sysvolreset`.

## Weitere Gruppenrichtlinien-Erweiterungen

Neben den Administrativen Vorlagen sind drei weitere
Client Side Extensions umgesetzt. Alle drei tragen sich bei Bedarf
selbst in `gPCMachineExtensionNames`/`gPCUserExtensionNames` des GPOs
ein -- ohne diesen Eintrag würde ein echter Client die Erweiterung nie
aufrufen, selbst wenn die Einstellungen vorhanden sind.

- **Softwareinstallation** (nach [MS-GPSI]): legt unterhalb des
  skopierten GPO-Zweigs `CN=Class Store` und darunter `CN=Packages` an,
  **beide als `classStore`**. Das ist vom Schema vorgegeben: unterhalb
  eines `classStore` sind laut `possSuperiors` nur
  `packageRegistration`, `typeLibrary`, `classRegistration`,
  `categoryRegistration` und `classStore` erlaubt -- ein gewöhnlicher
  `container` wird mit "Naming violation (64)" abgelehnt. "Durchsuchen..." startet im
  zuletzt benutzten Verzeichnis (sonst `/srv/freigaben`) und schlägt
  nach der Auswahl den UNC-Pfad vor -- dazu wird in der `smb.conf` die
  Freigabe gesucht, unter der die Datei liegt (bei verschachtelten
  Freigaben gewinnt die längste Übereinstimmung). legt ein
  `packageRegistration`-Objekt per LDAP in AD an und schreibt die
  zugehörige `.aas`-Datei ins SYSVOL. Die nötigen Objektklassen sind
  Teil des Standard-AD-Schemas und bei Samba bereits vorhanden.
- **Skripte** (nach [MS-GPSCR]): An-/Abmeldung für die Benutzer-,
  Start/Herunterfahren für die Computerkonfiguration, je eine
  `scripts.ini` pro Zweig (UTF-16LE mit BOM, durchnummerierte
  `CmdLine`/`Parameters`-Paare).
- **Ordnerumleitung** (nach [MS-GPFR] "Version Zero", der einzigen
  Version, die Windows 2000 kennt, und der Oberfläche aus `fde.dll`):
  Ordnerknoten Anwendungsdaten, Desktop, Eigene Dateien (mit Eigene
  Bilder) und Startmenü. Eigenschaften mit den Reitern "Ziel" (keine
  Richtlinie / Standard mit einem Zielpfad für alle / Erweitert mit
  Pfaden je Sicherheitsgruppe / bei Eigene Bilder "Dem Ordner Eigene
  Dateien folgen") und "Einstellungen" (exklusive Zugriffsrechte, Inhalt
  verschieben, Verhalten beim Entfernen der Richtlinie, Eigene Bilder
  unterordnen). Gespeichert in `User\Documents & Settings\fdeploy.ini`:
  `[FolderStatus]` mit den Flags hexadezimal (0x01 verschieben, 0x02
  folgen, 0x08 erweitert, 0x10 exklusiv, 0x20 beim Entfernen
  zurückleiten) und je Ordner ein Abschnitt `SID=Pfad` (Standard:
  `S-1-1-0`). Die frühere Fassung schrieb `[Folder Status]` ohne
  Pfadabschnitte und leitete stattdessen über "User Shell
  Folders"-Werte in der `Registry.pol` um -- diese Werte werden beim
  nächsten Speichern entfernt.

## Kodierung der ADM-Dateien

ADM-Vorlagen liefert Microsoft sowohl in ANSI als auch in UTF-16 aus.
Der Parser erkennt die Kodierung selbst -- über die
Bytereihenfolge-Markierung, ersatzweise über die Verteilung der
Nullbytes -- und wandelt vor dem Zerlegen nach UTF-8.

Ohne das verschwindet eine UTF-16-kodierte Datei stillschweigend: hinter
jedem Zeichen steht ein Nullbyte, der Tokenizer findet kein einziges
`CATEGORY` und der Editor zeigt einen leeren Baum. In der Praxis fehlte
dadurch die gesamte `system.adm` (Desktop, Startmenü, Systemsteuerung,
System, Netzwerk, Drucker), während die ANSI-kodierte `inetres.adm`
daneben sauber durchlief -- also genau die Art Fehler, die aussieht wie
"da fehlt noch was" statt wie ein Fehler.

## Versionszähler

Jede Änderung an einem GPO erhöht dessen Versionszähler, und zwar an
beiden Stellen: im AD-Attribut `versionNumber` und in der `GPT.INI` im
SYSVOL, die denselben Wert bekommt. Das obere Halbwort zählt die
Benutzer-, das untere die Computerkonfiguration.

Das ist nicht optional: ein Client merkt sich pro GPO die zuletzt
verarbeitete Version und überspringt es beim nächsten Start
vollständig, wenn sie unverändert ist. Wurde ein GPO also einmal leer
verarbeitet und danach ein Paket hinzugefügt, ohne die Nummer zu
erhöhen, passiert nie wieder etwas -- egal wie oft neu gestartet wird.
Genau das ist in der Praxis aufgetreten: der Zähler wurde nur beim
Speichern im Editor der administrativen Vorlagen erhöht, nicht bei
Softwareinstallation, Skripten oder Ordnerumleitung, und das
AD-Attribut gar nicht.

Schlägt das Schreiben in AD fehl, bleibt die `GPT.INI` absichtlich
unverändert, damit beide Stellen zusammenpassen.

LDAP-Schreibzugriffe laufen über `ldapadd`/`ldapmodify` gegen den
lokalen Samba-DC und brauchen -- wie GPOs selbst -- echte
Administrator-Anmeldedaten; root allein genügt dafür nicht.

Diese Werkzeuge stecken im Paket `ldap-utils`, das auf einem frischen
Debian fehlt. `dsadmin` prüft vor dem ersten LDAP-Zugriff, ob sie
vorhanden sind, und bietet die Installation an -- sonst scheitert die
erste GPO-Änderung mit einer nichtssagenden `env`-Meldung. `dcpromo`
installiert das Paket inzwischen gleich bei der Heraufstufung mit.

## Löschen von Gruppenrichtlinienobjekten

"Entfernen" löst -- wie im Original -- nur die Verknüpfung; das Objekt
selbst bleibt bestehen. Dadurch sammeln sich mit der Zeit verwaiste
GPOs an. Die zusätzliche Schaltfläche "Löschen..." entfernt das Objekt
vollständig: erst wird die Verknüpfung im aktuellen Container gelöst
(sonst bliebe in `gPLink` ein Verweis auf ein Objekt stehen, das es
nicht mehr gibt), dann löscht `samba-tool gpo del` das AD-Objekt samt
SYSVOL-Verzeichnis. Die Rückfrage weist ausdrücklich darauf hin, dass
das auch andere Container betrifft und dass "Entfernen" die richtige
Wahl ist, wenn nur die Verknüpfung weg soll.

## Verknüpfungsreihenfolge

Die Schaltflächen "Nach oben"/"Nach unten" im Gruppenrichtlinie-Reiter
verschieben eine Verknüpfung innerhalb der Liste. `samba-tool` kennt
dafür keinen Befehl (`gpo setlink` hängt nur an, `gpo dellink`
entfernt), deshalb wird das `gPLink`-Attribut des Containers direkt per
LDAP gelesen, umsortiert und komplett zurückgeschrieben. Die
Optionsflags jeder einzelnen Verknüpfung (`;0`, `;1` ...) bleiben dabei
erhalten.

Geklärt (am Samba-Quelltext, `samba/gp/gpclass.py` und
`samba/netcmd/gpo.py`): Die Blöcke in `gPLink` werden von vorn nach
hinten verarbeitet, Späteres überschreibt Früheres -- die **höchste
Priorität hat also der letzte Block**. `samba-tool gpo setlink` stellt
neue Verknüpfungen vorne an, eine neue Verknüpfung bekommt damit wie im
Original die niedrigste Priorität. Der Gruppenrichtlinie-Reiter zeigt
die Liste deshalb umgekehrt an: oben steht, was zuletzt in `gPLink`
steht, und "Nach oben" bedeutet "höhere Priorität".

## Hauptfenster: Werkzeugleiste und Menü "Vorgang"

Wie im Original: Zurück/Vor (Verlauf der geöffneten Container), Ebene
nach oben, Struktur anzeigen/ausblenden, Eigenschaften (markiertes
Objekt, sonst der geöffnete Container), Aktualisieren, Liste exportieren
(Tabstopp- oder kommagetrennt), Hilfe, dann die Snap-in-Knöpfe Neuer
Benutzer, Neue Gruppe, Neue Organisationseinheit, Suchen und Zu Gruppe
hinzufügen. Die Snap-in-Symbole unter `res/dsa` sind vorläufig, aus den
vorhandenen Symbolen zusammengesetzt.

Das Menü "Vorgang" bietet dieselben Aktionen samt "Neu"; Einträge, die
ein markiertes Objekt brauchen, sind sonst grau.

- **Neu**: Computer, Kontakt, Gruppe, Organisationseinheit, Benutzer,
  Freigegebener Ordner (Reihenfolge des deutschen Originals). Kontakt
  (`objectClass: contact`, vollständiger Name setzt sich aus Vorname,
  Initialen und Nachname zusammen) und Freigegebener Ordner
  (`objectClass: volume` mit `uNCName`) werden per LDAP angelegt; Namen
  werden für die DN nach RFC 4514 maskiert.
- **Suchen** ("Benutzer, Kontakte und Gruppen suchen"): Name
  (cn/sAMAccountName/displayName) und Beschreibung als Teilstring, über
  ldapi, Filterwerte nach RFC 4515 maskiert; Enter startet die Suche,
  Doppelklick auf einen Treffer öffnet dessen Eigenschaften.
- **Zu Gruppe hinzufügen**: für markierte Benutzer, Computer und
  Gruppen über die Objektauswahl, geschrieben als `add: member` auf den
  gewählten Gruppen.

Die Liste zerlegt DNs jetzt maskierungsfest: Objekte mit Komma im Namen
("Meier, Hans" -- als `CN=Meier\, Hans`) wurden vorher gar nicht
angezeigt, weil am ersten Komma getrennt wurde.

## Eigenschaften einer Gruppe

Doppelklick oder "Eigenschaften" öffnet wie im Original vier Reiter;
geschrieben wird erst mit OK/Übernehmen:

- *Allgemein*: Gruppenname (Prä-Windows 2000), Beschreibung, E-Mail,
  Gruppenbereich (Lokal in Domäne/Global/Universal) und Gruppentyp
  (Sicherheit/Verteilung) über `groupType`, Anmerkungen (`info`, mit
  CRLF). Bei vordefinierten Gruppen (Builtin) sind Bereich und Typ
  gesperrt. Bereich/Typ werden vor den Mitgliedern geschrieben, damit
  eine von AD abgelehnte Umwandlung auffällt, bevor sich etwas anderes
  ändert.
- *Mitglieder*: Benutzer, Computer und Gruppen mit Active
  Directory-Ordner; Hinzufügen über die Objektauswahl, Entfernen mit
  Rückfrage. Geschrieben als ein LDAP-Modify mit `add: member` /
  `delete: member` auf der Gruppe -- DNs statt Anmeldenamen, damit
  Computerkonten und Namen mit Sonderzeichen ohne Umweg funktionieren.
- *Mitglied von*: ändert das `member`-Attribut der jeweils anderen
  Gruppe. Nach einem Teilfehler wird der echte Stand neu gelesen.
- *Verwaltet von*: dasselbe Panel wie bei Organisationseinheiten und
  der Domäne (`ManagedByPanel`).

Wie bei Benutzern führen Mitgliederlisten keine Mitgliedschaft über die
primäre Gruppe (`primaryGroupID`) -- das Original zeigt sie dort auch
nicht.

## Anzeigename vs. Anmeldename

Der Anzeigename eines Objekts (CN, z.B. "Max Mustermann") und sein
Anmeldename (sAMAccountName, z.B. "mmustermann") können sich
unterscheiden. `dsadmin` führt beide getrennt (`accountName`-Feld) --
ermittelt über einen `samba-tool ... list --full-dn`-Abgleich statt
über einen reinen Namensvergleich, der bei abweichenden CNs sonst
fehlschlagen würde.

## GPOs brauchen echte Administrator-Anmeldedaten

`CN=Policies,CN=System` ist besonders geschützt: Weder root noch das
Maschinenkonto des Domänencontrollers dürfen dort schreiben --
genau wie im echten AD dürfen nur Domain Admins GPOs anlegen. Beim
ersten GPO-Schreibzugriff (Neu/Hinzufügen/Entfernen) fragt `dsadmin`
deshalb einmalig nach Administrator-Anmeldedaten und cacht sie für
die laufende Sitzung. **Lesen** (GPO-Liste, Verknüpfungen anzeigen)
funktioniert dagegen problemlos ohne das.

## Bauen
```sh
cd dsadmin
make
./dsadmin
```

## Fehlermeldungen von samba-tool

`samba-tool` schreibt vor der eigentlichen Meldung seitenweise Rauschen
-- registrierte GENSEC-Backends, lmhosts-Versuche, Schema-Hinweise, die
Warnung über Kennwörter auf der Kommandozeile. Im Fehlerdialog
erschlägt das die eine Zeile, auf die es ankommt, deshalb werden diese
Zeilen herausgefiltert. Besteht die Ausgabe ausnahmsweise nur aus
solchen Zeilen, wird sie ungefiltert angezeigt, damit nie etwas
verlorengeht.

Ein Fall wird eigens behandelt: "A GPO already existing with name".
Legt man ein Gruppenrichtlinienobjekt unter einem Namen an, den es
schon gibt, erklärt der Dialog das und bietet an, das vorhandene Objekt
mit dem Container zu verknüpfen.

Vorbeugend fragt "Entfernen" wie im Original nach, was gemeint ist:
nur die Verknüpfung lösen (Vorgabe) oder das Objekt dauerhaft löschen.
Beim dauerhaften Löschen folgt eine zweite Rückfrage, weil dabei auch
alle Verknüpfungen zu anderen Containern verschwinden.

## Bekannte Grenzen
- Objekte werden immer in dem Container angelegt, der im Baum markiert
  ist -- auch beim Rechtsklick auf einen anderen Knoten wird dieser
  zuerst zum aktuellen Container gemacht. (FOX löst bei
  `setCurrentItem()` kein `SEL_CHANGED` aus; ohne das ausdrückliche
  Nachziehen landeten Benutzer, Gruppen und Computer still im zuvor
  angeklickten Container.)
- Organisationseinheiten unterhalb eines ausgeblendeten Containers
  erscheinen nicht im Baum; die DN-Zerlegung trennt an Kommas und
  behandelt maskierte Kommas in einem RDN nicht.
- Umsortieren der Verknüpfungen und die Sammeländerung im Editor sind
  bisher nur kompiliert und mit Einzeltests der Zerlegungs-/
  Sortierlogik geprüft, noch nicht gegen eine laufende Domäne.
- Bekannte, ungelöste Einschränkung aus dem Testen: Das Eingabefeld
  für einen neuen GPO-Namen (aus dem bereits modalen Eigenschaften-
  Dialog heraus geöffnet) nahm in der Xvfb-Testumgebung ohne
  Fenstermanager keinen Tastaturfokus an -- noch nicht auf einem
  echten System mit Fenstermanager verifiziert.
