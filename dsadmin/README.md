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
  + eigene Organisationseinheiten
- Container-Anzeige mit Typ-Klassifizierung (Benutzer/Sicherheits-
  gruppe/Computer/Organisationseinheit/Container) und passenden Icons
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

## Gruppenrichtlinienobjekt-Editor

Der "&Bearbeiten..."-Button im Gruppenrichtlinie-Reiter öffnet den
vollständigen Editor: Baum links (Kategorien aus den zusammengeführten
`.adm`-Dateien), Liste rechts (Richtlinien mit Status). Doppelklick
öffnet Nicht konfiguriert/Aktiviert/Deaktiviert plus das passende
Eingabefeld (Checkbox/Textfeld/Zahlenfeld/Dropdown). "Speichern"
schreibt die Änderungen in die echte `Registry.pol` des GPOs unter
`/var/lib/samba/sysvol/<Domäne>/Policies/{GUID}/MACHINE/Registry.pol`
und erhöht die `GPT.INI`-Versionsnummer.

Ende-zu-Ende gegen eine echte Domäne und ein echtes GPO getestet --
alle Feldtypen (Checkbox/Text/Zahl/Dropdown), byte-genaue Verifikation
des Dateiinhalts, Rundlauf über einen kompletten Programmneustart.

Unterstützt sowohl Computer- als auch Benutzerkonfiguration (`CLASS
MACHINE`/`CLASS USER`, jeweils eigener Baum-Wurzelknoten und eigene
`Registry.pol` im SYSVOL) sowie Richtlinien mit mehreren Parts (jeder
Part bekommt sein eigenes Eingabefeld und seinen eigenen
Registry.pol-Eintrag). `GPT.INI` kodiert Computer-/Benutzer-Version
getrennt und wird beim Speichern gezielt nur für den tatsächlich
geänderten Zweig erhöht.

Bekannte Grenzen dieser Version: keine Mehrfachauswahl/Verschieben von
Richtlinien.

## Weitere Gruppenrichtlinien-Erweiterungen

Neben den Administrativen Vorlagen sind drei weitere
Client Side Extensions umgesetzt. Alle drei tragen sich bei Bedarf
selbst in `gPCMachineExtensionNames`/`gPCUserExtensionNames` des GPOs
ein -- ohne diesen Eintrag würde ein echter Client die Erweiterung nie
aufrufen, selbst wenn die Einstellungen vorhanden sind.

- **Softwareinstallation** (nach [MS-GPSI]): legt ein
  `packageRegistration`-Objekt per LDAP in AD an und schreibt die
  zugehörige `.aas`-Datei ins SYSVOL. Die nötigen Objektklassen sind
  Teil des Standard-AD-Schemas und bei Samba bereits vorhanden.
- **Skripte** (nach [MS-GPSCR]): An-/Abmeldung für die Benutzer-,
  Start/Herunterfahren für die Computerkonfiguration, je eine
  `scripts.ini` pro Zweig (UTF-16LE mit BOM, durchnummerierte
  `CmdLine`/`Parameters`-Paare).
- **Ordnerumleitung** (nach [MS-GPFR], "Version Zero" -- die einzige
  Version, die Windows 2000 beherrscht): Eigene Dateien, Eigene
  Bilder, Startmenü, Anwendungsdaten und Desktop. Der Zielpfad selbst
  läuft ganz normal über die `User Shell Folders`-Werte in der
  `Registry.pol`; zusätzlich wird eine `fdeploy.ini` geschrieben,
  bewusst nur mit dem sichersten Standard-Flag (0), da die genaue
  Bit-Bedeutung öffentlich nicht vollständig dokumentiert ist.

LDAP-Schreibzugriffe laufen über `ldapadd`/`ldapmodify` gegen den
lokalen Samba-DC und brauchen -- wie GPOs selbst -- echte
Administrator-Anmeldedaten; root allein genügt dafür nicht.

## Gruppenmitgliedschaft

"Eigenschaften" auf einer Sicherheitsgruppe öffnet eine
Mitgliederliste mit Hinzufügen/Entfernen (`samba-tool group
addmembers`/`removemembers`/`listmembers`) -- für besonders
geschützte Gruppen greift bei Bedarf derselbe Administrator-
Anmeldedaten-Fallback wie bei GPOs.

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

## Bekannte Grenzen
- Nur eine Ebene von Organisationseinheiten unter der Domänenwurzel
  wird im Baum abgebildet (keine rekursive Verschachtelung).
- Bekannte, ungelöste Einschränkung aus dem Testen: Das Eingabefeld
  für einen neuen GPO-Namen (aus dem bereits modalen Eigenschaften-
  Dialog heraus geöffnet) nahm in der Xvfb-Testumgebung ohne
  Fenstermanager keinen Tastaturfokus an -- noch nicht auf einem
  echten System mit Fenstermanager verifiziert.
