# certsrv -- Zertifizierungsstelle

Nachbau von `certsrv.msc` aus Windows 2000 Server.

## Aufbau

Links der Baum: "Zertifizierungsstelle (Lokal: <Rechner>)", darunter die
eingerichtete Zertifizierungsstelle mit "Ausgestellte Zertifikate" und
"Gesperrte Zertifikate". Rechts die Liste mit den Spalten
Anforderungs-ID, Antragsteller, Gültig bis bzw. Sperrdatum und Status
bzw. Sperrgrund.

## Unterbau

Eine openssl-Zertifizierungsstelle unter `/etc/ice2k/ca`:

| Datei | Zweck |
|---|---|
| `ca.crt`, `private/ca.key` | Zertifikat und Schlüssel der Stelle |
| `index.txt` | Datenbank von `openssl ca` -- daraus kommen beide Listen |
| `serial`, `crlnumber` | Zähler für Zertifikate und Sperrlisten |
| `newcerts/` | jedes ausgestellte Zertifikat unter seiner Seriennummer |
| `crl.pem` | Sperrliste |
| `openssl.cnf` | Konfiguration samt Profilen für Server, Client und Benutzer |

- **Einrichten**: Name, Gültigkeit und Schlüssellänge; legt CA-Zertifikat,
  Schlüssel und Datenbank an.
- **Neues Zertifikat**: Name (CN), Verwendungszweck
  (Serverauthentifizierung, Clientauthentifizierung, Benutzer) und
  Gültigkeit. Schlüssel und Zertifikat werden anschließend angezeigt und
  lassen sich speichern -- die Stelle bewahrt den privaten Schlüssel
  **nicht** auf.
- **Zertifikat sperren**: mit Sperrgrund nach RFC 5280; danach wird die
  Sperrliste sofort neu geschrieben.
- **Sperrliste veröffentlichen** erzeugt `crl.pem` neu; CA-Zertifikat und
  Sperrliste lassen sich exportieren.

## Abgleich mit dem Original

Texte und Symbole stammen aus der deutschen `certmmc.dll` (Windows 2000
SP4; die DLL selbst liegt nicht im Repository):

- Knotennamen "Ausgestellte Zertifikate" und "Gesperrte Zertifikate"
  (Texte 17, 18), Fenstertitel "Zertifizierungsstelle (Lokal)"
  (Texte 11, 12)
- Sperrdialog "Zertifikatssperrung" mit dem Wortlaut "Sind Sie sicher,
  dass Sie das Zertifikat ... sperren möchten? Das Angeben eines Grunds
  für das Sperren ist optional." (Text 26, Dialog 326)
- Sperrgründe wortgleich: Nicht angegeben, Schlüsselkompromiss,
  Stellenkompromiss, Zuordnung geändert, Abgelöst, Vorgangsende,
  Zertifikat blockiert (Texte 150-156) -- sie erscheinen auch in der
  Liste der gesperrten Zertifikate
- Symbole unter `res/certmmc`: Zertifizierungsstelle, Zertifikat,
  Schlüssel; der Ordner stammt aus `els.dll`

## Abweichungen vom Original

- Windows kennt Zertifikatvorlagen, Anforderungen über das Netz (Web
  Enrollment, DCOM) sowie die Ordner "Ausstehende Anforderungen" und
  "Fehlgeschlagene Anforderungen". Hier werden Zertifikate direkt
  ausgestellt; diese beiden Ordner gibt es deshalb nicht.
- Kein automatisches Veröffentlichen in Active Directory und keine
  automatische Zertifikatanforderung über Gruppenrichtlinien.
- Die Sperrliste wird als Datei geschrieben; sie über HTTP oder LDAP
  bereitzustellen bleibt Handarbeit.
- Sicherung und Wiederherstellung der Zertifizierungsstelle
  (Assistenten in `certmmc.dll`) sowie Richtlinien- und
  Beendigungsmodule gibt es nicht.

## Bauen

```sh
cd certsrv && make && ./certsrv
```
