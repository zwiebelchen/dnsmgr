# secpol -- Sicherheitsrichtlinien

Nachbau der drei Sicherheitsrichtlinien-Konsolen aus "Start → Programme
→ Verwaltung" von Windows 2000 Server:

| Aufruf | Menüpunkt | Gruppenrichtlinienobjekt |
|---|---|---|
| `secpol --domain` | Sicherheitsrichtlinie für Domänen | Default Domain Policy |
| `secpol --dc` | Sicherheitsrichtlinie für Domänencontroller | Default Domain Controllers Policy |
| `secpol --local` (Vorgabe) | Lokale Sicherheitsrichtlinie | lokale Sicherheitsdatenbank des Servers |

Alle drei zeigen denselben Zweig "Sicherheitseinstellungen" wie der
Gruppenrichtlinien-Editor in `dsadmin` -- Konto-, Kerberos-,
Überwachungs- und Ereignisprotokoll-Richtlinien, Benutzerrechte,
Sicherheitsoptionen, eingeschränkte Gruppen, Systemdienste,
Registrierung und Dateisystem --, nur fest auf ein
Gruppenrichtlinienobjekt gerichtet und ohne den Rest des Baums. Der
Wurzelknoten nennt das jeweilige Ziel.

Die Gruppenrichtlinienobjekte werden über ihren Anzeigenamen gesucht
("Default Domain Policy" bzw. "Default Domain Controllers Policy"); nur
falls das fehlschlägt, greifen die bekannten festen GUIDs.

## Lokale Sicherheitsrichtlinie

Wie im Original lässt sie sich auch auf einem Domänencontroller öffnen
und bearbeiten. Die Liste hat dieselben zwei Spalten wie dort:

- **Lokale Einstellung** -- was hier auf dem Server eingestellt ist
- **Effektive Einstellung** -- was tatsächlich gilt, also die lokale
  Einstellung, überschrieben von allen Gruppenrichtlinien, die auf
  diesen Computer wirken (aktive Verknüpfungen an der Domänenwurzel und
  an der Organisationseinheit "Domain Controllers", in der Reihenfolge
  ihrer Priorität)

Der Bearbeiten-Dialog zeigt oben die effektive Einstellung zum Ansehen,
darunter die lokale zum Ändern, und weist darauf hin, dass Richtlinien
auf Domänenebene die lokalen überschreiben.

Windows hält die lokale Richtlinie in `secedit.sdb`. Hier tritt an deren
Stelle `/var/lib/ice2k/secpol/local.inf` im selben INF-Format wie die
Sicherheitsvorlagen der Gruppenrichtlinien -- so arbeiten dieselben
Dialoge damit.

**Einschränkung:** Die lokalen Werte werden gespeichert und angezeigt,
aber noch nicht auf das Linux-System angewendet. Für Domänenkonten
zählt ohnehin die Domänenrichtlinie (die `dsadmin` an Samba
weitergibt); eine Übersetzung der lokalen Werte nach PAM, `login.defs`
und Co. gibt es noch nicht.

## Bauen

Dasselbe Programm wie `dsadmin`, nur mit einem anderen Einstiegspunkt
(`-DSECPOL_BUILD`); die Quellen liegen in `../dsadmin`:

```sh
cd secpol && make && ./secpol --domain
```
