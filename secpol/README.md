# secpol -- Sicherheitsrichtlinien

Nachbau der drei Sicherheitsrichtlinien-Konsolen aus "Start → Programme
→ Verwaltung" von Windows 2000 Server:

| Aufruf | Menüpunkt | Gruppenrichtlinienobjekt |
|---|---|---|
| `secpol --domain` | Sicherheitsrichtlinie für Domänen | Default Domain Policy |
| `secpol --dc` | Sicherheitsrichtlinie für Domänencontroller | Default Domain Controllers Policy |
| `secpol --local` (Vorgabe) | Lokale Sicherheitsrichtlinie | Default Domain Controllers Policy, nur zum Ansehen |

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

Ein Domänencontroller hat unter Windows keine eigene lokale
Sicherheitsdatenbank mehr -- seine Einstellungen kommen aus den
Richtlinien der Domäne, und das Original zeigt sie deshalb grau. Hier
öffnet `--local` aus demselben Grund die Richtlinie der
Domänencontroller schreibgeschützt und verweist beim Versuch einer
Änderung auf die beiden anderen Konsolen.

## Bauen

Dasselbe Programm wie `dsadmin`, nur mit einem anderen Einstiegspunkt
(`-DSECPOL_BUILD`); die Quellen liegen in `../dsadmin`:

```sh
cd secpol && make && ./secpol --domain
```
