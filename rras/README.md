# rras -- Routing und RAS

Nachbau des Snap-Ins "Routing und RAS" von Windows 2000 Server.

## Aufbau

Wie im Original: links der Baum mit "Routing und RAS", darunter
"Serverstatus" und der lokale Server, rechts der Startbildschirm bzw.
die Serverstatusliste mit den Spalten Servername, Servertyp, Status,
Verwendete Ports, Ports gesamt und Betriebszeit. Das Kontextmenü des
Servers bietet "Routing und RAS konfigurieren und aktivieren",
"Routing und RAS deaktivieren" (jeweils nur das gerade Sinnvolle),
Aktualisieren und Eigenschaften.

## Was umgesetzt ist

- **Konfigurieren und aktivieren**: Der Dialog bietet dieselben
  Serverrollen wie der Assistent des Originals. Umgesetzt sind
  "Netzwerkrouter" und "Manuell konfigurierter Server" -- beide schalten
  die IP-Weiterleitung des Kernels ein, sofort per
  `sysctl -w net.ipv4.ip_forward=1` und dauerhaft über
  `/etc/sysctl.d/99-ice2k-rras.conf`.
- **Deaktivieren** schaltet sie wieder ab.
- **Eigenschaften**, Reiter "Allgemein": Router an/aus sowie "Nur
  lokales Netzwerk (LAN-Routing)" bzw. "LAN- und Einwählrouting".
- **Serverstatus**: Servername, Betriebssystem als Servertyp und der
  Status ("Gestartet" bzw. "Beendet (nicht konfiguriert)").
- **Knoten unterhalb des Servers**, sobald Routing und RAS aktiv ist:
  - *Routingschnittstellen*: die Netzwerkschnittstellen des Servers mit
    Typ, Status und Verbindungsstatus (aus `ip link`)
  - *Ports*: noch leer -- Einwähl- und VPN-Anschlüsse fehlen
  - *IP-Routing → Allgemein*: Schnittstellen mit IP-Adresse,
    Verwaltungs- und Betriebsstatus (aus `ip addr`)
  - *IP-Routing → Statische Routen*: die Routingtabelle (aus
    `ip route`), Rechtsklick legt eine Route an oder löscht sie
- **VPN-Server**: Die Rolle "VPN-Server" des Assistenten fragt danach,
  welcher Dienst die Aufgabe übernimmt -- Windows 2000 hat hier PPTP und
  L2TP/IPSec:
  - *WireGuard*: wird vollständig eingerichtet -- Schlüsselpaar erzeugt,
    `/etc/wireguard/<Name>.conf` geschrieben, `wg-quick@<Name>` aktiviert;
    der öffentliche Schlüssel des Servers wird angezeigt. Clients werden
    als `[Peer]`-Abschnitte ergänzt.
  - *OpenVPN*: schreibt `/etc/openvpn/server/<Name>.conf`. Zertifikate
    (ca.crt, server.crt, server.key, dh.pem) legt die Konsole **nicht**
    an; fehlen sie, sagt sie das und startet den Dienst nicht.
  - *strongSwan*: schreibt `/etc/swanctl/conf.d/<Name>.conf` (IKEv2 mit
    Adresspool). Zertifikate und Benutzer müssen vorhanden sein.
  - Der Knoten *Ports* zeigt den eingerichteten Dienst mit seinem Zustand
    und bei WireGuard zusätzlich die Peers.
- **Paketfilter** je Schnittstelle (Rechtsklick auf eine Schnittstelle →
  "Eingabefilter..." / "Ausgabefilter..."), Dialoge nach `rtrfiltr.dll`:
  "Alle Pakete empfangen/übertragen, mit Ausnahme..." bzw. "Alle Pakete
  verwerfen, mit Ausnahme...", darunter die Filterliste mit
  Quelladresse/-maske, Zieladresse/-maske, Protokoll und Ports. Die
  Filter stehen in `/etc/ice2k/rras-filters`; daraus entsteht
  `/etc/ice2k/rras-filter.nft` (Tabelle `inet ice2k_rras`), das mit
  `nft -f` geladen wird.
- **Statische Routen** werden sofort gesetzt (`ip route add`) und in
  `/etc/ice2k/rras-routes` gemerkt; beim nächsten "Konfigurieren und
  aktivieren" werden sie wieder gesetzt, da der Kernel Routen beim
  Neustart vergisst. Eine eigene systemd-Unit dafür gibt es noch nicht.

Die gewählte Rolle merkt sich `/etc/ice2k/rras.conf`.

## Was noch fehlt

- Einwählserver (Modem/ISDN), RAS-Richtlinien und Protokollierung.
- VPN-Clientverwaltung: Peers bzw. Benutzer werden noch nicht über die
  Oberfläche angelegt (bei WireGuard also keine Peer-Verwaltung).
- Die Paketfilter kennen nur IPv4 und werden beim Systemstart erst mit
  "Konfigurieren und aktivieren" wieder geladen; eine eigene
  systemd-Unit dafür fehlt.
- Adressumsetzung (Internetverbindungsserver) und Firewallregeln.
- Routingprotokolle (RIP, OSPF) -- unter Linux wäre FRR der
  naheliegende Unterbau.
- Adressumsetzung (NAT) für den Internetverbindungsserver.
- "LAN- und Einwählrouting" unterscheidet sich derzeit nur im
  gespeicherten Zustand, solange es keine Einwahl gibt.

## Abgleich mit dem Original

Texte und Symbole stammen aus der deutschen `mprsnap.dll` (Windows 2000
SP4, 5.00.2195.6609; die DLL selbst liegt nicht im Repository):

- Startbildschirme "Willkommen" (291) und "Den Routing- und RAS-Server
  konfigurieren" (300-302)
- Zustandstexte "Gestartet" (105), "Beendet" (102) und
  "%s (nicht konfiguriert)" (97), Spalten der Serverstatusliste (45-49,
  91), Menüeintrag "Routing und RAS deaktivieren" (59)
- Setup-Assistent mit den fünf Serverrollen und ihren Beschreibungen
  (Dialog 12611)
- Eigenschaften, Reiter "Allgemein" (Dialog 12517): "Diesen Computer
  aktivieren als:", "Router", "Nur LAN-Routing", "LAN und bei Bedarf
  wählendes Routing", "RAS-Server"
- Symbole unter `res/rras`: Wurzel, Serverstatus sowie der Server in den
  Zuständen gestartet/beendet -- der Knoten wechselt sein Symbol wie im
  Original

`iprtrmgr.dll` (IP-Routerverwaltung) enthält nur vier Texte und keine
Dialoge, `mprapi.dll` gar keine Ressourcen und `rasmontr.dll` nur
netsh-Hilfetexte; daraus war nichts zu übernehmen. `RASDLG.DLL` enthält
die Dialoge des Einwahl-Clients (Verbindungen herstellen), nicht die der
Konsole. Die Dialoge des IP-Routers -- etwa "Statische Route" -- stecken
in `iprtrui.dll`, die bisher fehlt; die Beschriftungen dort sind deshalb
eigene, mit den Feldern des Originals (Schnittstelle, Ziel,
Netzwerkmaske, Gateway, Metrik). `rtrfiltr.dll` (Paketfilter) liegt vor
und ist die Vorlage für die noch fehlenden Ein-/Ausgangsfilter.

## Bauen

```sh
cd rras && make && ./rras
```
