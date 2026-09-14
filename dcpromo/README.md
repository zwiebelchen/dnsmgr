# dcpromo -- Assistent zum Installieren von Active Directory für ice2k

Ein Nachbau des Windows-2000-`dcpromo`-Assistenten für
[ice2k](https://github.com/comdlg32/ice2k). Gebaut mit demselben
FOX-Toolkit-Muster wie `dnsmgr`/`dhcpmgr`/`compmgmt`. Backend: **Samba
als AD-Domain-Controller** (`samba-tool domain provision`).

![Willkommen-Seite](../docs/dcpromo/screenshots/screenshot-willkommen.png)

## Umfang -- bewusst nur der häufigste Fall

Dieser Assistent bildet **nur** "Domänencontroller für eine neue
Domäne" + "Neue Domänenstruktur erstellen" + "Neue Gesamtstruktur aus
Domänenstrukturen erstellen" ab -- die mit Abstand häufigste
Kombination beim Original. Bewusst (noch) nicht unterstützt, aber
**nicht endgültig ausgeschlossen** für später:
- "Zusätzlicher Domänencontroller für eine bestehende Domäne"
  (bräuchte laufende Replikation gegen einen erreichbaren DC)
- "Untergeordnete Domäne" / "Gesamtstruktur beitreten" (Trust-
  Beziehungen zwischen mehreren Domänen)

Ebenfalls weggelassen: individuelle Pfade für Datenbank/Protokolldatei/
SYSVOL (Windows-NTFS-Pfade wie `C:\WINNT\NTDS` ergeben unter Linux
keinen Sinn -- Samba nutzt seine eigenen sinnvollen Standardpfade) und
ein separates DSRM-Kennwort (Samba hat kein echtes Äquivalent zum
Verzeichnisdienste-Wiederherstellungsmodus).

## Der Kompromiss: Windows-2000-kompatibel vs. moderne AD-Integration

Windows 2000 selbst kannte das AD-integrierte DNS-Speichermodell
("DomainDnsZones"-Partition), das für die direkte BIND9-DLZ-
Integration nötig ist, noch nicht -- das kam erst mit Windows Server
2003. Der Assistent bietet deshalb zwei Wege an:

| | Windows-2000-kompatibel | Moderne AD-Integration |
|---|---|---|
| Funktionsebene | 2000 | 2003 |
| DNS-Backend | Sambas eigener Server (`SAMBA_INTERNAL`) | BIND9 via DLZ-Modul |
| Wer hat Port 53? | Samba (Pflicht für AD-Clients) | BIND9 |
| `dnsmgr`s andere Zonen | über `dns forwarder` (BIND9 auf Port 5353) | BIND9 bleibt alleiniger Port-53-Server |

Beide Wege wurden Ende-zu-Ende getestet und funktionieren
nebeneinander mit den von `dnsmgr` verwalteten Zonen.

## Migration: "Windows-2000-Kompatibilität aufheben"

Wurde die Domäne Windows-2000-kompatibel angelegt, lässt sich später
per Knopfdruck auf die moderne AD-Integration wechseln (**nicht
umgekehrt** -- dieser Schritt ist einseitig, wie im Original das
Anheben einer Funktionsebene):
1. `samba-tool domain level raise --domain-level=2003 --forest-level=2003`
2. `samba_upgradedns --dns-backend=BIND9_DLZ`
3. `smb.conf`: `dns forwarder` entfernen, `server services` ohne `dns`
4. BIND9 auf die DLZ-Integration umstellen (Port 53, Keytab, passendes
   `dlz_bind9_XX.so` für die installierte BIND-Version)

Der Assistent erkennt beim Start automatisch, ob schon eine Domäne
existiert (liest `smb.conf`), und zeigt dann eine Status-Seite mit
diesem Migrations-Knopf statt erneut zu provisionieren.

## Bauen
```sh
cd dcpromo
make
./dcpromo
```
Voraussetzung: `samba`, `samba-ad-provision`, `samba-dsdb-modules`,
`samba-vfs-modules`, `winbind` und `bind9` installiert.

## Bekannte Grenzen
- Kein echtes Fortschritts-Streaming während `samba-tool domain
  provision` läuft (kann je nach System spürbar dauern) -- das
  Protokoll erscheint erst, wenn der Befehl fertig ist.
- Dienste-Neustart über `systemctl` -- auf Systemen ohne systemd
  (z.B. reine Testcontainer) muss man `bind9`/`samba-ad-dc` danach
  manuell starten.
- Kein "Domäne wieder entfernen" (`dcpromo /forceremoval`-Äquivalent).
