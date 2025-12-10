# Network Scanner v8.1

Scanner di rete multi-thread sviluppato in Python per la scoperta di host, scansione porte (TCP/UDP) e fingerprinting passivo del sistema operativo. Progettato per scopi educativi e amministrazione di rete autorizzata.

## 👥 Team

<table>
  <tr>
    <td align="center">
      <a href="https://github.com/MS-0x404">
        <img src="https://github.com/MS-0x404.png" width="100px;" alt=""/><br />
        <sub><b>msfire</b></sub>
      </a><br />
      <a href="#" title="Code">💻</a>
    </td>
    <td align="center">
      <a href="https://github.com/thevirtueye">
        <img src="https://github.com/thevirtueye.png" width="100px;" alt=""/><br />
        <sub><b>Alberto</b></sub>
      </a><br />
      <a href="#" title="Documentation">📖</a>
    </td>
    <td align="center">
      <a href="https://github.com/ANTHr0p1c">
        <img src="https://github.com/ANTHr0p1c.png" width="100px;" alt=""/><br />
        <sub><b>ANTHr0p1c</b></sub>
      </a><br />
      <a href="#" title="Documentation">📖</a>
    </td>
    <td align="center">
      <a href="https://github.com/Neniku">
        <img src="https://github.com/Neniku.png" width="100px;" alt=""/><br />
        <sub><b>Neniku</b></sub>
      </a><br />
      <a href="#" title="Documentation">📖</a>
    </td>
    <td align="center">
      <a href="https://github.com/M4nu3lR1cc1">
        <img src="https://github.com/M4nu3lR1cc1.png" width="100px;" alt=""/><br />
        <sub><b>M4nu3lR1cc1</b></sub>
      </a><br />
      <a href="#" title="Documentation">📖</a>
    </td>
  </tr>
</table>

## Funzionalita

- **Scoperta Host**: Scansione ARP + deep discovery TCP per rilevamento affidabile
- **Scansione Porte**: Modalita' TCP Connect e UDP
- **Fingerprinting OS**: Rilevamento tramite TTL (ping)
- **Risoluzione Hostname**: DNS + NetBIOS + query al gateway locale
- **Liste Porte Intelligenti**: Top 20 porte separate per protocolli TCP e UDP
- **Monitoraggio Progresso**: Barra di avanzamento in tempo reale con stima del tempo
- **Generazione Report**: Risultati salvati in `analysis.txt`

## Requisiti

- **Sistema Operativo**: Windows o Linux
- **Python**: 3.x
- **Privilegi**: Root richiesto solo su Linux (`sudo`). Su Windows funziona senza privilegi di amministratore.

## Installazione

```bash
pip install -r requirements.txt
```

**Dipendenze:**
- `scapy` - Scoperta ARP e scansione UDP
- `tqdm` - Visualizzazione barra di progresso

## Struttura del Progetto

```
├── main.py              # Punto di ingresso, interfaccia utente
├── requirements.txt     # Dipendenze
├── analysis.txt         # Report di output (generato dopo la scansione)
└── libs/
    ├── scanner.py       # Logica scansione porte
    ├── network.py       # Scoperta host (ARP + TCP)
    └── report.py        # Generazione file report
```

## Utilizzo

Avvia lo scanner:

```bash
# Windows
python main.py

# Linux
sudo python3 main.py
```

### Menu Interattivo

1. **Selezione Target**
   - IP singolo: `192.168.1.1`
   - Sottorete: `192.168.1.0/24`

2. **Modalita' Scansione**
   - `1` TCP Scan
   - `2` UDP Scan
   - `3` Full Scan (TCP + UDP)

3. **Selezione Porte**
   - `1` Top common ports (20 TCP, 20 UDP, o 40 per Full Scan)
   - `2` Tutte le porte (1-65535)
   - `3` Range personalizzato (es. `22,80,443` o `1-1000`)

### Top Ports

**TCP (20 porte):**
```
21, 22, 23, 25, 53, 80, 110, 135, 139, 389, 443, 445, 1433, 3306, 3389, 5432, 5900, 8080, 8443, 27017
```

**UDP (20 porte):**
```
53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520, 1194, 1900, 4500, 5353, 11211, 1701, 4789, 33434
```

## Esempio di Output

**Console:**
```
====================================================================================================
  IP                   HOSTNAME                       PORT                 STATE           OS
====================================================================================================
# 192.168.1.1          router                         22/TCP               Open            Linux/Unix
  192.168.1.1          router                         80/TCP               Open            Linux/Unix
# 192.168.1.100        PC-Windows                     135/TCP              Open            Winzoz
  192.168.1.100        PC-Windows                     445/TCP              Open            Winzoz
====================================================================================================
```

**analysis.txt:**
```
[SCAN REPORT - v7.2]
====================================================================================================
Target: 192.168.1.0/24
Scan Type: TCP
Ports: Top common ports (TCP)
====================================================================================================
  IP                   HOSTNAME                       PORT                 STATE           OS
====================================================================================================
# 192.168.1.1          router                         22/TCP               Open            Linux/Unix
...
====================================================================================================
Timestamp: 2025-12-03 15:30:00
```

## Scorciatoie da Tastiera

- `CTRL+C` - Ferma la scansione ed esce immediatamente

## Risoluzione Problemi

### Nessun Host Trovato
- Assicurati di eseguire come Amministratore/Root (su Linux)
- Controlla che il firewall non blocchi i pacchetti ARP
- Prova prima a scansionare un singolo IP

### La Scansione UDP e' Lenta
- La scansione UDP richiede di attendere i timeout
- Usa meno thread (20) per stabilita'
- Considera l'uso della scansione TCP per risultati piu' veloci

### Errori di Permessi
- Windows: Non dovrebbero esserci problemi
- Linux: Usa `sudo python3 main.py`

## Disclaimer
Questo strumento e' solo per scopi educativi e test autorizzati. Non scansionare reti senza il permesso esplicito del proprietario. L'autore non e' responsabile per qualsiasi uso improprio.
