netmon

Monitor di rete per macOS. Cattura il traffico delle interfacce, associa ogni connessione al processo che l’ha generata, prova a dare un nome alle destinazioni e segnala comportamenti anomali. Osserva, non blocca.

Cosa fa
cattura pacchetti con libpcap, un thread per interfaccia;
decodifica IPv4 con Scapy, ricava IP, porte, protocollo, lunghezza;
attribuisce il PID con psutil, usando la tabella dei socket;
ricava i nomi di dominio dalle risposte DNS in chiaro e dall’SNI (in sviluppo);
salva tutto in SQLite;
mostra statistiche, avvisi e una classifica di telemetria in una TUI.
Requisiti
macOS, Python 3.10+
privilegi di root (libpcap e net_connections li richiedono)
dipendenze: pylibpcap, scapy, psutil
bash
pip install pylibpcap scapy psutil
Avvio
bash
sudo $(which python3) main.py

Un solo terminale. Log in netmon.log.

Comandi
Tasto	Azione
1 2 3 4 / Tab	cambia vista
frecce	scorre la lista
s	avvia o ferma la cattura (vista 2)
Invio	dettaglio app (vista 4)
Esc / Backspace	torna alla lista
q	esce
Viste
Statistiche: pacchetti e byte per direzione, top processi e domini in uscita.
Interfacce: stato di cattura per ciascuna interfaccia en*.
Avvisi: quiet (processo che non dovrebbe comunicare), new (destinazione mai vista), volume (troppi byte in una finestra).
Telemetria: classifica delle app per punteggio, con destinazioni e tracker.

Il punteggio ordina le app, non le giudica.

Struttura
main.py          avvio, TUI, thread
model/           dati: db, packets, intel, alerts, telemetria
capture/         cattura e analisi: monitor, registry, analyzer, procmap
detect/          regole di rilevamento
tui/             viste (testo) e controller (tasti)
config.py        tutti i default

Il flusso: Monitor → coda → Analyzer → SQLite → viste e rilevamento.

Liste di domini

La tabella intel contiene domini di tracker e telemetria, caricati da file. Il match è per suffisso: x.a.example.com corrisponde a example.com.

bash
mkdir -p intel
curl -sL https://v.firebog.net/hosts/Easyprivacy.txt -o intel/easyprivacy.txt
python3 -c "import model.db as db, model.intel as intel; c = db.connect('test_db.db'); intel.init(c); print(intel.load(c, 'intel/easyprivacy.txt', 'tracker', 'easyprivacy'))"
Limiti
Il nome di dominio c’è solo se passa un DNS in chiaro o un SNI visibile. Con DNS over HTTPS e ECH resta l’IP.
Il traffico cifrato non viene letto: si sa a chi, non cosa.
Le connessioni UDP senza destinazione fissa sono attribuite per porta, quindi l’attribuzione può essere ambigua.
Connessioni più brev, di un secondo circa, possono risultare Unknown.
IPv6 non è ancora analizzato.
Le liste di dominio hanno falsi positivi e invecchiano: vanno riscaricate.
Dati

Un file SQLite, test_db.db, con cinque tabelle: packets, intel, alerts, pairs, meta. Non è incluso nel repository, come netmon.log e intel/.

Test
bash
python3 -m pytest tests/
