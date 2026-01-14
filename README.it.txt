Rilevamento della presenza, controllo della rete, monitoraggio dell'energia

- Rilevamento della presenza basato su connessione WiFi o ethernet dello smartphone
- Monitora e controlla* la tua rete wifi e i dispositivi connessi
- Blocca il WiFi dei tuoi figli dopo cena
- Monitora il consumo energetico dei tuoi dispositivi di rete, ad es. la TV.

Vedi e registra:
- stato della connessione internet
- velocità di upload e download internet
- stato di connessione dei dispositivi collegati
- qualità WiFi e larghezza di banda per dispositivo
- consumo energetico per dispositivo

Agisci su:
- dispositivo che va online o offline (presenza)
- cambio di larghezza di banda o link wifi del dispositivo
- rilevamento di un dispositivo sconosciuto che si connette alla rete
- allarme quando la connessione internet cade
- cambio della velocità di upload/download internet

Fai:
- invia WakeOnLan* (WOL) a un indirizzo MAC
- blocca e consenti un dispositivo collegato tramite indirizzo MAC
- abilita e disabilita WiFi Ospiti*
- riavvia il router*

* Lavori in corso

Configurazione del dispositivo router in Homey:
L'app è destinata ai router OpenWRT che funzionano in modalità Router. Puoi aggiungere router OpenWRT configurati in modalità Access Point (AP) per un rilevamento migliore/più veloce dei dispositivi wifi in tutta la casa. Il tuo Homey dovrebbe essere collegato all'interno della parte LAN del router, non dall'esterno (WAN). All'avvio dell'app, Homey proverà ad abilitare automaticamente le statistiche del traffico (velocità di upload/download) installando il pacchetto nlbwmon.

Rilevamento della presenza:
Dopo aver aggiunto il tuo router a Homey, puoi iniziare ad aggiungere i dispositivi mobili o fissi che desideri tracciare per la presenza.

Monitoraggio dell'energia:
Dopo aver aggiunto il tuo router a Homey, puoi aggiungere ulteriori dispositivi che desideri monitorare per l'energia, ad es. la tua TV o stampante. Nelle impostazioni avanzate del dispositivo inserisci il consumo energetico stimato / medio del dispositivo quando è SPENTO o ACCESO. Ora, quando accendi la tua TV, vedrai che la potenza stimata è inclusa nella scheda Energia di Homey.

Router supportati:
Questa app è stata sviluppata e testata su un router Netgear R7800 con OpenWRT 24.10. Dovrebbe essere compatibile con tutti i router OpenWRT con firmware 24.10 o superiore.