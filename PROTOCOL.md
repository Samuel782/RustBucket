# Protocollo Digidesign Control|24 — specifica astratta

Bozza per un driver Rust indipendente. Descrive **fatti** del formato su filo
(layout dei byte, costanti, temporizzazioni), riformulati da zero: non contiene
codice di terzi.

## Provenienza e affidabilità

| Livello | Significato |
|---|---|
| **[OBS]** | Osservato sul filo con un banco reale (firmware `v1.08`), nelle registrazioni del 3 novembre 2026 (circa 16 000 frame). |
| **[RC24]** | Osservato nell'implementazione open source ReaControl24 (GPL-3, ultimo commit giugno 2020), che funziona con hardware reale. |
| **[INF]** | Dedotto da quei dati; plausibile ma non confermato. |
| **[?]** | Sconosciuto: da verificare. |

`rustbucket <file>.pcap` (in `src/analysis.rs`) controlla ogni registrazione
rispetto a questa specifica: checksum, lunghezze dei messaggi, regola dei
contatori, contenuto degli ACK.

Nota di licenza: ReaControl24 è GPL-3. Usarlo come fonte di fatti sul protocollo
va bene; se nel driver si traducesse il suo codice, il driver diventerebbe un
lavoro derivato soggetto a GPL-3. Scrivere il parser da questa specifica evita
il problema.

---

## 1. Trasporto

- **Livello 2 Ethernet puro**, niente IP/UDP. **[RC24] [OBS]**
- **EtherType `0x885F`**. **[RC24] [OBS]**
- Il banco ha un MAC con OUI **`00:A0:7E`** (Digidesign). **[RC24] [OBS]**
- Accesso dall'host: raw socket / BPF (`pcap`, `pnet`). Serve privilegio
  elevato su macOS/Linux. Filtro utile:
  `(ether dst <MAC host> or broadcast) and ether[12:2] = 0x885f`. **[RC24]**
- Su macOS, BPF restituisce all'host anche i frame che l'host stesso invia:
  vanno scartati in ricezione (MAC sorgente = proprio MAC). **[OBS]**
- I frame sotto i 60 byte vengono riempiti (padding) dal livello Ethernet: il
  parser deve affidarsi al campo lunghezza, non alla lunghezza del frame. **[OBS]**

## 2. Struttura del frame

Tutti i campi multibyte sono **big-endian**. **[RC24] [OBS]**

```
offset  len  campo
 0       6   MAC destinazione
 6       6   MAC sorgente
12       2   EtherType = 0x885F
------------------------------ header C24 (16 byte)
14       2   length        = 16 + lunghezza payload
16       2   checksum      somma dei byte del payload, modulo 2^16
18       4   send_counter  contatore del mittente
22       4   ack_counter   valore che si sta confermando
26       2   retry         0, oppure numero del tentativo di ritrasmissione
28       1   command       tipo di pacchetto (§3)
29       1   n_messages    numero di messaggi nel payload
------------------------------
30       N   payload       0..n messaggi concatenati (§5)
```

- **Checksum** **[OBS]**: vale per tutti i 5 500 pacchetti del banco
  registrati, di ogni tipo (dati, ACK, annunci). Un payload vuoto ha checksum
  `0000`. I `02 44` che ReaControl24 imposta nell'handshake non sono "flag": sono
  il checksum del messaggio di reset del clock (§4.2). Il banco ha accettato
  anche pacchetti dell'host con checksum `0000` errato, ma l'host deve calcolarlo.
- Header totali: 30 byte. Massimo visto dal banco: 8 messaggi (40 byte) per
  pacchetto. **[OBS]** ReaControl24 usa al più 48 messaggi e circa 314 byte di
  buffer **[RC24]**. Il limite reale del banco: **[?]**.

## 3. Tipi di pacchetto (`command`)

| Valore | Nome | Direzione | Payload |
|---|---|---|---|
| `0x00` | dati | entrambe | messaggi (§5) **[RC24] [OBS]** |
| `0xA0` | ACK | entrambe | vuoto; `ack_counter` = `send_counter` confermato **[RC24] [OBS]** |
| `0xE0` | annuncio | banco → broadcast | annuncio (§4.1): il banco cerca un host **[OBS]** |
| `0xE1` | beacon | banco → broadcast | annuncio (§4.1): il banco è legato a un host **[OBS]** |
| `0xE2` | online | host → banco | vuoto; avvia la sessione **[RC24] [OBS]** |

Il parser accetta valori sconosciuti (`Command::Unknown(u8)`) invece di
scartare il frame.

## 4. Sessione

### 4.1 Annuncio e beacon **[OBS]**

Il banco invia in broadcast (`FF:FF:FF:FF:FF:FF`) pacchetti `0xE0` o `0xE1`
con `n_messages` = 1 e un payload di 34 byte:

```
offset  len  campo
 0       6   MAC dell'host a cui il banco è legato (tutti zero se nessuno)
 6       8   00 00 00 01 00 00 00 06   (costante; significato [?])
14      10   versione firmware, ASCII terminato da NUL: "v1.08"
24      10   nome dispositivo, ASCII terminato da NUL: "CNTRL|24"
```

- `0xE0` (annuncio): all'accensione con host a zero; dopo aver perso l'host
  (per esempio quando il programma viene fermato), con il MAC dell'ultimo host.
- `0xE1` (beacon): ogni **5,4–7,4 s** (mediana 6,9 s) mentre il banco è legato
  a un host, anche durante l'uso normale.
- Il `send_counter` di annunci e beacon è una sequenza propria (1, 2, 3, …),
  separata da quella dei pacchetti dati.
- Il driver (`src/session.rs`) si collega su `0xE0`, e su `0xE1` solo se il
  beacon nomina il suo MAC e non è già collegato. Un beacon che nomina un altro
  host viene ignorato. Il banco resta collegato senza risposte ai beacon. **[OBS]**

### 4.2 Handshake **[RC24] [OBS]**
1. Host → banco: pacchetto `online` (`0xE2`), senza payload. Il banco lo
   conferma con un ACK con `ack_counter` = 0.
2. Host → banco: messaggio di reset del display del clock (§5.4)
   `F0 13 01 30 19 00×9 F7`, checksum `0244`, `send_counter` = 1.
   Il banco lo conferma con `ack_counter` = 1.
3. L'handshake azzera il display del clock: ripeterlo inutilmente si vede.

### 4.3 Contatori e ACK
- `send_counter` avanza del **numero di messaggi** inviati. **[RC24] [OBS]**
  Le due parti però lo applicano in modo diverso:
  - il **banco** mette nel pacchetto il numero del suo *primo* messaggio:
    contatore del pacchetto precedente + messaggi del pacchetto precedente
    (es. 218 con 1 messaggio, 219 con 2, poi 221) **[OBS]**;
  - questo driver, come ReaControl24, mette il numero dell'*ultimo*
    messaggio: contatore precedente + messaggi di questo pacchetto **[RC24]**.
  Il banco ha confermato tutti i pacchetti dell'host scritti così (1 706 ACK su
  1 706 in una registrazione), quindi sembra controllare solo l'eco
  nell'ACK. **[OBS] [INF]** Con un messaggio per pacchetto le due regole coincidono.
- Il contatore del banco **non** riparte con l'handshake: continua attraverso
  le sessioni (es. 2500 dopo varie prove). Quello dell'host riparte da 1. **[OBS]**
- Ogni pacchetto dati con `n_messages > 0` va confermato con un ACK il cui
  `ack_counter` è esattamente il `send_counter` ricevuto. **[RC24] [OBS]**
  Il banco risponde in meno di 1 ms. **[OBS]**
- Finestra di invio = 1: l'host non invia il pacchetto successivo finché non
  riceve l'ACK con il `send_counter` del pacchetto in volo. L'ACK dell'`online`
  (`ack_counter` 0) non libera la finestra. **[RC24] [OBS]**
- ACK in ritardo: con il banco acceso non è mai successo nelle registrazioni;
  succede quando il banco viene spento o scollegato. **[OBS]** Politica di
  ritrasmissione lato host: **[?]**.

### 4.4 Ritrasmissioni dal banco **[OBS]**
- Se l'ACK non arriva, il banco ritrasmette lo stesso pacchetto ogni **~31 ms**
  con `retry` = 1, 2, 3, … e si ferma dopo **16** tentativi (circa 0,5 s): il
  messaggio è perso.
- Succede quando il banco è legato all'host ma il programma sull'host non sta
  girando, o non si è ancora collegato.
- L'host conferma ogni ritrasmissione ma consegna i messaggi una sola volta.
  ReaControl24 sospende inoltre l'invio per ~300 ms. **[RC24]**
- Un pacchetto con checksum errato non viene confermato, così il banco lo
  ritrasmette. **[INF]**

### 4.5 Keepalive
- Se l'host non invia nulla per **10 s**, manda un pacchetto dati con un solo
  messaggio di 1 byte `0x00`; il banco lo conferma. **[RC24] [OBS]**
- Timeout del banco in assenza di traffico dall'host: **[?]**.

---

## 5. Messaggi nel payload

Il formato ricorda il MIDI: status byte con il bit alto acceso, byte dati a
7 bit, messaggi di sistema `F0 … F7`. I messaggi sono concatenati senza
separatori; la lunghezza dipende dal primo byte.

Tabella delle lunghezze (`src/message/desk.rs`). Con queste regole nessuno
dei 4 800 pacchetti dati del banco registrati ha differenze tra
`n_messages` e i messaggi trovati dal parser. **[OBS]**

| Primo byte | Lunghezza | Fonte |
|---|---|---|
| `00` | 1 (keepalive) | **[OBS]** (host → banco) |
| `90` | 3 (pulsante / LED) | **[RC24] [OBS]** |
| `B0`, byte 1 senza `0x40` | 5 (fader) | **[RC24] [OBS]** |
| `B0`, byte 1 con `0x40` | **3** (encoder: V-Pot, jog) | **[OBS]** (non 4, come si pensava) |
| `FF` | 3 | **[RC24]**, mai visto dal banco |
| `F0` | fino a `F7` compreso | **[RC24] [OBS]** (host → banco) |
| altro | sconosciuta: il resto del payload resta grezzo | **[?]**, mai visto |

Nelle formule `t` = indice della traccia/canale, 0–23.

### 5.1 Fader (banco ↔ host) — `B0`, 5 byte **[RC24] [OBS]**
```
B0  t  hi  (20+t)  lo
```
- Valore a **10 bit** (0–1023): `hi = v >> 3` (7 bit), `lo = (v & 7) << 4`.
  In fondo corsa il banco riporta valori vicini a 0, in cima oltre 1000. **[OBS]**
- Stessa forma in entrambe le direzioni: posizione dal banco, comando al
  motore verso il banco. Con valore 768 il fader 1 è andato a circa −3 dB. **[OBS]**
- Durante il movimento il banco invia una posizione ogni ~30 ms. **[OBS]**
- **Rilasciato il fader, il motore lo riporta all'ultima posizione impostata
  dall'host** (in fondo, se l'host non ne ha mai impostata una). **[OBS]**
  L'host deve quindi rimandare ogni posizione ricevuta: così il fader resta
  dove viene lasciato, senza scatti durante il movimento. **[OBS]**
- Il tocco del fader è il pulsante `09` della striscia (§5.3). **[OBS]**
- Non c'è un fader master fisico. **[OBS]**
- Curva da valore a dB: **[?]** (un solo punto: 768 ≈ −3 dB).

### 5.2 Encoder: V-Pot e jog (banco → host) — `B0`, 3 byte **[OBS]**
```
B0  (40 | i)  d
```
- `i` 0–23: V-Pot della traccia `i`. `i` = 28 (`5C`): jog/shuttle.
- `d - 0x40` = passi con segno: +1 verso destra, −1 verso sinistra per ogni
  scatto; il jog arriva fino a ±3 quando girato veloce. Non c'è un byte di
  velocità.

### 5.3 Pulsanti e touch dei fader — `90`, 3 byte **[RC24] [OBS]**
```
90  indice  (gruppo | stato)
```
- Il bit `0x40` del secondo byte è lo stato (premuto / acceso). **[OBS]**
- ID = `[indice, gruppo]` **[OBS]**:
  - gruppi `00`–`17`: le 24 strisce di canale. Indici: `00` Rec Arm,
    `01` Pan/Send, `02` EQ, `03` Dyn, `04` Switch Active, `05` Auto,
    `06` Select, `07` Solo, `08` Mute, `09` tocco del fader, `0A` Insert;
  - `18`: tasti funzione, meter select, automazione, modificatori Pro Tools;
  - `19`: finestre, preset di zoom, navigazione, modo del counter;
  - `1A`: tastierino numerico (la cifra *n* ha indice *n*);
  - `1B`: modi e strumenti di edit, funzioni di edit, gruppi, banchi;
  - `1C`: trasporto;
  - `1D`: monitor, insert, assegnazione, mandate, pan, scorrimento della barra.
- Tabella completa con i nomi: `src/buttons.rs`. La sezione control room
  monitor non invia nulla su Ethernet. **[OBS]**
- **Stesso formato per i LED** dall'host: inviando l'ID di un pulsante si
  accende il suo LED. **[RC24] [OBS]**
- **Rimbalzo dei contatti** **[OBS]**: una sola pressione arriva spesso come
  premuto → rilasciato → premuto → rilasciato, con meno di 50 ms (al massimo
  47) tra il rilascio spurio e la nuova pressione. Pressioni volute dello
  stesso tasto distano almeno 100 ms. L'host scarta una pressione che arriva
  entro 60 ms dal rilascio dello stesso tasto (`src/debounce.rs`).
- Un tasto tenuto premuto non ripete il messaggio. **[OBS]**

### 5.4 Display, LED e meter (host → banco) — SysEx `F0 13 01 <sub> … F7` **[RC24]**

| `sub` | Uso | Layout dopo `F0 13 01 sub` |
|---|---|---|
| `40` | Scribble strip (4 caratteri per traccia) | `t 00 c0 c1 c2 c3 F7` (ASCII) **[OBS]** |
| `30` | Display del trasporto (clock / counter) | `19 dots d0…d7 F7`: 8 cifre a 7 segmenti, `d0` la più a destra **[OBS]** |
| `20` | LED vari (gruppo) | `19 00 F7` + varianti **[?]** |
| `10` | Meter | `a l0 l1 F7`, con `a` = `32·lato + t` per i canali e `32·lato + 24 + coppia` per i bus **[OBS]** |
| `00` | Anello LED del V-Pot | `(p0 \| t) p1 p2 F7`: 3 byte di pattern, il primo condivide il byte con `t` (solo il bit `0x40` resta al pattern); 8 byte in tutto **[RC24] [OBS]** |

- Scribble strip: `Ch01`…`Ch24` sono comparsi sui canali giusti, con i
  caratteri giusti. **[OBS]**
- **Anello del V-Pot** **[OBS]**: 15 LED, numerati da 1 (il più a sinistra)
  a 15; l'8 è il centrale. Ogni bit del pattern accende un LED:

  | Byte | `40` | `20` | `10` | `08` | `04` | `02` | `01` |
  |---|---|---|---|---|---|---|---|
  | `p0` | 1 | – | – | – | – | – | – |
  | `p1` | 2 | 3 | 4 | 5 | 6 | 7 | 8 (centro) |
  | `p2` | 9 | 10 | 11 | 12 | 13 | 14 | 15 |

  Tutti i bit (`40 7F 7F`) accendono tutti i 15 LED. `RingLeds` in
  `src/message/host.rs` traduce posizioni in pattern (punto, barra da
  sinistra, barra dal centro).
- **Meter** **[OBS]**: 2 per canale (stereo) più 6 di uscita bus, 14 LED
  ciascuno. I due byte di livello **non sono un valore** ma due maschere di
  bit: ogni bit accende un LED.

  | Byte | `40` | `20` | `10` | `08` | `04` | `02` | `01` |
  |---|---|---|---|---|---|---|---|
  | `l0` | 0 | −2 | −4 | −6 | −8 | −10 | −14 |
  | `l1` | −18 | −22 | −26 | −30 | −35 | −40 | −50 |

  I bit `08`–`40` sono stati provati uno per uno; i tre bit bassi di ogni
  byte accendono insieme −8/−10/−14 e −35/−40/−50, e l'ordine tra loro segue
  quello degli altri **[INF]**. `MeterLeds` in `src/message/host.rs` traduce un
  livello in dB in una barra.
- Indirizzi `a` dei meter **[OBS]**: canali 0–23 con lato 0, 32–55 con lato 1
  (la prova a indirizzi 32–55 ha acceso tutti i LED); bus 1, 3, 5 a 24, 25, 26
  e bus 2, 4, 6 a 56, 57, 58. Gli indirizzi 27–31 e 59 non accendono nulla.
  Lato 0 = sinistro, lato 1 = destro. **[OBS]**
- **Display del trasporto** **[OBS]**: ogni byte
  `d0`…`d7` è una maschera di segmenti, non un codice di carattere (i valori
  ASCII danno forme senza senso). `d0` è la cifra più a destra, `d7` la più a
  sinistra.

  | Bit | `40` | `20` | `10` | `08` | `04` | `02` | `01` |
  |---|---|---|---|---|---|---|---|
  | Segmento | a (alto) | b (alto destra) | c (basso destra) | d (basso) | e (basso sinistra) | f (alto sinistra) | g (centro) |

  `dots`: il bit *k* accende il punto della cifra `d(7−k)`: bit 0 = cifra più
  a sinistra, bit 6 = seconda da destra; la cifra più a destra non ha punto.
  Il byte `19` dopo `30` è costante e il suo significato è **[?]**.
  `seven_segment` e `HostMessage::clock_text` in `src/message/host.rs`
  scrivono testo (cifre, molte lettere, `-`, `_`, punti).
- Set di caratteri dello scribble strip oltre l'ASCII: **[?]**.

### 5.5 Altri messaggi dal banco **[RC24]**
- `FF FE xx`: LED della modalità di automazione (`F0` Read, `F1` Trim,
  `F2` Latch, `F3` Touch, `F4` Write, `F5` Off).
- `FF FF xx`: LED della modalità del counter (`F0` ore/ms, `F1` ore/frame,
  `F2` piedi/frame, `F3` misure/battute, `F4` spento).
- Nessuno dei due è comparso nelle registrazioni: i tasti di automazione e
  Counter Mode arrivano come normali pulsanti `90`. **[OBS]**

---

## 6. Punti aperti, in ordine di priorità

1. Tenuta del collegamento in sessioni di ore: finora provata per minuti.
2. Ordine dei 3 bit bassi dei meter; se i meter vanno aggiornati di continuo o
   restano accesi da soli.
3. Byte 6–13 dell'annuncio; byte `19` del display del trasporto; LED
   `F0 13 01 20`; timeout lato banco.
4. Curva da valore del fader a dB; set di caratteri dello scribble strip; i due
   punti (`:`) del display del trasporto, se esistono.
