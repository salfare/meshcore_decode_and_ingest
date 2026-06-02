# get_meshcore_from_mqtt.py

MeshCore MQTT → MySQL ingester using the **meshcoredecoder** library.

Connects to an MQTT broker over TLS, decodes each raw LoRa packet,
resolves transport codes to region names, decrypts GroupText channel messages,
and inserts one row per packet into the MySQL `packets` table.

---

## How it works

```
MQTT broker (TLS)  →  on_message()  →  decode_packet()  →  save_packet_to_mysql()
                                             │
                                  MeshCoreDecoder.decode()
                                             │
                             ┌───────────────┴────────────┐
                      transport codes              GroupText ?
                             │                            │
                     region lookup               channel decryption
                     (HMAC-SHA256)               (AES via keystore)
```

1. Connects to the MQTT broker on the configured port with TLS and username/password auth.
2. Subscribes to `meshcore/+/+/packets` by default (wildcards match `{IATA}/{PUBLIC_KEY}`).
3. For each incoming JSON message the raw hex payload is decoded by `MeshCoreDecoder`.
4. Transport codes are resolved to region names via `HMAC-SHA256(SHA256(region)[:16], type_byte || payload)[:2]` (LE uint16).
5. `GroupText` packets are decrypted with the keystore built from `STATIC_CHANNELS` (pre-shared secrets) and `HASH_CHANNELS` (name-derived secrets).
6. The observer timestamp is normalised to UTC (offset inferred from ingester receive time).
7. The decoded row is inserted into the MySQL `packets` table.

---

## Setup

### 1. Create and activate a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure

```bash
cp env.example .env
```

Edit `.env` and fill in `DB_*`, `MQTT_USERNAME`, `MQTT_PASSWORD`, and any `STATIC_CHANNELS` entries.

### 4. Run

```bash
python get_meshcore_from_mqtt.py
```

Press `Ctrl-C` to stop.

---

## Configuration

All secrets and endpoints live in `.env` in the repo directory. Never commit `.env` to version control — use `env.example` as a template.

### MySQL

| Variable      | Description    |
|---------------|----------------|
| `DB_HOST`     | MySQL host     |
| `DB_NAME`     | MySQL database |
| `DB_USER`     | MySQL user     |
| `DB_PORT`     | MySQL port     |
| `DB_PASSWORD` | MySQL password |

### MQTT broker

| Variable             | Description                                         |
|----------------------|-----------------------------------------------------|
| `MQTT_SERVER`        | Broker hostname                                     |
| `MQTT_PORT`          | Port (typically 8883 for TLS)                       |
| `MQTT_USERNAME`      | Broker username                                     |
| `MQTT_PASSWORD`      | Broker password                                     |
| `MQTT_TOPIC_PACKETS` | Subscription topic (default `meshcore/+/+/packets`) |

### Channel secrets

| Variable               | Description                                                       |
|------------------------|-------------------------------------------------------------------|
| `STATIC_CHANNELS`      | JSON object: channel-name → 128-bit hex secret (pre-shared keys) |
| `EXTRA_HASH_CHANNELS`  | JSON array of `#channel` names to add on top of the built-in list |

#### Adding a static channel

Extend `STATIC_CHANNELS` in `.env`:

```dotenv
STATIC_CHANNELS={"public":"<32-char hex>","myChannel":"<32-char hex>"}
```

Restart the service to pick up the change.

#### Hash-derived channels

Channels listed in `HASH_CHANNELS` (inside the script) derive their secret automatically:

```
filtered = "#" + lowercase_alphanumeric(name)
secret   = SHA256(filtered)[:16]
```

To add one, append its `#name` to `HASH_CHANNELS` and restart.

---

## Running as a systemd service

```bash
sudo systemctl start   get_meshcore_from_mqtt
sudo systemctl stop    get_meshcore_from_mqtt
sudo systemctl restart get_meshcore_from_mqtt
sudo systemctl status  get_meshcore_from_mqtt
```

Unit file (`/etc/systemd/system/get_meshcore_from_mqtt.service`):

```ini
[Unit]
Description=MeshCore MQTT ingester (meshcoredecoder)
After=network-online.target

[Service]
Environment="PATH=<repo>/venv/bin:/usr/local/bin:/usr/bin:/bin"
WorkingDirectory=<repo>
Type=simple
User=root
Group=root
ExecStart=<repo>/venv/bin/python <repo>/get_meshcore_from_mqtt.py
Restart=on-failure
RestartSec=5
TimeoutStartSec=infinity

[Install]
WantedBy=multi-user.target
```

Replace `<repo>` with the absolute path to this repo (e.g. the output of `pwd`).

---

## MySQL schema — `packets` table

| Column              | Type         | Notes                                            |
|---------------------|--------------|--------------------------------------------------|
| `key_timestamp`     | VARCHAR(30)  | Ingester receive timestamp (primary key)         |
| `origin`            | VARCHAR(100) | Sending node name                                |
| `timestamp`         | DATETIME(6)  | Packet timestamp, local time (Europe/Zurich)     |
| `timestamp_utc`     | DATETIME(6)  | Packet timestamp, UTC                            |
| `type`              | VARCHAR(20)  | Payload type string (`NodeInfo`, `GroupText`, …) |
| `time`              | TIME         | Time-of-day component (local)                    |
| `date`              | DATE         | Date component (local)                           |
| `len`               | INT          | Total frame length (bytes)                       |
| `packet_type`       | INT          | Numeric `PayloadType` enum value                 |
| `route`             | VARCHAR(10)  | Route flags                                      |
| `payload_len`       | INT          | Payload length (bytes)                           |
| `raw`               | TEXT         | Raw hex payload                                  |
| `SNR`               | FLOAT        | Signal-to-noise ratio (dB)                       |
| `RSSI`              | INT          | Received signal strength (dBm)                   |
| `latitude`          | FLOAT        | GPS latitude (NULL if not present)               |
| `longitude`         | FLOAT        | GPS longitude (NULL if not present)              |
| `msg_txt`           | TEXT         | Decrypted message text (GroupText only)          |
| `msg_sender`        | VARCHAR(100) | Decrypted sender name (GroupText only)           |
| `deviceName`        | VARCHAR(100) | Node advertised name                             |
| `deviceRole`        | INT          | `1` = companion, `2`/`3` = repeater/router       |
| `hash_id`           | VARCHAR(100) | Packet hash / dedup key                          |
| `path`              | JSON         | Hop path (JSON array of public-key prefixes)     |
| `pathLength`        | INT          | Number of hops                                   |
| `channelHash`       | VARCHAR(4)   | 1-byte channel hash (hex, upper-case)            |
| `channelName`       | VARCHAR(200) | Resolved channel name                            |
| `transportCodes`    | JSON         | Raw transport-code list (hex strings)            |
| `PublicKey`         | VARCHAR(200) | Sender full public key (hex)                     |
| `source_hash`       | VARCHAR(20)  | Source node hash                                 |
| `destination_hash`  | VARCHAR(20)  | Destination node hash                            |
| `cipher_mac`        | VARCHAR(40)  | AES-GCM cipher MAC                               |
| `sender_public_key` | VARCHAR(200) | Sender public key (from encrypted header)        |
| `path_hash_size`    | INT          | Path-hash size in bytes (1–4)                    |
| `region`            | VARCHAR(200) | Resolved region name(s), comma-separated         |

---

## Dependencies

See `requirements.txt`. Key packages:

- `paho-mqtt` — MQTT client
- `mysql-connector-python` — MySQL driver
- `python-dotenv` — `.env` loading
- `meshcoredecoder` — MeshCore packet decoder
- `cryptography` / `pycryptodome` — AES decryption
