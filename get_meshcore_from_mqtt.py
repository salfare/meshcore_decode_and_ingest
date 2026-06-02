#!/usr/bin/env python3
"""
MeshCore MQTT → MySQL ingester (meshcoredecoder edition).

Subscribes to `meshcore/packets/#`, decodes each raw LoRa packet with the
meshcoredecoder library, resolves transport-codes → regions and GroupText
channel secrets, then inserts one row per packet into the MySQL `packets` table.

All secrets and endpoints are read from the `.env` file in the project root.
See `new_get_meshcore_from_mqtt.md` for configuration details and the systemd
unit file.
packet decoding based on : https://github.com/chrisdavis2110/meshcore-decoder-py

"""

import ast
import hashlib
import hmac
import json
import logging
import os
import re
import ssl
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from dotenv import load_dotenv
import mysql.connector
import paho.mqtt.client as mqtt

load_dotenv(dotenv_path=Path(__file__).resolve().parent / '.env')

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

from meshcoredecoder import MeshCoreDecoder
from meshcoredecoder.crypto import MeshCoreKeyStore
from meshcoredecoder.types.crypto import DecryptionOptions
from meshcoredecoder.types.enums import PayloadType
from meshcoredecoder.utils.enum_names import (
    get_device_role_name,
    get_payload_type_name,
    get_route_type_name,
)


# ── known regions ─────────────────────────────────────────────────────────────

KNOWN_REGIONS = [
    # wildcard
    "*",

    # Europe
    "europe",
    "bodensee",

    # Switzerland
    "ch", "ch-de", "ch-fr", "ch-it",
    "rudolfstetten", "rud",  "local",

    # Italy
    "it", "italy", "lombardia",

    # France
    "fr",

    # Germany – national
    "de",

    # Germany – Bundesländer (ISO 3166-2)
    "de-bw",   # Baden-Württemberg
    "de-by",   # Bayern
    "de-be",   # Berlin
    "de-bb",   # Brandenburg
    "de-hb",   # Bremen
    "de-hh",   # Hamburg
    "de-he",   # Hessen
    "de-mv",   # Mecklenburg-Vorpommern
    "de-ni",   # Niedersachsen
    "de-nw",   # Nordrhein-Westfalen
    "de-rp",   # Rheinland-Pfalz
    "de-sl",   # Saarland
    "de-sn",   # Sachsen
    "de-st",   # Sachsen-Anhalt
    "de-sh",   # Schleswig-Holstein
    "de-th",   # Thüringen

    # Germany – zones
    "de-nord", "de-ost", "de-sued", "de-west", "de-mitte",

    # Germany – local/test
    "local", "lokal",

    # Baden-Württemberg sub-regions
    "de-bw-em",   # Emmendingen
    "de-bw-fr",   # Freiburg / LKBH
    "de-bw-loe",  # Lörrach
    "de-bw-muel", # Müllheim
    "de-bw-og",   # Offenburg / Ortenau
    "de-bw-wt",   # Waldshut
    "de-bw-ka",   # Karlsruhe
    "de-bw-br",   # Bruchsal
    "de-bw-ra",   # Rastatt
    "de-bw-bad",  # Baden-Baden
    "de-bw-pf",   # Pforzheim
    "de-bw-str",  # Metropolregion Stuttgart
    "de-bw-es",   # Landkreis Esslingen
    "de-bw-s",    # Stadtkreis Stuttgart
    "de-bw-sha",  # Schwäbisch Hall
    "de-bw-sbh",  # Schwarzwald-Baar-Heuberg
    "de-bw-rw",   # Landkreis Rottweil
    "de-bw-tut",  # Landkreis Tuttlingen
    "de-bw-vs",   # Villingen-Schwenningen
    "de-abo",     # Allgäu/Bodensee/Oberschwaben
    "suedbaden", "upper-rhine", "nordbaden",
    "pamina",     # DE/FR border region
    "rhein-neckar",

    # Bayern sub-regions
    "de-by-fr",   # Franken
    "de-by-ofr",  # Oberfranken
    "de-by-ofr-fo", "de-by-ofr-ba", "de-by-ofr-bt",
    "de-by-mfr",  # Mittelfranken
    "de-by-mfr-n", "de-by-mfr-fue", "de-by-mfr-erh", "de-by-mfr-nea", "de-by-mfr-er",
    "de-by-ufr",  # Unterfranken
    "de-by-oal", "de-by-oa", "de-by-mn", "de-by-li",
    "allgaeu",
    "de-by-muc",  # München
    "de-by-la", "de-by-ed",

    # Berlin/Brandenburg
    "de-bebb",
    "de-bb-um", "de-bb-opr", "de-bb-pr", "de-bb-ohv", "de-bb-bar",
    "de-bb-hvl", "de-bb-mol", "de-bb-pm", "de-bb-lds", "de-bb-tf",
    "de-bb-los", "de-bb-spn", "de-bb-ee", "de-bb-osl",

    # Bremen
    "de-hb-bhv", "bremesh",

    # Hamburg
    "hansemesh",

    # Hessen
    "taunus", "westerwald", "rhein-main", "frankfurt",
    "de-ks-goe",  # Drei-Länder-Eck HE/NI/NW

    # Niedersachsen sub-regions
    "de-ni-he", "de-ni-sz", "de-ni-wob",
    "bsmesh", "braunschweig",
    "de-harz", "de-solling",
    "de-ni-nom", "de-ni-goe",
    "landkreis-harburg", "seevetal", "sg-tostedt", "lk-stade", "altes-land",
    "de-ni-dan", "de-ni-lg", "de-ni-ue",
    "heidemesh", "de-ni-h",

    # NRW sub-regions
    "ruhrgebiet",
    "de-nw-gl", "de-nw-su",
    "rheinland", "bergischesland", "koeln", "bonn", "sauerland",
    "de-nw-owl",

    # Rheinland-Pfalz
    "de-rp-ger", "de-rp-wei",

    # Sachsen
    "de-sn-leipzig",
    "de-sn-vvo", "de-sn-dd", "de-sn-mei",

    # Sachsen-Anhalt
    "halle",

    # Schleswig-Holstein
    "de-sh-ki", "de-sh-slfl", "de-sh-ploe", "de-sh-pi",

    # Thüringen
    "de-th-ef", "de-th-sm", "de-th-hbn", "de-th-themar",
]


# ── hash-derived channel names ────────────────────────────────────────────────

HASH_CHANNELS = [
    "#info", "#test-ch", "#test", "#ping", "#wardrive", "#frblabla",
    "#meteo", "#le-38", "#bot", "#wardriving", "#luzern", "#basel",
    "#bern", "#zuerich", "#qrv", "#lucern", "#freiburg",
    "#svizzera", "#hamradio", "#switzerland", "#romande", "#prove",
    "#warnings", "#Seeland", "#suisse-romande",
    "#flachwitze", "#france", "#austria", "#chtest", "#germany",
    "#muenchen", "#aalgau", "#oberaargau", "#suisse", "#blackout", "#andy73",

    # --- BEGIN: meshcore-de.fyi/meshcore:allgemeines:hashtag_channels (fetched 2026-04-24) ---
    # To revert: remove this entire block from BEGIN to END (inclusive)

    # General
    "#ankuendigungen", "#bbxdwd", "#emergency", "#meshcore", "#sos",
    "#testing", "#wetter",

    # Interest / Hobby
    "#aurora", "#criticalmass", "#drk", "#feuerwehr", "#freifunk",
    "#jokes", "#konfiguration", "#makerspace", "#meshcorenetz",
    "#pota", "#sota", "#sports", "#stricken", "#thw", "#kats", "#bienen",

    # Germany – national / multi-state
    "#dl-mitte", "#nrw",

    # Baden-Württemberg
    "#bw-kn", "#ka-pf", "#karlsruhe", "#durlach", "#groetzingen",
    "#ettlingen", "#df0uk", "#stuttgart", "#boeblingen", "#zak",
    "#pamina",

    # Bayern
    "#allgaeu", "#region-muc", "#rosenheim", "#franken", "#nuernberg",
    "#fuerth", "#ingolstadt", "#oberfranken", "#oberbayern", "#passau",
    "#landshut", "#ergolding", "#ergoldsbach",

    # Berlin / Brandenburg
    "#berlin", "#berlinbrandenburg", "#brandenburg",
    "#de-bb-bar", "#de-bb-cb", "#de-bb-ee", "#de-bb-ffo", "#de-bb-hvl",
    "#de-bb-lds", "#de-bb-los", "#de-bb-mol", "#de-bb-pm", "#de-bb-pr",
    "#de-bb-ohv", "#de-bb-opr", "#de-bb-osl", "#de-bb-spn", "#de-bb-tf",
    "#de-bb-um",

    # Hamburg / Bremen
    "#hansemesh",

    # Hessen
    "#taunus", "#westerwald", "#rhein-neckar", "#rhein-main",
    "#oberhessen", "#wetterau", "#frankfurt", "#mkk", "#bergstrasse",
    "#untermain",

    # Niedersachsen
    "#bsmesh", "#h33", "#seevetal", "#landkreis-harburg", "#hannover",
    "#helmstedt", "#wolfsburg", "#nordharz", "#altes-land", "#lk-stade",
    "#friesland", "#ffnw",

    # NRW
    "#sauerland", "#bochum", "#essen", "#muelheim",

    # Rheinland-Pfalz
    "#woerth-am-rhein", "#jockgrim", "#weinstrasse", "#drg",

    # Saarland
    "#saarland", "#sarlorlux",

    # Sachsen
    "#cmdd", "#dresden", "#dd-ping", "#de-sn-dd", "#de-sn-mei",
    "#de-sn-pir", "#dd-repeater", "#dd-companion", "#dd-roomserver",
    "#ffdd", "#sn", "#leipzig", "#lej", "#zwickau",

    # Sachsen-Anhalt
    "#st", "#magdeburg",

    # Thüringen
    "#th", "#erfurt", "#jena", "#hbn", "#themar", "#mhl",
    "#fichtelgebirge",
    
    # --- END: meshcore-de.fyi/meshcore:allgemeines:hashtag_channels ---

    # Switzerland (additional)
    "#wallis",
]


# ── channel credential derivation ─────────────────────────────────────────────

def derive_channel_credentials(channel_name: str) -> dict:
    """Return channelHash (1-byte hex) and channelSecret (16-byte hex) for a #channel."""
    if not channel_name.startswith('#'):
        raise ValueError("Channel name must start with '#'")
    filtered   = '#' + re.sub(r'[^a-z0-9-]', '', channel_name[1:].lower())
    name_hash  = hashlib.sha256(filtered.encode()).digest()
    secret     = name_hash[:16].hex()
    secret_hash = hashlib.sha256(name_hash[:16]).digest()
    return {
        "channelHash":   f"{secret_hash[0]:02x}".upper(),
        "channelSecret": secret,
    }


# ── build keystore and lookup maps ────────────────────────────────────────────

def _build_channel_maps():
    """Return (secret_to_name, hash_to_names, all_secrets, key_store, decrypt_options)."""
    static_channels      = json.loads(os.environ['STATIC_CHANNELS'])
    extra_hash_channels  = ast.literal_eval(os.environ.get('EXTRA_HASH_CHANNELS', '[]'))

    secret_to_name: dict[str, str] = {}
    hash_to_names:  dict[str, list[str]] = {"11": ["public"]}
    all_secrets:    list[str] = []

    for name, secret in static_channels.items():
        secret_to_name[secret] = name
        all_secrets.append(secret)

    for name in HASH_CHANNELS + extra_hash_channels:
        creds  = derive_channel_credentials(name)
        secret = creds["channelSecret"]
        h      = creds["channelHash"]
        secret_to_name[secret] = name
        if secret not in all_secrets:
            all_secrets.append(secret)
        hash_to_names.setdefault(h, [])
        if name not in hash_to_names[h]:
            hash_to_names[h].append(name)

    for h, names in hash_to_names.items():
        if len(names) > 1:
            logging.warning("Hash collision on %s: %s", h, names)

    ks   = MeshCoreKeyStore({'channel_secrets': all_secrets})
    opts = DecryptionOptions(key_store=ks)
    return secret_to_name, hash_to_names, all_secrets, ks, opts


secret_to_name: dict = {}
hash_to_names:  dict = {}
all_secrets:    list = []
key_store             = None
decrypt_options       = None


# ── transport code resolution ─────────────────────────────────────────────────

def _region_key(region_name: str) -> bytes:
    return hashlib.sha256(region_name.encode()).digest()[:16]


def _compute_transport_code(region_name: str, payload_type_byte: int, payload_bytes: bytes) -> int | None:
    key  = _region_key(region_name)
    msg  = bytes([payload_type_byte]) + payload_bytes
    mac  = hmac.new(key, msg, hashlib.sha256).digest()
    code = struct.unpack_from('<H', mac, 0)[0]
    return None if code in (0x0000, 0xFFFF) else code


def resolve_transport_codes(transport_codes_raw, payload_type_byte: int, payload_bytes: bytes) -> list:
    if not transport_codes_raw:
        return []

    if isinstance(transport_codes_raw, str):
        try:
            codes = ast.literal_eval(transport_codes_raw)
        except Exception:
            codes = [transport_codes_raw]
    else:
        codes = list(transport_codes_raw)

    lookup: dict[int, str] = {}
    for region in KNOWN_REGIONS:
        region_key = region if region == "*" else f"#{region}"
        code = _compute_transport_code(region_key, payload_type_byte, payload_bytes)
        if code is not None:
            lookup[code] = region

    results = []
    for code_int in codes:
        if not isinstance(code_int, int):
            try:
                code_int = int(str(code_int), 16)
            except ValueError:
                results.append({'code': str(code_int), 'int': None, 'region': 'unknown'})
                continue

        if code_int in (0x0000, 0xFFFF):
            continue

        results.append({
            'code':   f"{code_int:04X}",
            'int':    code_int,
            'region': lookup.get(code_int, 'unknown'),
        })
    return results


# ── channel collision resolver ────────────────────────────────────────────────

def resolve_channel_name(hex_data: str, channel_hash: str) -> str:
    """Return the channel name for a successfully decrypted GroupText packet.

    When multiple secrets share the same hash, probes each candidate
    individually to find which one actually decrypts the packet.
    """
    candidates = key_store._channel_hash_to_keys.get(channel_hash.lower(), [])

    if not candidates:
        return f"#{channel_hash}"
    if len(candidates) == 1:
        return secret_to_name.get(candidates[0], f"#{channel_hash}")

    for secret in candidates:
        ks = MeshCoreKeyStore({'channel_secrets': [secret]})
        try:
            test_packet = MeshCoreDecoder.decode(hex_data, DecryptionOptions(key_store=ks))
            decoded     = test_packet.payload.get('decoded')
            if decoded and decoded.decrypted:
                return secret_to_name.get(secret, f"#{channel_hash}")
        except Exception:
            continue

    return f"#{channel_hash}"


# ── helpers ───────────────────────────────────────────────────────────────────

def get_path_hash_size(raw: str) -> int | None:
    """Return path-hash size in bytes from the raw packet hex string."""
    try:
        if not raw or len(raw) < 4:
            return None
        header_byte = int(raw[0:2], 16)
        route_type  = header_byte & 0x03
        if route_type in (0, 3):
            if len(raw) < 12:
                return None
            path_length_byte = int(raw[10:12], 16)
        else:
            path_length_byte = int(raw[2:4], 16)
        return ((path_length_byte >> 6) & 0x03) + 1
    except Exception:
        return None


# ── timestamp normalisation ───────────────────────────────────────────────────

LOCAL_TZ = ZoneInfo(os.environ.get('TZ', 'Europe/Zurich'))


def normalize_timestamps(observer_ts_str: str, received_at_utc: datetime):
    """Infer observer UTC offset (rounded to nearest whole hour) and return (local_dt, utc_dt).

    Compares observer-reported time against ingester's known UTC receive time.
    Returns (None, None) if the observer timestamp is missing or unparseable.
    """
    try:
        obs_ts = datetime.fromisoformat(observer_ts_str)
    except (ValueError, TypeError):
        return None, None

    if obs_ts.tzinfo is not None:
        utc_dt = obs_ts.astimezone(timezone.utc).replace(tzinfo=None)
    else:
        diff_s = (obs_ts - received_at_utc.replace(tzinfo=None)).total_seconds()
        offset_hours = round(diff_s / 3600)
        if abs(offset_hours) > 14:
            logging.warning("Implausible observer offset %+dh — treating as UTC", offset_hours)
            offset_hours = 0
        elif offset_hours != 0:
            logging.debug("Observer UTC offset inferred: %+dh", offset_hours)
        utc_dt = obs_ts - timedelta(hours=offset_hours)

    local_dt = utc_dt.replace(tzinfo=timezone.utc).astimezone(LOCAL_TZ).replace(tzinfo=None)
    return local_dt, utc_dt


# ── packet decoder ────────────────────────────────────────────────────────────

def decode_packet(hex_data: str, timestamp: str, packets_dict: dict) -> None:
    packet  = MeshCoreDecoder.decode(hex_data, decrypt_options)
    decoded = packet.payload.get('decoded') if isinstance(packet.payload, dict) else None

    payload_type = packet.payload_type
    logging.debug("Decoded packet: %s", get_payload_type_name(payload_type))

    pkt = packets_dict[timestamp]
    pkt['path_hash_size'] = get_path_hash_size(hex_data)
    pkt['type']           = get_payload_type_name(payload_type)
    pkt['packet_type']    = payload_type.value
    pkt['pathLength']     = packet.path_length
    pkt['path']           = packet.path or None
    pkt['transportCodes'] = str(packet.transport_codes) if packet.transport_codes else None
    pkt['region']         = None

    app_data = getattr(decoded, 'app_data', {}) or {}
    location = app_data.get('location') or {}
    pkt['PublicKey']         = getattr(decoded, 'public_key', None)
    pkt['deviceName']        = app_data.get('name')
    pkt['deviceRole']        = app_data.get('device_role').value if app_data.get('device_role') else None
    pkt['latitude']          = location.get('latitude')
    pkt['longitude']         = location.get('longitude')
    pkt['source_hash']       = getattr(decoded, 'source_hash', None)
    pkt['destination_hash']  = getattr(decoded, 'destination_hash', None)
    pkt['cipher_mac']        = getattr(decoded, 'cipher_mac', None)
    pkt['sender_public_key'] = getattr(decoded, 'sender_public_key', None)

    # transport code → region
    if packet.transport_codes:
        payload_raw   = packet.payload.get('raw', '') if isinstance(packet.payload, dict) else ''
        payload_bytes = bytes.fromhex(payload_raw) if payload_raw else b''
        resolved      = resolve_transport_codes(packet.transport_codes, payload_type.value, payload_bytes)
        if resolved:
            pkt['region'] = ', '.join(r['region'] for r in resolved)
            for r in resolved:
                logging.info("  Transport code %s → region: %s", r['code'], r['region'])

    # GroupText decryption
    if payload_type == PayloadType.GroupText:
        group_text = decoded

        if group_text:
            ch_hash       = group_text.channel_hash.upper()
            pkt['channelHash'] = ch_hash
            pkt['cipher_mac']  = group_text.cipher_mac

            if group_text.decrypted:
                channel_name         = resolve_channel_name(hex_data, ch_hash)
                pkt['msg_sender']    = group_text.decrypted.get('sender')
                pkt['msg_txt']       = group_text.decrypted.get('message')
                pkt['channelName']   = [channel_name]
                logging.info("  Channel: %s (hash %s)", channel_name, ch_hash)
                logging.info("  Sender:  %s", group_text.decrypted.get('sender'))
                logging.info("  Message: %s", group_text.decrypted.get('message'))
            else:
                logging.warning("GroupText hash %s: could not decrypt", ch_hash)


# ── MySQL ─────────────────────────────────────────────────────────────────────

def save_packet_to_mysql(conn, packet_key: str, packet: dict) -> None:
    ts       = datetime.fromisoformat(packet['timestamp'])
    date_obj = datetime.strptime(packet['date'], "%d/%m/%Y").date()

    values = (
        packet_key,
        packet.get('origin'),
        ts,
        packet.get('timestamp_utc'),
        packet.get('type'),
        packet.get('time'),
        date_obj,
        int(packet['len']),
        int(packet['packet_type']),
        packet.get('route'),
        int(packet['payload_len']),
        packet.get('raw'),
        float(packet['SNR']),
        packet.get('latitude'),
        packet.get('longitude'),
        packet.get('msg_txt'),
        packet.get('msg_sender'),
        packet.get('deviceName'),
        packet.get('deviceRole'),
        int(packet['RSSI']),
        packet.get('hash'),
        json.dumps(packet.get('path', [])),
        packet.get('pathLength'),
        packet.get('channelHash'),
        ', '.join(packet.get('channelName')) if packet.get('channelName') else None,
        json.dumps(packet['transportCodes']) if packet.get('transportCodes') else None,
        packet.get('PublicKey'),
        packet.get('source_hash'),
        packet.get('destination_hash'),
        packet.get('cipher_mac'),
        packet.get('sender_public_key'),
        packet.get('path_hash_size'),
        packet.get('region'),
    )

    query = """
        INSERT INTO packets (
            key_timestamp, origin, timestamp, timestamp_utc, type,
            time, date, len, packet_type, route, payload_len, raw,
            SNR, latitude, longitude, msg_txt, msg_sender,
            deviceName, deviceRole, RSSI, hash_id,
            path, pathLength, channelHash, channelName,
            transportCodes, PublicKey,
            source_hash, destination_hash, cipher_mac, sender_public_key,
            path_hash_size, region
        ) VALUES (
            %s, %s, %s, %s, %s,
            %s, %s, %s, %s, %s, %s, %s,
            %s, %s, %s, %s, %s,
            %s, %s, %s, %s,
            %s, %s, %s, %s,
            %s, %s,
            %s, %s, %s, %s,
            %s, %s
        )
    """

    placeholders = query.count('%s')
    assert placeholders == len(values), \
        f"Placeholder/value mismatch: {placeholders} vs {len(values)}"

    try:
        cursor = conn.cursor()
        cursor.execute(query, values)
        conn.commit()
        cursor.close()
    except mysql.connector.Error as e:
        logging.error("MySQL error (%s) — reconnecting", e)
        conn.reconnect(attempts=3, delay=5)
        cursor = conn.cursor()
        cursor.execute(query, values)
        conn.commit()
        cursor.close()
    logging.info("Inserted %s | %s | %s | hash=%s", packet_key, packet.get('origin'), packet.get('type'), packet.get('hash'))


# ── MQTT callbacks ────────────────────────────────────────────────────────────

def _make_on_message(conn):
    counter = 0

    def on_message(client, userdata, msg):
        nonlocal counter
        counter += 1
        logging.debug("rcvd #%d", counter)

        try:
            received_at = datetime.now(timezone.utc)
            message     = json.loads(msg.payload.decode())
            timestamp   = received_at.strftime("%Y-%m-%d-%H:%M:%S.%f")[:-3]

            packets_dict = {timestamp: message}
            decode_packet(message['raw'], timestamp, packets_dict)

            for pkt in packets_dict.values():
                local_dt, utc_dt = normalize_timestamps(pkt.get('timestamp', ''), received_at)
                if local_dt is not None:
                    pkt['timestamp']     = local_dt.isoformat()
                    pkt['timestamp_utc'] = utc_dt
                    pkt['date']          = local_dt.strftime("%d/%m/%Y")
                    pkt['time']          = local_dt.strftime("%H:%M:%S")

            for key, pkt in packets_dict.items():
                save_packet_to_mysql(conn, key, pkt)
        except Exception as e:
            logging.error("Error processing packet #%d: %s", counter, e)

    return on_message


# ── entry point ───────────────────────────────────────────────────────────────

def main():
    global secret_to_name, hash_to_names, all_secrets, key_store, decrypt_options
    secret_to_name, hash_to_names, all_secrets, key_store, decrypt_options = _build_channel_maps()

    mqtt_host  = os.environ['MQTT_SERVER']
    mqtt_port  = int(os.environ['MQTT_PORT'])
    mqtt_user  = os.environ['MQTT_USERNAME']
    mqtt_pass  = os.environ['MQTT_PASSWORD']
    mqtt_topic = os.environ.get('MQTT_TOPIC_PACKETS', 'meshcore/+/+/packets')

    def on_connect(client, userdata, flags, reason_code, properties):
        if reason_code == 0:
            logging.info("Connected to %s, subscribing to %s", mqtt_host, mqtt_topic)
            client.subscribe(mqtt_topic)
        else:
            logging.error("Connection failed with code %s", reason_code)

    conn = mysql.connector.connect(
        host=os.environ['DB_HOST'],
        database=os.environ['DB_NAME'],
        user=os.environ['DB_USER'],
        port=int(os.environ['DB_PORT']),
        charset='utf8mb4',
        password=os.environ['DB_PASSWORD'],
    )

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.tls_set(tls_version=ssl.PROTOCOL_TLS_CLIENT)
    client.username_pw_set(mqtt_user, mqtt_pass)
    client.on_connect = on_connect
    client.on_message = _make_on_message(conn)
    client.connect(mqtt_host, mqtt_port)
    client.loop_forever()


if __name__ == '__main__':
    main()
