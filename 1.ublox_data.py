#Author : CHRISTOPHER T. WILLIAMS 3/31/26
#ublox_data.py
import serial
import time
import datetime
import os

COM_PORT = "COM12"
BAUD = 38400

def checksum(payload):
    ck_a = 0
    ck_b = 0
    for byte in payload:
        ck_a = (ck_a + byte) % 256
        ck_b = (ck_b + ck_a) % 256
    return ck_a, ck_b

def build_ubx(cls, msg_id, payload):
    header = [0xB5, 0x62, cls, msg_id]
    length = [len(payload) % 256, (len(payload) // 256) % 256]
    body = header[2:] + length + list(payload)
    ck_a, ck_b = checksum(body)
    return bytes(header + length + list(payload) + [ck_a, ck_b])

def send_ubx(ser, packet, label):
    ser.write(packet)
    time.sleep(0.3)
    response = ser.read(ser.in_waiting or 10)
    if b'\x05\x01' in response:
        status = "ACK"
    elif b'\x05\x00' in response:
        status = "NAK"
    else:
        status = "NO_RESP"
    print(label + " -> " + status)

def cfg_msg(cls_id, msg_id, rate=1):
    payload = bytes([cls_id, msg_id, 0, 0, 0, rate, 0, 0])
    return build_ubx(0x06, 0x01, payload)

print("Connecting to " + COM_PORT + " at " + str(BAUD) + " baud...")
ser = serial.Serial(COM_PORT, BAUD, timeout=1)
time.sleep(1)
ser.reset_input_buffer()
print("Connected.")

print("Step 1: Enabling GPS + SBAS + GLONASS...")
gnss_payload = bytes([
    0x00, 0x00, 0x20, 0x03,
    0x00, 0x08, 0x0E, 0x00, 0x01, 0x00, 0x01, 0x01,
    0x01, 0x01, 0x03, 0x00, 0x01, 0x00, 0x01, 0x01,
    0x06, 0x04, 0x0E, 0x00, 0x01, 0x00, 0x01, 0x01
])
send_ubx(ser, build_ubx(0x06, 0x3E, gnss_payload), "CFG-GNSS GPS+SBAS+GLONASS")
time.sleep(0.5)

print("Step 2: Enabling jamming detection...")
itfm_payload = bytes([0xF3, 0xAC, 0x03, 0x80, 0x47, 0x00, 0x00, 0x00])
send_ubx(ser, build_ubx(0x06, 0x39, itfm_payload), "CFG-ITFM jamming detect")
time.sleep(0.3)

print("Step 3: Enabling evidence messages on USB...")
send_ubx(ser, cfg_msg(0x02, 0x10), "RXM-RAW pseudorange")
send_ubx(ser, cfg_msg(0x02, 0x13), "RXM-SFRBX subframe ephemeris")
send_ubx(ser, cfg_msg(0x01, 0x03), "NAV-STATUS spoofing flags")
send_ubx(ser, cfg_msg(0x01, 0x04), "NAV-DOP dilution")
send_ubx(ser, cfg_msg(0x01, 0x07), "NAV-PVT position fix")
send_ubx(ser, cfg_msg(0x01, 0x22), "NAV-CLOCK GPS/GLONASS timing")
send_ubx(ser, cfg_msg(0x01, 0x30), "NAV-SVINFO satellite info")
send_ubx(ser, cfg_msg(0x01, 0x35), "NAV-SAT satellite status")
send_ubx(ser, cfg_msg(0x0A, 0x09), "MON-HW jamming AGC noise")
time.sleep(0.3)

print("Step 4: Enabling NMEA sentences...")
send_ubx(ser, cfg_msg(0xF0, 0x00), "NMEA-GGA position")
send_ubx(ser, cfg_msg(0xF0, 0x02), "NMEA-GSA DOP active sats")
send_ubx(ser, cfg_msg(0xF0, 0x03), "NMEA-GSV all constellations")
send_ubx(ser, cfg_msg(0xF0, 0x04), "NMEA-RMC minimum data")
send_ubx(ser, cfg_msg(0xF0, 0x01), "NMEA-GLL lat lon")
time.sleep(0.3)

print("Step 5: Setting 1Hz measurement rate...")
rate_payload = bytes([0xE8, 0x03, 0x01, 0x00, 0x01, 0x00])
send_ubx(ser, build_ubx(0x06, 0x08, rate_payload), "CFG-RATE 1Hz")
time.sleep(0.3)

print("Step 6: Saving config to flash...")
save_payload = bytes([
    0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x17
])
send_ubx(ser, build_ubx(0x06, 0x09, save_payload), "CFG-CFG save to flash")
time.sleep(1)

print("Step 7: Starting evidence log...")
os.makedirs("C:\\GNSS_Evidence", exist_ok=True)
ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
ubx_path = "C:\\GNSS_Evidence\\ublox7_" + ts + ".ubx"
nmea_path = "C:\\GNSS_Evidence\\ublox7_" + ts + ".nmea"
meta_path = "C:\\GNSS_Evidence\\ublox7_" + ts + "_meta.txt"

meta = open(meta_path, "w")
meta.write("Session Start UTC: " + ts + "\n")
meta.write("Port: " + COM_PORT + "\n")
meta.write("Baud: " + str(BAUD) + "\n")
meta.write("Complainant: Christopher Thomas Williams\n")
meta.write("DOB: November 24 1986\n")
meta.write("Address: 267 Momento Ave Perris CA 92570\n")
meta.write("GPS Coords: 33.800509 -117.220352\n")
meta.write("Purpose: FCC complaint GPS RF interference evidence\n")
meta.write("Related filing: FCC Enforcement Bureau March 31 2026\n")
meta.flush()

ubx_file = open(ubx_path, "wb")
nmea_file = open(nmea_path, "w")

print("Logging to " + ubx_path)
print("NMEA to    " + nmea_path)
print("Press Ctrl+C to stop.")
print("----------------------------------------")

count = 0
bytes_total = 0

try:
    while True:
        data = ser.read(512)
        if data:
            ubx_file.write(data)
            ubx_file.flush()
            bytes_total = bytes_total + len(data)
            try:
                text = data.decode("ascii", errors="ignore")
                for line in text.split("\n"):
                    line = line.strip()
                    if line.startswith("$"):
                        ts2 = datetime.datetime.utcnow().isoformat()
                        nmea_file.write(ts2 + "," + line + "\n")
                        nmea_file.flush()
                        count = count + 1
                        if count % 60 == 0:
                            print(str(count) + " NMEA lines | " + str(bytes_total) + " bytes")
            except Exception:
                pass
except KeyboardInterrupt:
    end_ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    print("Stopped at " + end_ts)
    print("Total bytes: " + str(bytes_total))
    print("Total NMEA:  " + str(count))
    meta.write("Session End UTC: " + end_ts + "\n")
    meta.write("Total bytes: " + str(bytes_total) + "\n")
    meta.write("Total NMEA lines: " + str(count) + "\n")
    meta.flush()

ubx_file.close()
nmea_file.close()
meta.close()
ser.close()
print("All files closed. Evidence saved to C:\\GNSS_Evidence\\")
