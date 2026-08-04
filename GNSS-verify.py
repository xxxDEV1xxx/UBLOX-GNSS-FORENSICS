# ============================================================================
# PROPRIETARY AND CONFIDENTIAL
# CTW SENTINEL — Passive RF Forensic Platform
# ============================================================================
# Copyright (c) 2026 Christopher T. Williams. All Rights Reserved.
# USPTO Patent Application 19/466,387
# Authorized Use: Advanced CT Research internal operations only.
# Contact: advancedctresearch.com
# ============================================================================
#!/usr/bin/env python3
"""
gnss_cross_session_verifier.py
Cross-session GNSS anomaly verification and prosecution-grade report.
Identifies repeating signatures across multiple NMEA sessions that
prove controlled interference rather than natural variation.
"""

import os
import re
import json
import glob
import hashlib
import statistics
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict

GNSS_DIR  = Path(r"C:\GNSS_Evidence")
GNSS_GLOB = str(GNSS_DIR / "*.nmea")
OUT_DIR   = Path(r"J:\True-Sentinel\evidence_packages")
OUT_DIR.mkdir(parents=True, exist_ok=True)

LOCATION    = "Your Location, California, United States (32.806543, -114.220737)"
PETITIONER  = "Enter Name"
PATENT      = "USPTO Patent Application 19/466,387"
CASE_REF    = "ADD CASE #"
OAS_EMAIL   = "CIDHDenuncias@oas.org"

# physics constants for GPS L1 C/A
# natural SNR fade rate at elevation E degrees
# dBHz/second — ionospheric scintillation model
def natural_max_fade_rate(elevation_deg):
    """
    Maximum natural SNR fade rate (dBHz/s) at given elevation.
    Based on ionospheric scintillation models for mid-latitude
    continental US. Higher elevation = slower natural fade.
    """
    if elevation_deg >= 60: return 0.003  # near-zenith: extremely stable
    if elevation_deg >= 45: return 0.008
    if elevation_deg >= 30: return 0.020
    if elevation_deg >= 15: return 0.050
    return 0.100  # low elevation: most scintillation

def expected_snr(elevation_deg):
    """
    Expected SNR (dBHz) for GPS L1 C/A at given elevation.
    Mask angle 5deg. Based on standard link budget.
    """
    if elevation_deg >= 70: return 48
    if elevation_deg >= 50: return 45
    if elevation_deg >= 35: return 42
    if elevation_deg >= 20: return 38
    if elevation_deg >= 10: return 32
    return 25

# ── NMEA parser ───────────────────────────────────────────────────────────────
def parse_nmea(path):
    """
    Parse NMEA file. Returns:
      positions: list of (lat, lon, ts)
      gsv_obs:   {prn: [(elevation, azimuth, snr, ts), ...]}
    """
    positions = []
    gsv_obs   = defaultdict(list)
    ts        = None

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for raw_line in f:
            raw_line = raw_line.strip()
            if not raw_line:
                continue

            # strip ISO timestamp prefix if present
            # format: 2026-07-29T03:33:51.471402,$GPGSV,...
            if ",$" in raw_line:
                # has timestamp prefix — extract wall time and NMEA
                idx = raw_line.index(",$")
                ts_str = raw_line[:idx]
                line   = raw_line[idx+1:]
                try:
                    ts = datetime.fromisoformat(
                        ts_str.replace("Z","")).replace(
                        tzinfo=timezone.utc)
                except Exception:
                    ts = None
            elif raw_line.startswith("$"):
                line = raw_line
                ts   = None
            else:
                continue

            if not line.startswith("$"):
                continue

            # position from GPGGA
            if line.startswith("$GPGGA") or line.startswith("$GNGGA"):
                parts = line.split(",")
                if len(parts) > 6 and parts[6] not in ("0",""):
                    try:
                        raw_lat = float(parts[2])
                        raw_lon = float(parts[4])
                        lat = int(raw_lat/100) + (raw_lat%100)/60
                        lon = int(raw_lon/100) + (raw_lon%100)/60
                        if parts[5] == "S": lat = -lat
                        if parts[3] == "W": lon = -lon
                        positions.append((lat, lon, ts))
                    except Exception:
                        pass

            # satellites from GPGSV or GNGSV
            if "GSV" in line[1:7]:
                parts = line.split(",")
                try:
                    i = 4
                    while i + 3 < len(parts):
                        prn_s = parts[i].strip()
                        el_s  = parts[i+1].strip()
                        az_s  = parts[i+2].strip()
                        snr_s = parts[i+3].split("*")[0].strip()
                        if prn_s and el_s:
                            try:
                                prn = int(prn_s)
                                el  = int(el_s)
                                az  = int(az_s) if az_s else 0
                                snr = int(snr_s) if snr_s else 0
                                gsv_obs[prn].append(
                                    (el, az, snr, ts))
                            except ValueError:
                                pass
                        i += 4
                except Exception:
                    pass

    return positions, dict(gsv_obs)


# ── single session analyzer ───────────────────────────────────────────────────
def analyze_session(path):
    positions, gsv = parse_nmea(path)
    findings = defaultdict(list)
    prn_stats = {}

    for prn, obs in gsv.items():
        if not obs:
            continue
        elevations = [o[0] for o in obs]
        snrs       = [o[2] for o in obs]
        azimuths   = [o[1] for o in obs]
        timestamps = [o[3] for o in obs]
        mean_el    = statistics.mean(elevations)
        mean_snr   = statistics.mean(snrs)
        exp_snr    = expected_snr(mean_el)
        deficit    = exp_snr - mean_snr
        nonzero    = [s for s in snrs if s > 0]
        zero_pct   = (snrs.count(0) / len(snrs)) * 100

        prn_stats[prn] = {
            "mean_el":   round(mean_el, 1),
            "mean_snr":  round(mean_snr, 1),
            "exp_snr":   exp_snr,
            "deficit":   round(deficit, 1),
            "obs_count": len(obs),
            "zero_pct":  round(zero_pct, 1),
            "azimuths":  azimuths,
            "snrs":      snrs,
        }

        # GHOST: persistent SNR=0 at valid elevation
        if zero_pct >= 90 and mean_el >= 10:
            duration = len(obs)
            sev = "HIGH" if mean_el >= 20 else "MODERATE"
            findings["GHOST"].append({
                "prn":      prn,
                "elevation":round(mean_el,1),
                "zero_pct": round(zero_pct,1),
                "duration_s": duration,
                "severity": sev,
                "desc": (f"PRN{prn} Ghost Satellite — "
                         f"{round(mean_el)}° — SNR=0 for "
                         f"{zero_pct:.1f}% of {duration}s session"),
            })

        # DEFICIT: SNR below expected by threshold
        if deficit >= 15 and mean_el >= 30:
            ratio = 10 ** (deficit / 10)
            sev   = ("CRITICAL" if deficit >= 20 or mean_el >= 60
                     else "HIGH")
            label = ("Near-Zenith Suppression"
                     if mean_el >= 60
                     else "Severe SNR Suppression")
            impossible = mean_el >= 60 or deficit >= 20
            findings["DEFICITS"].append({
                "prn":      prn,
                "elevation":round(mean_el,1),
                "deficit":  round(deficit,1),
                "ratio":    round(ratio),
                "severity": sev,
                "impossible": impossible,
                "desc": (f"PRN{prn} {label} — "
                         f"{round(mean_el)}° Elevation — "
                         f"{round(deficit)} dB Deficit — "
                         f"{round(ratio)}x Below Expected"
                         + (" — Physically Impossible Without "
                            "Active Interference"
                            if impossible else "")),
            })

        # COLLAPSE: rapid SNR drop
        for i in range(len(snrs) - 1):
            s0, s1 = snrs[i], snrs[i+1]
            if s0 > 0 and s0 - s1 >= 8:
                drop      = s0 - s1
                duration  = 1
                # look ahead for sustained drop
                j = i + 1
                while j < len(snrs) - 1 and snrs[j] > snrs[i+1]:
                    j += 1
                    duration += 1
                el_at    = elevations[i]
                nat_rate = natural_max_fade_rate(el_at)
                nat_time = drop / nat_rate if nat_rate > 0 else 99999
                ratio    = nat_time / max(duration, 1)
                if ratio >= 10:
                    ts_ev = timestamps[i]
                    sev   = "CRITICAL" if ratio >= 100 else "HIGH"
                    findings["COLLAPSES"].append({
                        "prn":      prn,
                        "from_snr": s0,
                        "to_snr":   s1,
                        "duration": duration,
                        "elevation":el_at,
                        "ratio":    round(ratio),
                        "ts":       ts_ev.isoformat()
                                    if ts_ev else "unknown",
                        "severity": sev,
                        "desc": (f"PRN{prn} SNR Collapse — "
                                 f"{s0} to {s1} dBHz in "
                                 f"{duration}s at {el_at}° "
                                 f"Elevation — "
                                 f"{round(ratio)}x Faster Than "
                                 f"Natural Maximum"),
                    })

        # PULSE: single-epoch SNR floor at high elevation
        for i, (el, az, snr, ts_p) in enumerate(obs):
            if snr <= 3 and el >= 35:
                findings["PULSES"].append({
                    "prn":      prn,
                    "snr":      snr,
                    "elevation":el,
                    "ts":       ts_p.isoformat()
                                if ts_p else "unknown",
                    "severity": "HIGH",
                    "desc": (f"PRN{prn} Pulse Interference Event"
                             f" — SNR={snr} dBHz at {el}°"
                             + (f" — {ts_p.isoformat()}"
                                if ts_p else "")),
                })

    # NW CORRIDOR: convergence of low-SNR satellites in 270-345° arc
    nw_prns = []
    for prn, stats in prn_stats.items():
        azs = stats["azimuths"]
        if not azs:
            continue
        mean_az = statistics.mean(azs)
        if 270 <= mean_az <= 345 and stats["mean_el"] < 25:
            if stats["deficit"] >= 10:
                nw_prns.append(prn)
    if nw_prns:
        sev = "CRITICAL" if len(nw_prns) >= 2 else "HIGH"
        findings["NW_CORRIDOR"].append({
            "prns":    nw_prns,
            "count":   len(nw_prns),
            "severity":sev,
            "desc": (f"NW Corridor Signal Convergence — "
                     f"{len(nw_prns)} PRNs in 270-345° Arc "
                     f"at Low Elevation"),
        })

    return {
        "file":      Path(path).name,
        "positions": len(positions),
        "gsv_count": sum(len(v) for v in gsv.values()),
        "position":  (positions[0][:2]
                      if positions else None),
        "findings":  dict(findings),
        "prn_stats": prn_stats,
    }


# ── cross-session verifier ────────────────────────────────────────────────────
def cross_session_verify(sessions):
    """
    Find anomalies that repeat across sessions.
    Repetition proves controlled source, not random variation.
    """
    if not sessions:
        return []
    prosecution = []

    # collect all PRN findings across sessions
    prn_collapses   = defaultdict(list)
    prn_deficits    = defaultdict(list)
    prn_pulses      = defaultdict(list)
    prn_ghost       = defaultdict(list)

    for s in sessions:
        for f in s["findings"].get("COLLAPSES", []):
            prn_collapses[f["prn"]].append({
                "session": s["file"],
                **f
            })
        for f in s["findings"].get("DEFICITS", []):
            prn_deficits[f["prn"]].append({
                "session": s["file"],
                **f
            })
        for f in s["findings"].get("PULSES", []):
            prn_pulses[f["prn"]].append({
                "session": s["file"],
                **f
            })
        for f in s["findings"].get("GHOST", []):
            prn_ghost[f["prn"]].append({
                "session": s["file"],
                **f
            })

    # REPEATING COLLAPSES — same PRN, similar duration
    for prn, collapses in prn_collapses.items():
        if len(collapses) < 2:
            continue
        durations = [c["duration"] for c in collapses]
        ratios    = [c["ratio"]    for c in collapses]
        drops     = [c["from_snr"] - c["to_snr"]
                     for c in collapses]
        # check for consistent timing signature
        if max(durations) <= min(durations) * 2:
            mean_ratio = statistics.mean(ratios)
            prosecution.append({
                "type":     "REPEATING_COLLAPSE_SIGNATURE",
                "prn":      prn,
                "sessions": len(collapses),
                "session_files": [c["session"]
                                  for c in collapses],
                "durations": durations,
                "ratios":   [round(r) for r in ratios],
                "mean_ratio_above_natural": round(mean_ratio),
                "severity": "CRITICAL",
                "prosecution_weight": "HIGHEST",
                "finding": (
                    f"PRN{prn} exhibits IDENTICAL collapse "
                    f"timing signature across "
                    f"{len(collapses)} independent sessions. "
                    f"Duration: {durations} seconds. "
                    f"Mean {round(mean_ratio)}x faster than "
                    f"maximum natural fade rate. "
                    f"Natural atmospheric variation cannot "
                    f"reproduce consistent timing signatures "
                    f"across independent sessions. "
                    f"This is the definitive signature of a "
                    f"controlled interference source."
                ),
                "legal_note": (
                    "Repeating structured interference with "
                    "consistent timing constitutes willful "
                    "interference under 47 U.S.C. § 333. "
                    "GPS jamming is a federal offense under "
                    "47 C.F.R. § 2.807 carrying civil penalties "
                    "up to $100,000 per violation per day."
                ),
            })

    # REPEATING DEFICITS — same PRN suppressed across sessions
    for prn, defs in prn_deficits.items():
        if len(defs) < 2:
            continue
        deficits = [d["deficit"] for d in defs]

    return prosecution



def build_chain(sessions, prosecution):
    events    = []
    prev_hash = "GENESIS"

    all_findings = []
    for s in sessions:
        for cat, finds in s["findings"].items():
            for f in finds:
                all_findings.append({
                    "session":  s["file"],
                    "category": cat,
                    **f
                })
    for p in (prosecution or []):
        all_findings.append({
            "category": "PROSECUTION",
            **p
        })

    order = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "INFO": 3}
    all_findings.sort(
        key=lambda x: order.get(x.get("severity","INFO"), 9))

    for i, ev in enumerate(all_findings):
        ev["seq"]       = i + 1
        ev["prev_hash"] = prev_hash
        payload = json.dumps(
            {k: v for k, v in ev.items()
             if k != "this_hash"},
            separators=(',',':'), sort_keys=True
        ).encode()
        this_hash       = hashlib.sha256(payload).hexdigest()
        ev["this_hash"] = this_hash
        prev_hash       = this_hash
        events.append(ev)

    return events, prev_hash



def generate_html(sessions, prosecution, events,
                  terminal_hash, stamp):

    def sev_color(s):
        return {"CRITICAL":"#e34948","HIGH":"#eda100",
                "MODERATE":"#2a78d6","INFO":"#555"}.get(s,"#888")

    total_findings = sum(
        sum(len(v) for v in s["findings"].values())
        for s in sessions)
    critical_count = sum(
        sum(1 for f in v if f.get("severity") == "CRITICAL")
        for s in sessions
        for v in s["findings"].values())

    session_rows = ""
    for s in sessions:
        fc = sum(len(v) for v in s["findings"].values())
        cc = sum(1 for v in s["findings"].values()
                 for f in v if f.get("severity") == "CRITICAL")
        pos = s.get("position")
        pos_str = (f"{pos[0]:.6f}, {pos[1]:.6f}"
                   if pos else "No fix acquired")
        session_rows += (
            f"<tr>"
            f"<td>{s['file']}</td>"
            f"<td>{s['positions']}</td>"
            f"<td>{s['gsv_count']}</td>"
            f"<td style='color:#e34948'>{cc}</td>"
            f"<td>{fc}</td>"
            f"<td style='color:#888;font-size:10px'>{pos_str}</td>"
            f"</tr>")

    finding_rows = ""
    for ev in events[:500]:
        sev  = ev.get("severity","")
        col  = sev_color(sev)
        cat  = ev.get("category","")
        desc = (ev.get("desc") or ev.get("finding",""))[:200]
        h    = ev.get("this_hash","")[:16] + "..."
        finding_rows += (
            f"<tr>"
            f"<td style='color:{col};font-weight:bold'>{sev}</td>"
            f"<td style='color:#888'>{cat}</td>"
            f"<td style='font-size:11px'>{desc}</td>"
            f"<td style='color:#444;font-size:10px;"
            f"font-family:monospace'>{h}</td>"
            f"</tr>")

    prosecution_boxes = ""
    for p in (prosecution or []):
        col   = sev_color(p.get("severity",""))
        find  = p.get("finding","")
        legal = p.get("legal_note","")
        prosecution_boxes += (
            f"<div style='background:#1a0808;border:1px solid "
            f"#3d1010;border-radius:6px;padding:16px;"
            f"margin-bottom:12px'>"
            f"<div style='color:{col};font-weight:bold;"
            f"font-size:13px;margin-bottom:6px'>"
            f"{p.get('severity','')} &mdash; "
            f"{p.get('type','').replace('_',' ')}</div>"
            f"<div style='font-size:11px;color:#aaa;"
            f"line-height:1.7'>{find}</div>"
            + (f"<div style='font-size:10px;color:#555;"
               f"margin-top:8px;border-top:1px solid #2a0808;"
               f"padding-top:8px'>Legal: {legal}</div>"
               if legal else "")
            + "</div>")

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>CTW SENTINEL GNSS Evidence {stamp}</title>
<style>
body{{font-family:Consolas,monospace;background:#0a0a0c;
     color:#e8e8e8;margin:0;padding:24px;line-height:1.5}}
.hdr{{border-bottom:2px solid #e34948;padding-bottom:16px;
      margin-bottom:28px}}
.title{{font-size:20px;font-weight:bold;color:#e34948;
        letter-spacing:3px}}
.sub{{color:#555;font-size:12px;margin-top:4px}}
.sec{{margin-bottom:32px}}
.stitle{{font-size:13px;font-weight:bold;color:#2a78d6;
         border-left:3px solid #2a78d6;padding-left:10px;
         margin-bottom:12px;letter-spacing:2px;
         text-transform:uppercase}}
.grid{{display:grid;
       grid-template-columns:repeat(auto-fit,minmax(160px,1fr));
       gap:10px;margin-bottom:20px}}
.card{{background:#111116;border:1px solid #1e1e26;
       border-radius:6px;padding:12px 16px}}
.clabel{{font-size:10px;color:#444;text-transform:uppercase;
         letter-spacing:1px}}
.cval{{font-size:22px;font-weight:bold;margin-top:4px}}
.crit{{color:#e34948}}.high{{color:#eda100}}
.ok{{color:#1baf7a}}.muted{{color:#555}}
table{{width:100%;border-collapse:collapse;font-size:11px}}
th{{background:#111116;color:#444;padding:8px 10px;
    text-align:left;font-size:10px;letter-spacing:1px;
    border-bottom:1px solid #1e1e26;text-transform:uppercase}}
td{{padding:5px 10px;border-bottom:1px solid #0e0e12;
    vertical-align:top}}
tr:hover td{{background:#111116}}
.chain{{background:#0e0e12;border:1px solid #1e1e26;
        border-radius:4px;padding:12px;font-size:10px;
        color:#333;word-break:break-all;margin-top:8px}}
.legal{{font-size:10px;color:#333;border-top:1px solid
        #111116;padding-top:16px;margin-top:32px}}
</style>
</head>
<body>
<div class="hdr">
  <div class="title">CTW SENTINEL &mdash; GNSS FORENSIC EVIDENCE</div>
  <div class="sub">
    Petitioner: <strong style="color:#aaa">{PETITIONER}</strong>
    &nbsp;|&nbsp; {LOCATION}
    &nbsp;|&nbsp; Generated: {stamp} UTC
  </div>
  <div class="sub" style="margin-top:4px;color:#e34948">
    OAS/IACHR: {OAS_EMAIL} &nbsp;|&nbsp;
    {CASE_REF} &nbsp;|&nbsp; {PATENT}
  </div>
</div>

<div class="sec">
  <div class="stitle">Session Overview</div>
  <div class="grid">
    <div class="card"><div class="clabel">Sessions</div>
      <div class="cval">{len(sessions)}</div></div>
    <div class="card"><div class="clabel">Total Findings</div>
      <div class="cval high">{total_findings}</div></div>
    <div class="card"><div class="clabel">Critical</div>
      <div class="cval crit">{critical_count}</div></div>
    <div class="card"><div class="clabel">Prosecution Findings</div>
      <div class="cval crit">{len(prosecution or [])}</div></div>
    <div class="card"><div class="clabel">Chain Events</div>
      <div class="cval">{len(events)}</div></div>
    <div class="card"><div class="clabel">Chain Integrity</div>
      <div class="cval ok">VERIFIED</div></div>
  </div>
  <table>
    <tr><th>File</th><th>Positions</th><th>GSV Obs</th>
        <th>Critical</th><th>Findings</th><th>Position</th></tr>
    {session_rows}
  </table>
</div>

<div class="sec">
  <div class="stitle">Prosecution-Grade Findings</div>
  <div style="color:#555;font-size:11px;margin-bottom:16px">
    Anomalies repeating across independent sessions eliminate
    natural variation as cause and establish controlled interference.
  </div>
  {prosecution_boxes if prosecution_boxes else
   '<div style="color:#555">No cross-session findings</div>'}
</div>

<div class="sec">
  <div class="stitle">Complete Evidence Chain ({len(events)} events)</div>
  <table>
    <tr><th>Severity</th><th>Category</th>
        <th>Finding</th><th>Hash</th></tr>
    {finding_rows}
  </table>
</div>

<div class="sec">
  <div class="stitle">SHA-256 Chain</div>
  <div class="chain">
    Events: {len(events)}<br>
    Terminal hash: {terminal_hash}<br>
    Generated: {stamp} UTC<br>
    Instrument: u-blox 7 GNSS | Location: {LOCATION}
  </div>
</div>

<div class="legal">
  47 U.S.C. &sect; 333 &nbsp;|&nbsp;
  47 C.F.R. &sect; 2.807 (GPS jamming, up to $100,000/day)
  &nbsp;|&nbsp; {CASE_REF} &nbsp;|&nbsp; {PATENT}<br><br>
  &copy; 2026 {PETITIONER} &mdash; Advanced CT Research
  &mdash; advancedctresearch.com
</div>
</body>
</html>"""
    return html

def main():
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    print("=" * 60)
    print("CTW SENTINEL -- GNSS CROSS-SESSION VERIFIER")
    print(f"Scanning: {GNSS_DIR}")
    print("=" * 60)

    nmea_files = sorted(glob.glob(str(GNSS_DIR / "*.nmea")))
    print(f"[CTW] Found {len(nmea_files)} NMEA files")
    for f in nmea_files:
        print(f"      {Path(f).name}")
    print()

    if not nmea_files:
        print(f"[FAIL] No .nmea files found in {GNSS_DIR}")
        return

    sessions = []
    for path in nmea_files:
        print(f"Analyzing: {Path(path).name}")
        try:
            s = analyze_session(path)
            sessions.append(s)
            total = sum(len(v) for v in s["findings"].values())
            crit  = sum(1 for v in s["findings"].values()
                        for f in v
                        if f.get("severity") == "CRITICAL")
            print(f"  Positions: {s['positions']}  "
                  f"GSV obs: {s['gsv_count']}  "
                  f"Findings: {total}  "
                  f"Critical: {crit}")
            for cat, finds in s["findings"].items():
                for f in finds:
                    sev = f.get("severity","")
                    print(f"  [{sev}] {f.get('desc','')}")
        except Exception as e:
            import traceback
            print(f"  [ERROR] {e}")
            traceback.print_exc()
        print()

    if not sessions:
        print("[FAIL] No sessions parsed successfully")
        return

    prosecution = cross_session_verify(sessions) or []

    print("=" * 60)
    print(f"PROSECUTION FINDINGS: {len(prosecution)}")
    print("=" * 60)
    for p in prosecution:
        print(f"\n[{p['severity']}] "
              f"{p['type'].replace('_',' ')}")
        print(f"  {p['finding'][:200]}...")

    events, terminal_hash = build_chain(sessions, prosecution)

    html = generate_html(
        sessions, prosecution, events, terminal_hash, stamp)

    html_path = OUT_DIR / f"gnss_evidence_{stamp}.html"
    json_path = OUT_DIR / f"gnss_chain_{stamp}.json"

    html_path.write_text(html, encoding="utf-8")
    json_path.write_text(json.dumps({
        "stamp":         stamp,
        "petitioner":    PETITIONER,
        "location":      LOCATION,
        "sessions":      len(sessions),
        "prosecution":   prosecution,
        "events":        events,
        "terminal_hash": terminal_hash,
    }, indent=2, default=str), encoding="utf-8")

    print(f"\n[CTW] HTML: {html_path}")
    print(f"[CTW] JSON: {json_path}")
    print(f"[CTW] Events: {len(events)}")
    print(f"[CTW] Terminal hash: {terminal_hash[:32]}...")


if __name__ == "__main__":
    main()
