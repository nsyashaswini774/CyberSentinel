import sys
import os

# Ensure backend directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from fastapi.testclient import TestClient
from app.main import app
from app.services.geo_service import lookup_ip_geolocation
from app.services.url_inspector import extract_and_inspect_urls, inspect_single_url
from app.services.hop_analyzer import analyze_network_hops

client = TestClient(app)

results_summary = {}

def log_result(feature_name: str, passed: bool, details: str = ""):
    status = "PASS" if passed else "FAIL"
    results_summary[feature_name] = (status, details)
    mark = "[PASS]" if passed else "[FAIL]"
    print(f"\n{mark} {feature_name}")
    if details:
        print(f"       Details: {details}")

print("=" * 65)
print("  CYBERSENTINEL AI - PHASE 3 VERIFICATION TEST SUITE")
print("=" * 65)

# -------------------------------------------------------------
# 1. Test IP Geolocation Service
# -------------------------------------------------------------
try:
    # Test private IP
    priv_geo = lookup_ip_geolocation("192.168.1.1")
    assert priv_geo["is_private"] is True
    assert priv_geo["country"] == "Private Network"

    # Test public known test IP
    pub_geo = lookup_ip_geolocation("185.220.101.5")
    assert pub_geo["is_private"] is False
    assert pub_geo["country"] == "Germany"
    assert pub_geo["lat"] is not None and pub_geo["lon"] is not None

    # Test another test IP
    nl_geo = lookup_ip_geolocation("198.51.100.42")
    assert nl_geo["country"] == "Netherlands"

    log_result("IP Geolocation Service", True, f"Resolved private IP to LAN and public IPs to Germany ({pub_geo['city']}, {pub_geo['lat']}, {pub_geo['lon']}) and Netherlands.")
except Exception as e:
    log_result("IP Geolocation Service", False, str(e))

# -------------------------------------------------------------
# 2. Test URL Threat Intelligence (Shorteners, Homographs, Mismatched Anchors)
# -------------------------------------------------------------
try:
    # 2a. Shortener
    u_short = inspect_single_url("https://bit.ly/secure-auth-99")
    assert u_short.is_shortener is True
    assert u_short.is_suspicious is True
    assert any("shortening" in r.lower() for r in u_short.reasons)

    # 2b. Homograph / Punycode
    u_homo = inspect_single_url("http://xn--microsft-75a.com/auth")
    assert u_homo.has_homograph is True
    assert u_homo.is_suspicious is True
    assert any("punycode" in r.lower() or "homoglyph" in r.lower() for r in u_homo.reasons)

    # 2c. Mismatched Anchor Text
    u_mismatch = inspect_single_url("http://192.168.1.100/login/verify.php", anchor_text="https://security.enterprise.org/reset-password")
    assert u_mismatch.is_suspicious is True
    assert any("anchor text displays" in r.lower() for r in u_mismatch.reasons)

    # 2d. High-abuse TLD
    u_tld = inspect_single_url("http://portal-verification.buzz/auth")
    assert u_tld.is_suspicious is True
    assert any(".buzz" in r for r in u_tld.reasons)

    log_result("URL & Domain Threat Intelligence", True, "Successfully flagged URL shortener (bit.ly), IDN Punycode homograph, mismatched anchor spoofing, and high-risk TLD (.buzz).")
except Exception as e:
    log_result("URL & Domain Threat Intelligence", False, str(e))

# -------------------------------------------------------------
# 3. Test Hop Routing & Delay Analysis
# -------------------------------------------------------------
try:
    res = client.get("/api/v1/analyze/sample")
    assert res.status_code == 200
    data = res.json()
    hops = data["hops"]

    assert len(hops) >= 3, f"Expected at least 3 hops, got {len(hops)}"
    
    # Check chronological ordering: Hop 1 (node01 185.220.101.5) -> Hop 2 (relay02 198.51.100.42) -> Hop 3 (mx 10.0.0.1)
    hop1 = hops[0]
    hop2 = hops[1]
    hop3 = hops[2]

    assert hop1["ip"] == "185.220.101.5", f"Hop 1 IP mismatch: {hop1['ip']}"
    assert hop1["country"] == "Germany"
    assert hop1["lat"] == 50.1109

    assert hop2["ip"] == "198.51.100.42", f"Hop 2 IP mismatch: {hop2['ip']}"
    assert hop2["country"] == "Netherlands"

    assert hop3["ip"] == "10.0.0.1"
    assert hop3["is_private"] is True

    # Check delay calculation
    assert hop2["delay_seconds"] is not None
    assert hop2["delay_seconds"] >= 0.0

    log_result("Hop Routing & Delay Analysis", True, f"Reconstructed {len(hops)} hops with transit delays (Hop 2 delay: {hop2['delay_seconds']}s) and coordinates ({hop1['city']}, {hop1['country']} -> {hop2['city']}, {hop2['country']}).")
except Exception as e:
    log_result("Hop Routing & Delay Analysis", False, str(e))

# -------------------------------------------------------------
# 4. Test Integration with End-to-End Analysis API
# -------------------------------------------------------------
try:
    # Verify risk factors include Phase 3 rules
    risk_factors = data["threat"]["risk_factors"]
    rf_rules = [rf["rule"] for rf in risk_factors]
    
    assert "MISMATCHED_ANCHOR" in rf_rules, f"MISMATCHED_ANCHOR missing from {rf_rules}"
    assert "HOMOGRAPH_ATTACK" in rf_rules, f"HOMOGRAPH_ATTACK missing from {rf_rules}"
    assert "URL_SHORTENER" in rf_rules, f"URL_SHORTENER missing from {rf_rules}"

    # Verify origin IP in database matches first public relay
    res_hist = client.get("/api/v1/history")
    assert res_hist.status_code == 200
    latest = res_hist.json()[0]
    assert latest["origin_ip"] == "185.220.101.5"
    assert latest["origin_country"] == "Germany"

    log_result("Threat Intel & Geolocation API Integration", True, f"Full pipeline verified: MISMATCHED_ANCHOR, HOMOGRAPH_ATTACK, URL_SHORTENER risk rules triggered; Origin IP {latest['origin_ip']} ({latest['origin_country']}) saved in DB.")
except Exception as e:
    log_result("Threat Intel & Geolocation API Integration", False, str(e))

print("\n" + "=" * 65)
print("              PHASE 3 VERIFICATION SUMMARY")
print("=" * 65)
all_ok = True
for feature, (st, det) in results_summary.items():
    print(f"{feature.ljust(35)}: {st}")
    if st != "PASS":
        all_ok = False

print("=" * 65)
if all_ok:
    print("STATUS: ALL PHASE 3 BACKEND FEATURES 100% OPERATIONAL!")
    sys.exit(0)
else:
    print("STATUS: SOME TESTS FAILED")
    sys.exit(1)
