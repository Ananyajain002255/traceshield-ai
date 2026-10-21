
import io
import json
import re
import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse

import cv2
import numpy as np
import pandas as pd
import streamlit as st
from PIL import Image

st.set_page_config(
    page_title="TraceShield AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------- Design system ----------

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@400;500;600;700&display=swap');
.stApp {
    background: radial-gradient(ellipse at 85% 0%, #172747 0%, transparent 38%), #080d18;
    color: #edf4ff;
    font-family: 'DM Sans', sans-serif;
}
h1,h2,h3 {font-family:'Space Grotesk',sans-serif!important;letter-spacing:-.5px}
.block-container {max-width:1400px;padding-top:2rem}
[data-testid="stSidebar"] {background:#0c1423;border-right:1px solid #26344a}
[data-testid="stMetric"] {
    background:linear-gradient(145deg,#152239,#101827);
    border:1px solid #26344a;border-radius:16px;padding:17px;
}
[data-testid="stMetricLabel"] {color:#a8bad2}
[data-testid="stMetricValue"] {color:#edf4ff}
.stTextInput input,.stTextArea textarea {
    background:#101a2b!important;color:#edf4ff!important;
    border:1px solid #34445d!important;border-radius:10px!important;
}
.stButton>button,.stDownloadButton>button {
    border-radius:10px;min-height:43px;font-weight:600;
    border:1px solid #34445d;transition:all .2s;
}
.stButton>button[kind="primary"] {
    background:linear-gradient(100deg,#32cfc0,#71e9d9);
    color:#07121c;border:0;
}
.stButton>button:hover {border-color:#54e3d1;transform:translateY(-1px)}
.hero {
    padding:30px;background:linear-gradient(125deg,#14233b,#101725 65%,#18213c);
    border:1px solid #30435d;border-radius:22px;margin-bottom:22px;
}
.kicker {color:#54e3d1;font-size:12px;letter-spacing:2px;font-weight:700}
.muted {color:#a9bad1;font-size:14px;line-height:1.7}
.pill {
    display:inline-block;border:1px solid #34445d;background:#18243a;
    color:#c9d7ea;padding:5px 10px;border-radius:100px;font-size:12px;margin-right:5px
}
hr {border-color:#26344a!important}
footer {visibility:hidden}
</style>
""", unsafe_allow_html=True)

# ---------- Session state ----------

if "history" not in st.session_state:
    st.session_state.history = []
if "page" not in st.session_state:
    st.session_state.page = "Overview"

PAGES = [
    "Overview", "URL Investigator", "QR Scanner",
    "Message Lab", "Investigation History", "Methodology"
]


# ---------- URL analysis ----------

def parse_url(raw):
    raw = raw.strip()
    if not raw:
        raise ValueError("Enter a URL first.")
    if len(raw) > 2048:
        raise ValueError("URL exceeds the 2048-character limit.")
    if any(c.isspace() or ord(c) < 32 for c in raw):
        raise ValueError("URL contains whitespace or control characters.")

    candidate = raw if "://" in raw else "https://" + raw
    p = urlparse(candidate)

    if p.scheme.lower() not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")
    if not p.hostname:
        raise ValueError("A valid hostname could not be identified.")
    if p.username is not None or p.password is not None:
        raise ValueError("URLs containing embedded credentials are rejected.")

    try:
        host = p.hostname.encode("idna").decode("ascii").lower()
        _ = p.port
    except (UnicodeError, ValueError):
        raise ValueError("Hostname or port is invalid.")

    return candidate, p, host


def url_scan(raw):
    candidate, p, host = parse_url(raw)
    findings = []
    score = 0

    def flag(points, name, explanation):
        nonlocal score
        score += points
        findings.append({
            "indicator": name,
            "explanation": explanation,
            "points": points,
        })

    try:
        ipaddress.ip_address(host.strip("[]"))
        flag(25, "IP address as hostname",
             "The destination uses an IP address instead of a conventional domain.")
    except ValueError:
        pass

    if p.scheme.lower() == "http":
        flag(8, "HTTP scheme",
             "The URL does not specify HTTPS. This alone does not establish maliciousness.")

    if len(candidate) > 100:
        flag(8, "Long URL", "Long URLs can obscure the destination.")
    if len(candidate) > 180:
        flag(7, "Very long URL", "The URL contains an especially long string.")
    if "@" in p.netloc:
        flag(20, "At-sign in authority",
             "An @ character can make the intended destination harder to interpret.")
    if host.count(".") >= 4:
        flag(12, "Deep subdomain structure",
             "The hostname contains multiple subdomain levels.")
    if host.startswith("xn--") or ".xn--" in host:
        flag(12, "Punycode hostname",
             "The hostname contains an internationalised label that merits inspection.")
    if "-" in host:
        flag(5, "Hyphenated hostname",
             "Hyphens can be legitimate, but should be considered alongside other evidence.")
    if len(host) > 50:
        flag(7, "Long hostname", "The hostname is unusually long.")
    if re.search(r"https?%3a|%40|%2f%2f", candidate, re.I):
        flag(12, "Encoded delimiters",
             "Encoded URL delimiters may make the destination less readable.")

    words = {
        "login": 5, "verify": 6, "secure": 4, "account": 4,
        "password": 8, "wallet": 7, "banking": 6,
        "signin": 6, "confirm": 4, "recovery": 5,
    }
    matched = [w for w in words if w in candidate.lower()]
    if matched:
        flag(min(15, sum(words[w] for w in matched)),
             "Sensitive-action keywords",
             "Found terms commonly used in both legitimate and fraudulent flows: "
             + ", ".join(matched) + ".")

    if re.search(r"(.)\1{5,}", host):
        flag(8, "Repeated hostname characters",
             "The hostname contains a long run of repeated characters.")

    score = min(score, 100)

    if not findings:
        findings.append({
            "indicator": "No listed rule triggered",
            "explanation": "This limited ruleset found no listed indicator. This does not prove safety.",
            "points": 0,
        })

    if score >= 50:
        level, category = "HIGH INDICATOR SCORE", "High"
        advice = "Avoid opening the link or sharing information. Verify through the organisation's official website."
    elif score >= 25:
        level, category = "ELEVATED INDICATOR SCORE", "Elevated"
        advice = "Inspect the destination and verify it independently before proceeding."
    else:
        level, category = "LOWER INDICATOR SCORE", "Lower"
        advice = "Few listed indicators were found. Independently verify the destination; low score does not mean safe."

    return {
        "id": make_id(),
        "timestamp": now(),
        "type": "URL",
        "input": raw[:500],
        "score": score,
        "level": level,
        "category": category,
        "findings": findings,
        "advice": advice,
        "method": "Transparent URL heuristic rules v1",
        "limitations": "Not a trained ML model, calibrated probability, live reputation check, or guarantee of safety.",
    }


# ---------- Message analysis ----------

def message_scan(text):
    text = text.strip()
    if not text:
        raise ValueError("Paste a message first.")
    if len(text) > 12000:
        raise ValueError("Message exceeds the 12,000-character limit.")

    findings = []
    score = 0

    def flag(points, name, explanation):
        nonlocal score
        score += points
        findings.append({
            "indicator": name,
            "explanation": explanation,
            "points": points,
        })

    rules = [
        (r"\b(urgent|immediately|act now|expires today|within 24 hours)\b",
         12, "Urgency language", "The wording may pressure the recipient to act quickly."),
        (r"\b(password|otp|one.time.password|pin|cvv|passcode)\b",
         18, "Credential-related terms", "The message mentions authentication secrets."),
        (r"\b(account suspended|account blocked|account locked|verify your account)\b",
         18, "Account threat", "The message may pressure the recipient to resolve an account issue."),
        (r"\b(prize|winner|claim your reward|free gift|lottery)\b",
         12, "Unexpected reward", "Unexpected prizes can be used in social-engineering attempts."),
        (r"\b(gift card|wire transfer|crypto payment|send money)\b",
         16, "Payment-related language", "The message references a payment or transfer."),
        (r"\b(click here|open the link|verify now|confirm your details)\b",
         12, "Action prompt", "The wording asks the recipient to take an online action."),
        (r"\b(keep this secret|do not tell anyone|confidential payment)\b",
         15, "Secrecy pressure", "The message uses secrecy language associated with some scams."),
    ]

    for pattern, points, title, explanation in rules:
        if re.search(pattern, text, re.I):
            flag(points, title, explanation)

    urls = re.findall(r"""(?i)\b(?:https?://|www\.)[^\s<>"']+""", text)
    urls = list(dict.fromkeys(u.rstrip(".,!?;:)]}") for u in urls))[:10]

    if urls:
        flag(8, "Embedded links",
             f"Found {len(urls)} URL(s). Their presence alone does not prove fraud.")

    score = min(score, 100)
    if not findings:
        findings.append({
            "indicator": "No listed message rule triggered",
            "explanation": "Sophisticated scams may avoid these patterns; absence of a match is not proof of legitimacy.",
            "points": 0,
        })

    if score >= 45:
        level, category = "HIGH INDICATOR SCORE", "High"
        advice = "Do not share credentials or payment details. Verify through a separately obtained official contact."
    elif score >= 22:
        level, category = "ELEVATED INDICATOR SCORE", "Elevated"
        advice = "Pause and verify the sender and request through another trusted channel."
    else:
        level, category = "LOWER INDICATOR SCORE", "Lower"
        advice = "Few listed indicators were found. This does not establish that the message is legitimate."

    return {
        "id": make_id(),
        "timestamp": now(),
        "type": "Message",
        "input": text[:500],
        "score": score,
        "level": level,
        "category": category,
        "findings": findings,
        "urls": urls,
        "advice": advice,
        "method": "Transparent message-pattern rules v1",
        "limitations": "Not a trained NLP classifier, sender verification, or guarantee of phishing detection.",
    }


# ---------- QR analysis ----------

def qr_scan(data):
    try:
        img = Image.open(io.BytesIO(data)).convert("RGB")
    except Exception:
        raise ValueError("The uploaded file is not a readable image.")

    if img.width * img.height > 16_000_000:
        raise ValueError("Image dimensions are too large.")

    detector = cv2.QRCodeDetector()
    decoded, _, _ = detector.detectAndDecode(np.array(img))

    if not decoded:
        raise ValueError("No readable QR code found. Try a clearer image.")

    result = {
        "id": make_id(),
        "timestamp": now(),
        "type": "QR Code",
        "input": decoded[:500],
        "decoded_content": decoded[:2000],
        "score": None,
        "level": "CONTENT DECODED",
        "category": "Unassessed",
        "findings": [{
            "indicator": "QR content decoded",
            "explanation": "Decoding does not prove the content is safe or malicious.",
            "points": 0,
        }],
        "advice": "Do not open unexpected QR destinations before verifying them.",
        "method": "Local QR decoding with OpenCV",
        "limitations": "QR decoding alone does not establish trustworthiness.",
    }

    if re.match(r"(?i)^https?://", decoded.strip()):
        try:
            u = url_scan(decoded.strip())
            result.update({
                "score": u["score"],
                "level": u["level"],
                "category": u["category"],
                "findings": u["findings"],
                "advice": u["advice"],
                "method": "QR decoding + URL heuristic rules v1",
                "limitations": u["limitations"],
            })
        except ValueError as exc:
            result["findings"].append({
                "indicator": "URL could not be assessed",
                "explanation": str(exc),
                "points": 0,
            })
            result["level"] = "UNASSESSED"

    return result


# ---------- Shared UI helpers ----------

def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def make_id():
    return "TS-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")


def save_result(result):
    st.session_state.history.insert(0, result)
    st.session_state.history = st.session_state.history[:100]


def show_result(r):
    st.divider()
    st.subheader("Investigation report")

    a, b, c = st.columns(3)
    a.metric("Risk indicator score", f"{r['score']}/100" if r.get("score") is not None else "N/A")
    b.metric("Assessment", r.get("level", "UNASSESSED"))
    c.metric("Evidence indicators", len(r.get("findings", [])))

    if r.get("category") == "High":
        st.error("High indicator score. This is not a confirmed malicious verdict.")
    elif r.get("category") == "Elevated":
        st.warning("Elevated indicator score. Verify independently.")
    else:
        st.info("A lower score does not establish that the content is safe.")

    if r.get("score") is not None:
        st.progress(max(0, min(100, int(r["score"]))) / 100)

    st.markdown("### Evidence breakdown")
    for f in r.get("findings", []):
        with st.container(border=True):
            st.markdown(f"**{f['indicator']}**")
            st.write(f["explanation"])
            if f.get("points"):
                st.caption(f"Heuristic contribution: +{f['points']} points")

    if r.get("decoded_content"):
        st.markdown("### Decoded QR content")
        st.code(r["decoded_content"], language=None)

    if r.get("urls"):
        st.markdown("### Extracted links")
        for u in r["urls"]:
            st.code(u, language=None)

    st.markdown("### Recommended action")
    st.write(r.get("advice", "Verify independently."))

    with st.expander("Methodology and limitations"):
        st.write(r.get("method", ""))
        st.write(r.get("limitations", ""))
        st.caption("Investigation ID: " + r["id"])

    st.download_button(
        "Download JSON report",
        data=json.dumps(r, indent=2, ensure_ascii=False),
        file_name=f"{r['id']}.json",
        mime="application/json",
        key="report_" + r["id"],
    )


# ---------- Sidebar navigation ----------

with st.sidebar:
    st.markdown("## 🛡️ TraceShield AI")
    st.caption("EXPLAINABLE DIGITAL TRUST")
    st.divider()

    page = st.radio(
        "WORKSPACE",
        PAGES,
        key="page",
        label_visibility="collapsed",
    )

    st.divider()
    st.markdown('<span class="pill">LOCAL ANALYSIS</span>', unsafe_allow_html=True)
    st.caption("No automatic URL fetching.")
    st.caption("History is session-only and is not a permanent database.")

# ---------- Header ----------

st.markdown("""
<div class="hero">
  <div class="kicker">CYBERSECURITY · EXPLAINABLE INVESTIGATION</div>
  <h1 style="margin-top:12px">See the signal.<br>Understand the threat.</h1>
  <p style="color:#a9bad1;line-height:1.7">
    Investigate suspicious links, QR codes and digital messages
    with transparent indicators and practical safety recommendations.
  </p>
  <span class="pill">URL INVESTIGATION</span>
  <span class="pill">QR INTELLIGENCE</span>
  <span class="pill">MESSAGE LAB</span>
</div>
""", unsafe_allow_html=True)

# ---------- Pages ----------

if page == "Overview":
    history = st.session_state.history
    high = sum(x.get("category") == "High" for x in history)
    elevated = sum(x.get("category") == "Elevated" for x in history)

    a, b, c, d = st.columns(4)
    a.metric("Investigations", len(history))
    b.metric("High indicator scores", high)
    c.metric("Elevated scores", elevated)
    d.metric("Analysis modules", 3)

    st.markdown("## Investigation workspace")
    st.caption("Choose a module to begin an investigation.")

    c1, c2, c3 = st.columns(3)

    with c1:
        with st.container(border=True):
            st.markdown("### 🔗 URL Investigator")
            st.write("Inspect URL structure and risk indicators.")
            if st.button("Open URL Investigator", use_container_width=True):
                st.session_state.page = "URL Investigator"
                st.rerun()

    with c2:
        with st.container(border=True):
            st.markdown("### ▦ QR Scanner")
            st.write("Decode a QR image without opening its destination.")
            if st.button("Open QR Scanner", use_container_width=True):
                st.session_state.page = "QR Scanner"
                st.rerun()

    with c3:
        with st.container(border=True):
            st.markdown("### ✉ Message Lab")
            st.write("Inspect message wording and extract links.")
            if st.button("Open Message Lab", use_container_width=True):
                st.session_state.page = "Message Lab"
                st.rerun()

    st.markdown("## Recent investigations")
    if history:
        st.dataframe(pd.DataFrame([{
            "ID": r["id"],
            "Type": r["type"],
            "Assessment": r.get("level"),
            "Score": r.get("score"),
            "Timestamp": r["timestamp"],
        } for r in history[:8]]), use_container_width=True, hide_index=True)
    else:
        st.info("No investigations yet. Start with one of the modules above.")

elif page == "URL Investigator":
    st.markdown("## URL Investigator")
    st.write("Analyse URL structure locally. The submitted destination is never fetched.")

    with st.form("url_form"):
        url = st.text_input("URL or domain", placeholder="https://example.com/account")
        submit = st.form_submit_button("Analyse URL", type="primary", use_container_width=True)

    if submit:
        try:
            result = url_scan(url)
            save_result(result)
            show_result(result)
        except ValueError as exc:
            st.error(str(exc))

    st.caption("No live reputation checks or website-content inspection are performed.")

elif page == "QR Scanner":
    st.markdown("## QR Scanner")
    st.write("Upload a clear QR-code image for local decoding.")

    upload = st.file_uploader("Choose an image", type=["png", "jpg", "jpeg", "webp"])

    if upload:
        data = upload.getvalue()
        if len(data) > 5 * 1024 * 1024:
            st.error("Maximum image size is 5 MB.")
        else:
            try:
                preview = Image.open(io.BytesIO(data)).convert("RGB")
                if preview.width * preview.height > 16_000_000:
                    st.error("Image dimensions are too large.")
                else:
                    st.image(preview, caption="Uploaded QR image", width=300)
                    if st.button("Decode and investigate", type="primary"):
                        try:
                            result = qr_scan(data)
                            save_result(result)
                            show_result(result)
                        except ValueError as exc:
                            st.error(str(exc))
            except Exception:
                st.error("Invalid or unreadable image.")

elif page == "Message Lab":
    st.markdown("## Message Lab")
    st.write("Inspect common social-engineering indicators in email or SMS text.")

    with st.form("message_form"):
        message = st.text_area(
            "Suspicious message",
            height=220,
            max_chars=12000,
            placeholder="Paste the message here...",
        )
        submit = st.form_submit_button("Investigate message", type="primary", use_container_width=True)

    if submit:
        try:
            result = message_scan(message)
            save_result(result)
            show_result(result)
        except ValueError as exc:
            st.error(str(exc))

    st.caption("Rules can flag legitimate messages and miss sophisticated scams.")

elif page == "Investigation History":
    st.markdown("## Investigation History")
    history = st.session_state.history

    if not history:
        st.info("No investigations in this session yet.")
    else:
        query = st.text_input("Filter by ID or type")

        filtered = [
            r for r in history
            if query.lower() in (r["id"] + " " + r["type"]).lower()
        ]

        st.dataframe(pd.DataFrame([{
            "ID": r["id"],
            "Type": r["type"],
            "Assessment": r.get("level"),
            "Score": r.get("score"),
            "Timestamp": r["timestamp"],
        } for r in filtered]), use_container_width=True, hide_index=True)

        ids = [r["id"] for r in filtered]
        if ids:
            selected = st.selectbox("Open a report", ids)
            report = next(r for r in filtered if r["id"] == selected)
            show_result(report)

        st.download_button(
            "Export session history",
            data=json.dumps(history, indent=2, ensure_ascii=False),
            file_name="traceshield-history.json",
            mime="application/json",
        )

        if st.button("Clear history"):
            st.session_state.history = []
            st.rerun()

elif page == "Methodology":
    st.markdown("## Methodology and limitations")

    st.markdown("### URL analysis")
    st.write("Uses deterministic URL-structure heuristics and documented keyword indicators.")

    st.markdown("### QR analysis")
    st.write("Uses OpenCV to decode QR images locally. HTTP/HTTPS contents can be passed through URL rules.")

    st.markdown("### Message analysis")
    st.write("Uses transparent phrase-matching rules and link extraction.")

    st.markdown("### Important limitations")
    st.warning(
        "This version does not include a trained ML model, live reputation feeds, "
        "sender verification or permanent database storage. Scores are heuristic "
        "indicators, not calibrated probabilities or proof of maliciousness."
    )

    st.markdown("### Privacy")
    st.write(
        "Submitted URLs are parsed without network requests. QR decoding is local. "
        "Avoid entering confidential messages into a shared demo. Session history "
        "may be lost when the session ends."
    )

st.divider()
st.caption("TRACESHIELD AI · Explainable digital trust · Results are indicative, not guarantees.")
