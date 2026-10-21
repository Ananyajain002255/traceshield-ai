
# TraceShield AI 🛡️

**Explainable, Multi-Modal Phishing Investigation and Digital Trust Platform**

TraceShield AI helps users investigate suspicious URLs, QR codes, and digital messages through transparent security indicators and understandable recommendations.

## Features

- URL structure analysis
- Local QR-code decoding
- Suspicious message pattern detection
- Explainable evidence breakdown
- Investigation history for the active session
- Downloadable JSON reports
- Responsive cybersecurity dashboard

## Tech Stack

Python · Streamlit · OpenCV · Pillow · Pandas

## Run locally

```bash
python -m venv .venv
```

Activate the environment, then run:

```bash
pip install -r requirements.txt
streamlit run app.py
```

## Deploy

1. Push the project to GitHub.
2. Open https://share.streamlit.io/
3. Connect your GitHub account.
4. Select this repository and the `main` branch.
5. Set the application file to `app.py`.
6. Deploy and test the published website.

## Limitations

This version uses rule-based heuristics, not a trained ML classifier. It does not fetch URLs, perform live threat-intelligence lookups, or guarantee detection. History is session-based rather than permanently stored.

Risk scores are indicators, not calibrated probabilities or proof of malicious activity.

## Responsible use

Use the application for defensive security awareness and controlled testing. Independently verify suspicious requests before sharing credentials or making payments.
