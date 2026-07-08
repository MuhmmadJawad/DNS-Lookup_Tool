# Threat Intelligence Dashboard

A real-time-style cybersecurity dashboard built with **Dash** and **Plotly**, visualizing threats, IOCs, attack origins, and MITRE ATT&CK activity.

## Features
- Live threat feed table (severity, source, target, status)
- IOC table (IPs, domains, hashes, URLs) with confidence scores
- 24-hour threat volume bar chart
- Attack origin map by country
- Sector risk breakdown
- MITRE ATT&CK tactics distribution
- Auto-updating clock

## Requirements
```bash
pip install dash plotly pandas
```

## Run
```bash
python Threat-Intelligence-Dashboard.py
```
Then open `http://127.0.0.1:8050` in your browser.

## Notes
- Uses sample/synthetic data — no external API calls or live feeds.
- Built for demo, lab, and portfolio purposes.
