# Sentinel IDS Dashboard — Network Intrusion Detection System

This project fulfills CodeAlpha Cyber Security Task 4: set up a network-based IDS using tools such as Snort or Suricata, configure rules and alerts, monitor traffic for threats, implement response mechanisms, and optionally visualize detected attacks. fileciteturn0file0L48-L53

## Architecture
- **Suricata**: optional real IDS engine for authorized live/offline monitoring.
- **rules/local.rules**: safe lab rules for ICMP, SSH destination port, and RDP destination port.
- **EVE JSON parser**: reads Suricata alert events.
- **Streamlit dashboard**: visualizes severity/protocol distributions and event details.
- **Local detector**: small fallback for controlled CSV lab data when Suricata is not installed.

## Safe response design
The dashboard provides response recommendations such as escalation and verification. It does not automatically attack, delete remote data, or apply destructive firewall changes.

## Run dashboard
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run_checks.py
streamlit run app.py
```

## Suricata integration (authorized lab)
Install Suricata following your operating system's official documentation. Then test the included rules against a permitted PCAP with a command conceptually similar to:
```text
suricata -r your_lab_capture.pcap -S rules/local.rules -l output
```
The exact installation and interface configuration vary by operating system. Feed the generated `eve.json` to the dashboard.

## Interpretation
A rule match is an alert for investigation, not proof of compromise. Validate asset ownership, expected traffic, and context before escalating.
