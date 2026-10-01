from pathlib import Path
import pandas as pd
import streamlit as st
from parser import load_eve_json, build_summary
from detector import LocalIDSDetector

st.set_page_config(page_title='Sentinel IDS Dashboard',page_icon='🚨',layout='wide')
st.markdown('''<style>.block-container{padding-top:1.4rem}.hero{padding:1.35rem 1.5rem;border:1px solid rgba(127,127,127,.18);border-radius:20px;margin-bottom:1rem;background:linear-gradient(135deg,rgba(220,38,38,.10),rgba(79,70,229,.10))}.safe{padding:.8rem 1rem;border-radius:12px;border:1px solid rgba(14,165,233,.25);background:rgba(14,165,233,.06)}</style>''',unsafe_allow_html=True)
st.markdown('''<div class="hero"><h1>🚨 Sentinel IDS Dashboard</h1><p>A defensive intrusion-detection workspace for analyzing authorized network alerts, applying local detection rules, and visualizing security events.</p></div>''',unsafe_allow_html=True)
st.sidebar.title('IDS Source')
source=st.sidebar.radio('Choose input',['Sample Suricata EVE JSON','Upload Suricata EVE JSON','Local detector (CSV)'])
detector=LocalIDSDetector()
st.sidebar.markdown('<div class="safe"><b>Authorized use only:</b> analyze only network traffic and logs you are permitted to monitor.</div>',unsafe_allow_html=True)
if source=='Sample Suricata EVE JSON':
    events=load_eve_json(Path('samples/eve.json')); label='Built-in demo events'
elif source=='Upload Suricata EVE JSON':
    up=st.file_uploader('Upload eve.json',type=['json']); events=[] if up is None else load_eve_json(up); label=up.name if up else 'No file'
else:
    up=st.file_uploader('Upload CSV with src_ip,dst_ip,proto,dst_port',type=['csv'])
    if up: events=detector.detect_dataframe(pd.read_csv(up))
    else: events=[]
    label=up.name if up else 'No file'
if events:
    summary=build_summary(events); st.success(f'Loaded {len(events)} events from {label}.')
    a,b,c,d=st.columns(4); a.metric('Events',len(events)); b.metric('Alerts',summary['alerts']); c.metric('Sources',summary['sources']); d.metric('Destinations',summary['destinations'])
    t1,t2,t3,t4=st.tabs(['📋 Alerts','📊 Visualize','🔎 Event Details','🧭 Response'])
    with t1:
        df=pd.DataFrame(events); cols=[c for c in ['timestamp','src_ip','src_port','dst_ip','dst_port','proto','signature','severity','category'] if c in df.columns]; st.dataframe(df[cols],use_container_width=True,hide_index=True)
    with t2:
        sev=pd.DataFrame([{'Severity':k,'Events':v} for k,v in summary['severity_counts'].items()]); proto=pd.DataFrame([{'Protocol':k,'Events':v} for k,v in summary['protocol_counts'].items()])
        if not sev.empty: st.bar_chart(sev.set_index('Severity'))
        if not proto.empty: st.bar_chart(proto.set_index('Protocol'))
    with t3:
        idx=st.selectbox('Event',range(len(events)),format_func=lambda i:f"{i+1} — {events[i].get('signature','No signature')}"); st.json(events[idx])
    with t4:
        st.subheader('Safe response workflow'); st.write('Recommendations only: this app does not attack, delete, or automatically block remote systems.')
        for item in detector.response_actions(events): st.markdown(f"**{item['action']}** — {item['reason']}")
else:
    st.info('Load the built-in demo events first to verify the dashboard.')
st.divider(); st.caption('Sentinel IDS Dashboard • Suricata-compatible EVE JSON + local rule demonstration • Defensive monitoring only')
