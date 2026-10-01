import json
from pathlib import Path
from collections import Counter

def load_eve_json(source):
    if hasattr(source,'read'):
        raw=source.read(); raw=raw.decode('utf-8',errors='replace') if isinstance(raw,bytes) else raw; lines=raw.splitlines()
    else: lines=Path(source).read_text(encoding='utf-8').splitlines()
    events=[]
    for line in lines:
        if not line.strip(): continue
        obj=json.loads(line)
        if obj.get('event_type')=='alert':
            a=obj.get('alert',{})
            events.append({'timestamp':obj.get('timestamp',''),'src_ip':obj.get('src_ip',''),'src_port':obj.get('src_port',''),'dst_ip':obj.get('dest_ip',''),'dst_port':obj.get('dest_port',''),'proto':obj.get('proto',''),'signature':a.get('signature','Unknown alert'),'severity':str(a.get('severity','unknown')),'category':a.get('category','Unknown')})
    return events

def build_summary(events):
    return {'alerts':len(events),'sources':len({e['src_ip'] for e in events if e['src_ip']}),'destinations':len({e['dst_ip'] for e in events if e['dst_ip']}),'severity_counts':dict(Counter(e['severity'] for e in events)),'protocol_counts':dict(Counter(e['proto'] for e in events))}
