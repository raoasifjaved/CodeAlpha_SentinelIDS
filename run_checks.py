from pathlib import Path
import ast,pandas as pd
BASE=Path(__file__).resolve().parent
print('[1/4] Checking Python syntax...')
for p in BASE.rglob('*.py'): ast.parse(p.read_text(encoding='utf-8'),filename=str(p))
print('      PASS')
print('[2/4] Checking EVE JSON parser...')
from parser import load_eve_json,build_summary
events=load_eve_json(BASE/'samples/eve.json'); assert len(events)==3 and 'TCP' in build_summary(events)['protocol_counts']
print('      PASS')
print('[3/4] Checking local detector...')
from detector import LocalIDSDetector
out=LocalIDSDetector().detect_dataframe(pd.DataFrame([{'src_ip':'10.0.0.2','dst_ip':'10.0.0.1','src_port':50000,'dst_port':22,'proto':'TCP'}])); assert out[0]['severity']=='2'
print('      PASS')
print('[4/4] Checking response workflow...')
assert LocalIDSDetector().response_actions(events)
print('      PASS')
print('\nALL CHECKS PASSED')
