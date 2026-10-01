class LocalIDSDetector:
    def detect_dataframe(self,df):
        out=[]
        for _,r in df.fillna('').iterrows():
            src=str(r.get('src_ip','')); dst=str(r.get('dst_ip','')); proto=str(r.get('proto','')).upper(); port=str(r.get('dst_port',''))
            sig='Informational traffic'; sev='3'; cat='policy'
            if port=='22' and proto=='TCP': sig='Lab alert: SSH destination observed'; sev='2'; cat='remote-service'
            elif proto=='ICMP': sig='Lab alert: ICMP observed'; sev='3'; cat='network-discovery'
            elif port in {'3389','23'} and proto=='TCP': sig='Lab alert: sensitive remote-service port observed'; sev='2'; cat='remote-service'
            out.append({'timestamp':str(r.get('timestamp','')),'src_ip':src,'src_port':str(r.get('src_port','')),'dst_ip':dst,'dst_port':port,'proto':proto,'signature':sig,'severity':sev,'category':cat})
        return out
    def response_actions(self,events):
        actions=[]
        for e in events:
            if e['severity']=='1': actions.append({'action':'Escalate for incident triage','reason':e['signature']})
            elif e['severity']=='2': actions.append({'action':'Review source/destination context and validate whether the service is authorized','reason':e['signature']})
        return actions or [{'action':'No elevated response recommended by this demo rule set','reason':'No severity 1–2 alert in the loaded sample.'}]
