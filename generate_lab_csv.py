import csv
rows=[{'timestamp':'2026-09-29T12:00:01Z','src_ip':'192.168.56.10','src_port':53001,'dst_ip':'192.168.56.1','dst_port':22,'proto':'TCP'},{'timestamp':'2026-09-29T12:00:03Z','src_ip':'192.168.56.12','src_port':0,'dst_ip':'192.168.56.1','dst_port':0,'proto':'ICMP'},{'timestamp':'2026-09-29T12:00:05Z','src_ip':'192.168.56.13','src_port':54000,'dst_ip':'192.168.56.1','dst_port':3389,'proto':'TCP'}]
with open('samples/lab_traffic.csv','w',newline='',encoding='utf-8') as f:
 w=csv.DictWriter(f,fieldnames=rows[0].keys()); w.writeheader(); w.writerows(rows)
print('Created samples/lab_traffic.csv')
