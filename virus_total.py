import requests
import json
import csv
from csv import writer

df = pd.read_csv("data.csv")
dropped = df[['Source address', 'Destination address']].unstack().reset_index(drop=True)

pbar = tqdm(total=len(dropped), desc='TOTAL ADDRESSES')
headers = ['IP', 'Total vendors', 'Country', 'Protocol type', 'Source port', 'Destination port', 'Time']
with open("result.csv", 'w') as file:
    dw = csv.DictWriter(file, delimiter=',', fieldnames=headers)
    dw.writeheader()
    
for ip in dropped:
    url = ('https://www.virustotal.com/api/v3/ip_addresses/' + str(ip))
    headers = {
        'accept': 'application/json',
        'x-apikey': 'key'}
    response = json.loads((requests.get(url, headers=headers)).text)
    find_malicious = (json.dumps(response['data']['attributes']['last_analysis_stats']['malicious'], indent=4))
    pbar.update()
    if find_malicious == '1':
        country = response['data']['attributes']['country']
        vendors = len(response['data']['attributes']['last_analysis_results'])
        df_records = df[df['Source address'] == ip]



