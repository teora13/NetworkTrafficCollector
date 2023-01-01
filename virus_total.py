import requests
import json
import csv
from csv import writer
import pandas as pd
from time import sleep
from tqdm import tqdm

# opens created csv file, drops duplicates and sorts all records by ips
df = pd.read_csv("data.csv")
dropped = df[['Source address', 'Destination address']].unstack().reset_index(drop=True).drop_duplicates()

# creates a new csv file with headers
headers = ['IP', 'Total vendors', 'Country', 'Protocol type', 'Source port', 'Destination port', 'Time']
with open("result.csv", 'w') as file:
    dw = csv.DictWriter(file, delimiter=',', fieldnames=headers)
    dw.writeheader()
    
pbar = tqdm(total=len(dropped), desc='TOTAL ADDRESSES')    
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
        for index, row in df_records.iterrows():
            df_protocol = row['Protocol type']
            df_source_port = row['Source port']
            df_dest_post = row['Destination port']
            df_time = row['Time']
        with open('result.csv', 'a', newline='') as f_object:
            writer_object = writer(f_object)
            writer_object.writerows(zip([ip], [vendors], [country], [df_protocol], [df_source_port], [df_dest_post], [df_time]))
    sleep(5)

