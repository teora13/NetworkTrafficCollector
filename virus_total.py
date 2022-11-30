import requests
import json

df = pd.read_csv("data.csv")
dropped = df[['Source address', 'Destination address']].unstack().reset_index(drop=True)
