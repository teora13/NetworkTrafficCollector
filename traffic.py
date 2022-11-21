import pyshark
import csv
from csv import writer

cap = pyshark.LiveCapture(interface='\\Device\\NPF_{device}')
headers = ['Protocol type', 'Source address', 'Source port', 'Destination address', 'Destination port', 'Time']

with open("data.csv", 'w') as file:
    dw = csv.DictWriter(file, delimiter=',',
                        fieldnames=headers)
    dw.writeheader()

for packet in cap.sniff_continuously(packet_count=1):
    try:
        print('Protocol type:', packet.transport_layer, 'Source port:', packet[packet.transport_layer].srcport)
    except AttributeError:
		pass
