import pyshark
import csv
from csv import writer

# creates csv file and headers (only if they weren't created)
headers = ['Protocol type', 'Source address', 'Source port', 'Destination address', 'Destination port', 'Time']
with open("data.csv", 'w') as file:
    dw = csv.DictWriter(file, delimiter=',',
                        fieldnames=headers)
    dw.writeheader()
	
# captures all network traffic
cap = pyshark.LiveCapture(interface='\\Device\\NPF_{device}')

# makes a record for each packet 
for packet in cap.sniff_continuously():
	try:
		if packet.transport_layer == None:
			pass
		else:
			packet_data = packet.transport_layer,\
				      packet.ip.src, \
				      packet[packet.transport_layer].srcport,\
				      packet.ip.dst, \
				      packet[packet.transport_layer].dstport, \
				      str(packet.sniff_time)
			with open('data.csv', 'a', newline='') as f_object:
				writer_object = writer(f_object)
				writer_object.writerow(packet_data)
			print(packet_data)
	except AttributeError:
		pass
f_object.close()
