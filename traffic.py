import pyshark

cap = pyshark.LiveCapture(interface='\\Device\\NPF_{device}')

for packet in cap.sniff_continuously(packet_count=1):
     print('Protocol type:', packet.transport_layer, 'Source port:', packet[packet.transport_layer].srcport)
