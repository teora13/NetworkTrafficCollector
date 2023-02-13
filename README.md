# NetworkTrafficCollector

:lock: Scripts that collect and analyze all incoming/outcoming network traffic, sort IP addresses and check them for maliciousness.

![sc01.jpg](https://github.com/teora13/NetworkTrafficCollector/blob/main/images/sc01.jpg)

> traffic.py - сreates a csv file with the required headers, then collects all incoming and outgoing traffic.


> virus_total.py - makes sorting in the file by ip addresses, removing duplicates. 

![sc01.jpg](https://github.com/teora13/NetworkTrafficCollector/blob/main/images/sc01.jpg)

Makes an api request to www.virustotal.com to check ip addresses.
Creates a new file with processing results
