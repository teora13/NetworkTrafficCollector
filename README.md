# NetworkTrafficCollector

:lock: Scripts that collect and analyze all incoming/outcoming network traffic, sort IP addresses and check them for maliciousness.


There are 2 scripts: 

> traffic.py - сreates a csv file with the required headers, then collects all incoming and outgoing traffic and writes to this file.
> 
> virus_total.py - makes sorting in the file by ip addresses, removing duplicates. Makes an api request to www.virustotal.com to check ip addresses.
Creates a new file with processing results
