# NetworkTrafficCollector

:lock: Scripts that collect and analyze all incoming/outcoming network traffic, sort IP addresses and check them for maliciousness.


> traffic.py - сreates a csv file with the required headers, then collects all incoming and outgoing traffic.
> 
> virus_total.py - makes sorting in the file by ip addresses, removing duplicates. Makes an api request to www.virustotal.com to check ip addresses.
Creates a new file with processing results
