# NetworkTrafficCollector

:lock: Scripts that collect and analyze all incoming/outcoming network traffic, sort IP addresses and check them for maliciousness.


**traffic.py**
> сreates a csv file with the required headers, then collects all incoming and outgoing traffic (protocols, ips, ports, time)

![sc02.jpg.png](https://github.com/teora13/NetworkTrafficCollector/blob/main/images/sc02.jpg.png)


**virus_total.py** 
> makes sorting in the file by ip addresses, removing duplicates. 

> implemented progress bar in the command line (tqdm).

![sc01.jpg](https://github.com/teora13/NetworkTrafficCollector/blob/main/images/sc01.jpg)

> makes an api request to www.virustotal.com to check ip addresses.

> creates a new file with find resultes.

![sc03.jpg.png](https://github.com/teora13/NetworkTrafficCollector/blob/main/images/sc03.jpg.png)
