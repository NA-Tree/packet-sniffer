# packet-sniffer
A packet sniffer made in python with Scapy and Tkinter
## how to use the packet sniffer
By running the packet_sniffer.py file, you are able to see the application as a GUI.
<br>
One common way to run this application is with the following bash command (assuming bash & python 3 is installed)

``` bash
bash sudo python3 ./packet_sniffer.py
```

or simply running the following with admin priveleges
``` bash
python3 ./packet_sniffer.py
```

## to use the gui
1. click start
2. select the advanced option and you should see the source address/port , destination address/port, and protocol filters (select as desired)
3. click apply - you will get a message box telling the filter is applied
4. click start to begin capture and stop to pause capture (clear to start over)
5. click on a packet to examine its contents in more detail
6. press the save or save all icons to save as a csv [excel document ]

* note: this is still underdeveloped for commercial or high scale use and further testing may still be required
