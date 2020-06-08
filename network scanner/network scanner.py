#/usr/bin/env/ python
import scapy.all as scapy
import subprocess
print("""
      ___ ___       __   __           __   __                  ___  __
|\ | |__   |  |  | /  \ |__) |__/    /__` /  `  /\  |\ | |\ | |__  |__) 
| \| |___  |  |/\| \__/ |  \ |  \    .__/ \__, /~~\ | \| | \| |___ |  \ 
                                                     
                                                                =by devalfo=                                                      
""")
print("A network scanner is a software tool used for diagnostic and investigative purposes\n to find and categorize what devices are running on a network\n\n\n")

subprocess.call(["route","-n"])

print("\n Your wifi ip address is the gateway! \n")
wifi_ip=input("What is your wifi ip : " )
def scan(ip):
      # part1 : make the package and make how send them
      arp_request=scapy.ARP(pdst=ip)
      broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")       #dst stand for Destination MAC Field
      arp_request_broadcast = broadcast/arp_request            #we combine the two args to make the last packet
      answered_list = scapy.srp(arp_request_broadcast , timeout=5 , verbose=False)[0]  #this function will send the packet
      # part 4 printing a result
      print("\n\n\nIP\t\t\tMAC-Address\n:::::::::::::::::::::::::::::::::::::::::::::::::")
      #part 3 :parse the response
      for element in answered_list:
          print(element[1].psrc +"\t\t"+element[1].hwsrc)
      print("\n\n\n=inspired from zsecurity python course ,thanks to zaid sabih=")
      print("(https://zsecurity.org/courses/learn-python-ethical-hacking-from-scratch/)")
scan(wifi_ip + "/24")
