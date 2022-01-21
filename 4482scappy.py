import scapy
from scapy.all import *
import re
import pandas as pd

def main (ip_addr, choice):
    c = int(choice)
    responsive = ip_id_icmp = ip_id_tcp = port_open = ttl = window_size = cookies = ops = None
    print("Checking %s....." %ip_addr)
    pkt = IP(dst=ip_addr)/ICMP()
    a = sr1(pkt, timeout=1, verbose=0)
    if a is None:
        if c == 1:
            print("Device is not responsive. Exiting................")
        if c == 2:
            responsive = "OFF"
    else:
        type1 = getattr(a[0][1], "type")

        if type1 != 0:
            if c == 1:
                print("Device is not responsive bye Exiting............")
            if c == 2:
                responsive = "OFF"

        else:
            ttl = getattr(a[0], "ttl")
            ids = []
            if c == 1:
                print("Yes, the device is responsive")
            if c == 2:
                responsive = "ON"
            p, q = srloop(pkt, count=5, verbose=0)  # verbose hides the unnecessary output of srloop
            for i in range(len(p)):
                Ip_ID = getattr(p[i][1], "id")
                ids.append(Ip_ID)
            if len(ids) == 0:
                x = 0
            elif sorted(ids) == list(range(min(ids),
                                           max(ids) + 1)):  # if ids are consecutive then sorted list will be equal to range [min, max]
                ip_id_icmp="incremental"
            elif min(ids) == 0 and max(ids) == 0:  # if all ids are zero, then their min and max will be zero
                ip_id_icmp="zero"
            else:  # else all ids are random
                ip_id_icmp="random"
            if (c==1):
                print("The device deploys %s IP-ID counter (ICMP)" % str(ip_id_icmp))
            tcp_pkt = IP(dst=ip_addr) / TCP(dport=80, flags="S")
            t = sr1(tcp_pkt, timeout=1, verbose=0)
            if t is not None:

                ack = getattr(t[0][1], "ack")
                window_size = getattr(t[0][1], "window")
                if ack == 1:
                    if c == 1:
                        print("Yes, Port 80 on device is open")
                    if c == 2:
                        port_open = "open"
                    tcp1, tcp2 = srloop(tcp_pkt, count=5, verbose=0)
                    t_ids = []

                    for i in range(len(tcp1)):
                        if tcp1[i][1]:
                            tcp_id = getattr(tcp1[i][1], "id")
                            t_ids.append(tcp_id)
                    if len(t_ids) == 0:
                        x = 0  #dummy
                    elif sorted(t_ids) == list(range(min(t_ids),
                                                     max(t_ids) + 1)):  # if ids are consecutive then sorted list will be equal to range [min, max]
                        ip_id_tcp = "incremental"
                    elif min(t_ids) == 0 and max(
                            t_ids) == 0:  # if all ids are zero, then their min and max will be zero
                        ip_id_tcp = "zero"
                    else:  # else all ids are random
                        ip_id_tcp = "zero"
                    if c == 1:
                        print("The device deploys %s IP-ID counter (TCP)" % str(ip_id_tcp))
                    cookie_pkt = IP(dst=ip_addr) / TCP(dport=80, flags="S")
                    ans, unans_ = sr(cookie_pkt, timeout=2, verbose=0)

                    if len(ans) == 0 or ans is None:
                        cookies = "None"
                    elif len(ans) == 1:
                        if c == 1: print("Yes, SYN cookies are deployed by device")
                        if c == 2: cookies = "Deployed"
                    else:
                        if c == 1: print("No, SYN cookies are not deployed")
                        if c == 2: cookies="Not Deployed"
                else:
                    if c == 1:
                        print("No, port 80 on device is not open")
                    if c == 2:
                        cookies = window_size = ip_id_tcp = port_open = "CLOSED"
            else:
                if c == 1:
                    print("No, port 80 on device is not open")
                if c == 2:
                    cookies = window_size = ip_id_tcp = port_open = "CLOSED"
            ops = "other"
            # if window size is available
            ttl = int(ttl)

            if window_size != 'CLOSED' and window_size is not None:
                window_size = int(window_size)
                if ttl <= 64 and 5720 < window_size <= 5840:
                    ops = "Linux 2.4 and Linux 2.6"
                elif ttl <= 64 and 5600 < window_size <= 5720:
                    ops = "Google customized Linux"
                elif ttl <= 64 and 31000 < window_size <= 32120:
                    ops = "Linux Kernel 2.2"
                elif ttl <= 64 and 32120 < window_size <= 65535:
                    ops = "MAC or Free BSD"
                elif ttl <= 64 and window_size < 5600:
                    ops = "Likely Linux"
                elif 64 < ttl <= 128 and window_size <= 8192:
                    ops = "Windows 7 or more"
                elif 64 < ttl <= 128 and 8192 < window_size <= 16384:
                    ops = "Windows 2000"
                elif 64 < ttl <= 128 and 16384 < window_size <= 65535:
                    ops = "Windows XP"
                else:
                    ops = "other"
                if c == 1:
                    print("ttl: %d, Window size: %d, OS: %s" % (ttl, window_size, ops))
            else:
                if ttl <= 64:
                    ops = " Likely Linux"
                elif 64 < ttl <= 128:
                    ops = "Likely Windows"
                else:
                    ops = "other"
                if c == 1:
                    print("ttl: %d, Window size: None, OS: %s" % (ttl, ops))
    if c==2:
        print("%s,%s,%s,%s,%s,%s,%s,%s,%s\n" %(str(ip_addr), str(responsive), str(ip_id_icmp), str(port_open), str(ip_id_tcp), str(cookies), str(ttl), str(window_size), str(ops)))
        f.write((str(ip_addr)+","+str(responsive)+","+str(ip_id_icmp)+","+str(port_open)+","+str(ip_id_tcp)+","+str(cookies)+","+str(ttl)+","+str(window_size)+","+str(ops)+"\n"))
    print("\n")
ip_addr = None
choice = input("Press 1 to enter an IP address \nPress 2 to Enter file name containing IP address\n")
if int(choice) == 1:
    ip_addr = input("Enter a IP addresses\n")
    main(ip_addr, choice)
if int(choice) == 2:
    print("IMPORTANT: Before running \n"
          "1.Make sure data file is in the same directory as program file or Enter a valid path \n"
          "2.Only works with .csv files. For example, shodan_data.csv  \n"
          "3.To convert .xlsx file to .csv on Windows: \n"
          "        Open .xlsx file--> Click File-->Save As--> save as type: CSV(comma delimited)-->Save \n"
          "4.Make sure Pandas library is installed [Use: pip install pandas]\n"
          "5.Uncomment import Pandas line at the beginning of the code\n")
    file_name = input("Enter the file name, for example shodan_data.csv\n")
    df = pd.read_csv(file_name)
    IP_column = df.IP
    f = open('Jaffar_result.csv', 'w')
    f.write("IP,Responsive,IP-ID ICMP, PORT 80, IP-ID TCP, COOKIES, TTL, WINDOW SIZE, OS\n")
    saved_column = list(dict.fromkeys(IP_column))  # remove duplicates
    print("Please wait for few minutes. Output file is being generated")
    for i in range(len(saved_column)):
        ip_addr = saved_column[i]
        if re.match("(^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$)", ip_addr):  # regex for checking valid IPv4 address
            main(ip_addr, choice)
    print("Output file complete")
    f.close()
