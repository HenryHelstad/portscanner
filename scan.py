from scapy.all import *          
import sys
import itertools

l = len(sys.argv)

#print(sys.argv)


TOPUDP = "2,3,7,9,13,17,19,20,21,22,23,37,38,42,49,53,67,68,69,80,88,111,112,113,120,123,135,136,137,138,139,158,161,162,177,192,199,207,217,363,389,402,407,427,434,443,445,464,497,500,502,512,513,514,515,517,518,520,539,559,593,623,626,631,639,643,657,664,682,683,684,685,686,687,688,689,764,767,772,773,774,775,776,780,781,782,786,789,800,814,826,829,838,902,903,944,959,965,983,989,990,996,997,998,999,1000,1001,1007,1008,1012,1013,1014,1019,1020,1021,1022,1023,1024,1025,1026,1027,1028,1029,1030,1031,1032,1033,1034,1035,1036,1037,1038,1039,1040,1041,1042,1043,1044,1045,1046,1047,1048,1049,1050,1051,1053,1054,1055,1056,1057,1058,1059,1060,1064,1065,1066,1067,1068,1069,1070,1072,1080,1081,1087" 

TOPTCP = [1,3,4,6,7,9,13,17,19,20,21,22,23,24,25,26,30,32,33,37,42,43,49,53,70,79,80,81,82,83,84,85,88,89,90,99,100,106,109,110,111,113,119,125,135,139,143,144,146,161,163,179,199,211,212,222,254,255,256,259,264,280,301,306,311,340,366,389,406,407,416,417,425,427,443,444,445,458,464,465,481,497,500,512,513,514,515,524,541,543,544,545,548,554,555,563,587,593,616,617,625,631,636,646,648,666,667,668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800,801,808,843,873,880,888,898,900,901,902,903,911,912,981,987,990,992,993,995,999,1000,1001,1002,1007,1009,1010,1011,1021,1022,1023,1024,1025,1026,1027,1028,1029,1030,1031,1032,1033,1034,1035,1036,1037,1038,1039,1040,1041,1042,1043,1044,1045,1046,1047,1048,1049,1050,1051,1052,1053,1054,1055,1056,1057,1058,1059,1060,1061,1062,1063,1064,1065,1066,1067,1068,1069,1070,1071,1072,1073,1074,1075,1076,1077,1078,1079,1080,1081,1082,1083,1084,1085,1086,1087,1088,1089,1090,1091,1092,1093,1094,1095,1096,1097,1098,1099,1100,1102,1104,1105,1106,1107,1108,1110,1111,1112,1113,1114,1117,1119,1121,1122,1123,1124,1126,1130,1131,1132,1137,1138,1141,1145,1147,1148,1149,1151,1152,1154,1163,1164,1165,1166,1169,1174,1175,1183,1185,1186,1187,1192,1198,1199,1201,1213,1216,1217,1218,1233,1234,1236,1244,1247,1248,1259,1271,1272,1277,1287,1296,1300,1301,1309,1310,1311,1322,1328,1334,1352,1417,1433,1434,1443,1455,1461,1494,1500,1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687,1688,1700,1717,1718,1719,1720,1721,1723,1755,1761,1782,1783,1801,1805,1812,1839,1840,1862,1863,1864,1875,1900,1914,1935,1947,1971,1972,1974,1984,1998,1999,2000,2001,2002,2003,2004,2005,2006,2007,2008,2009,2010,2013,2020,2021,2022,2030,2033,2034,2035,2038,2040,2041,2042,2043,2045,2046,2047,2048,2049,2065,2068,2099,2100,2103,2105,2106,2107,2111,2119,2121,2126,2135,2144,2160]


TOPUDPLIST = TOPUDP.split(",")

TOP100UDP = TOPUDPLIST[:100] 

TOP100UDPINT = []
for i in TOP100UDP: TOP100UDPINT.append(int(i))
TOP100UDPINTTUP = tuple(TOP100UDPINT)

#---------------------------------------------------------------------------------------------

def pingAddr(ip, time_out):
    ret = sr1(IP(dst=ip, ttl=20)/ICMP(), timeout=time_out, verbose=0)
    if not (ret is None):
        return True
    return False


def tcpScan(dip, portL, portU):
    answered, unanswered = sr(IP(dst=dip)/TCP(dport=(portL,portU), flags="S"), timeout=1, verbose=0)
    retO = []
    retF = []
    for a in answered:
        if a.answer.haslayer(TCP): 
            if a.answer[TCP].flags == "SA":
                retO.append( a.answer[TCP].sport)
    for u in unanswered:
        retF.append(u.dport)

    return (retO, retF)

#a TCP connect() scan of ports 20-100, 130-150, and 400-500
def tcpConnect(dst_ip):
    retO = []
    retF = [] 
    a, b = tcpScan(dst_ip, 20, 100)
    retO += a
    retF += b
    a, b = tcpScan(dst_ip, 130, 150)
    retO += a
    retF += b
    a, b = tcpScan(dst_ip, 400, 500)
    retO += a
    retF += b
    print("Open Ports")
    print(retO) 
    print("Filter Ports")
    print(retF)

#exercise 1 : #a TCP connect() scan of ports 20-100, 130-150, and 400-500
#tcpConnect()

#---------------------------------------------------------------------------------------------

#exercise 2: udp scan

#TOP100UDPINTTUP 

#I tryed a sr() implementation but it seems that UDP doesn't play well with it so it's more
#work than its worth I am going to switch to sr1 for finer grain control
#def udpScan100(dip, ports):
#    answered, unanswered = sr(IP(dst=dip)/UDP( sport=ports, dport=ports), timeout=10)
#    portO = []
#    portOF = []
#    portF = []
#    portC = []
#    for a in answered:
#        if a.answer.haslayer(UDP):
#            portO.append(a.answer[UDP].sport)
#        elif a.answer.haslayer(ICMP):
#            if int(a.answer[ICMP].type) == 3 and int(a.answer[ICMP].code) in [1,2,8,10,13]:
#                portF.append(a.answer[ICMP].sport)
#            elif int(a.answer[ICMP].type) == 3 and int(a.answer[ICMP].code) == 3:
#                portC.append(a.answer[ICMP].sport)
#             
#    for u in unanswered:
#        portOF.append(u.dport)
#    return (portO, portOF, portF, portC)


#using https://nmap.org/book/scan-methods-udp-scan.html as a refference on how to interpret udp
#probe
def udpScan(dip, ports, timeOut, retrys):
    portO = []
    portOF = []
    portF = []
    portC = []

    for port in ports:
        i = 0
        resp = None
        while(resp == None and i < retrys):
            i += 1 
            resp = sr1(IP(dst=dip)/UDP(sport=port, dport=port), timeout=timeOut, verbose=0)
        
        if resp == None:
            #print(port, "Open / Filtered")
            portOF.append(port)


        elif resp.haslayer(ICMP) and int(resp[ICMP].type) == 3 and int(resp[ICMP].code) in [1,2,8,10,13]: 
            #print(port, "Filtered")
            portF.append(port)

        elif  resp.haslayer(ICMP) and int(resp[ICMP].type) == 3 and int(resp[ICMP].code) == 3: 
            #print(port, "Closed")
            portC.append(port)

        elif resp.haslayer(UDP):
            #print(port, "Open")
            portO.append(port)

    return (portOF, portO, portF, portC)

def ppUDPSCAN(dst_ip):
    of,o,f,c = udpScan(dst_ip, TOP100UDPINT, 10, 3)
    print("No Responce: ", of)
    print("open:        ", o)
    print("Filtered:    ", f)
    print("Closed:      ", c)
 
        
#print(udpScan(dst_ip, TOP100UDPINT, 10, 10))


#---------------------------------------------------------------------------------------------

#an OS detection scan

#The only way given is using the nmap module (i.e) using nmap so we can't do that
#there is also a way to tell if an os is linux or not if it responds to a tcp message
#that has no header flags if there as been a tcp connection already established
#we could also try to do passive fingerprinting techniques

def isLinux(ip):
    TCP_client.tcplink(Raw, ip, 80)
    a, b = sr(IP(dst=ip)/TCP(dport=80), verbose=0)
    for i in a:
        if i.answer.haslayer(TCP):
             if i.answer[TCP].ack == 1:
                return True  
    return False



def TCP_ACK_PING(ip):
    ret = sr1(IP(dst=ip)/TCP(dport=80,flags="S"),timeout=11, verbose=0)
    if str(type(ret))=="<type 'NoneType'>":
        return False
    elif ret.haslayer(TCP):
        #ret.show() 
        return ret[TCP].window 
        
#I was going to try to have a tcp conversation in order to tryp to fingerprint the 
#operating system but it turns out there are whole applications doing this inaccuratly
#so I think I will need to settle for the linux fingerprint described in the 
# recomended materials i.e. https://0xbharath.github.io/art-of-packet-crafting-with-scapy/network_recon/os_detection/index.html
# I think all of that info is old and useless for OS fingerprinting. OS detection can 
#probably only be done well by nmap or other dedicated applications
#print(TCP_ACK_PING(dst_ip)
#print(OSdetect(dst_ip))

#---------------------------------------------------------------------------------------------

#an IP protocol scan
#we are getting no responces even though this is exactly how the scapy man says to do
#an IP Protocol scan. Nmap says that it sends its packets with data.. I am not sure how
#to programataticly construct packets with different layers based on the protocal 
#number. Additionaly nmap is only finding that icmp port is open even though we know
#that tcp and udp protocals are working on this machine. 
#this is super frustraiting

# I tryed
# resp = sr1(IP(dst="scanme.nmap.org")/ICMP())
# maybe scanme.nmap.org firewall is blocking this... appearetly that is a common issue
# for these types of packets I even tryed an
# I think I am just going to interpret as nmap would because it dosn't look like there is a
#way to workaround what ever is blocking these packets

def ipProtoScan(dip, timeOut):
    openports = []
    closedports = []
    filtered = []
    noresponce = [] 
 
    for port in range(0,255):
        resp =  sr1(IP(dst=dip)/UDP(sport=port, dport=port), timeout=timeOut, verbose=0)
        if resp == None:
            noresponce.append(port) 
        elif resp.haslayer(ICMP) and int(resp[ICMP].type) == 3 and int(resp[ICMP].code) == 2:
            closedports.append(port)
        elif resp.haslayer(ICMP) and int(resp[ICMP].type) == 3 and int(resp[ICMP].code) in [1,3,9,10,13]:
            filtered.append(port)
        else:
            openports.append(port)
    return  (openports, closedports, filtered, noresponce)


 
def ppprotoscan(dst_ip):
    o,c,f,n = ipProtoScan(dst_ip, 2)
    if 1 not in o and pingAddr(dst_ip, 3):
        o.append(1)
        if 1 in c: c.remove(1)
        if 1 in f: f.remove(1)
        if 1 in n: n.remove(1)
    b = TCP_ACK_PING(dst_ip) 
    if 6 not in o and 6 not in c  and type(b) != bool:
        if b == 0:
            c.append(6)
            if 1 in o: o.remove(6)
            if 1 in f: f.remove(6)
            if 1 in n: n.remove(6)
        if b != 0 :
            o.append(6)
            if 1 in c: c.remove(6)
            if 1 in f: f.remove(6)
            if 1 in n: n.remove(6)
 
    print("No Responce: ", n)
    print("open:        ", o)
    print("Filtered:    ", f)
    print("Closed:      ", c)
 
#ipProtoScan(dst_ip, 20)
#---------------------------------------------------------------------------------------------

# With nmap, you can use CIDR notation to list a network to scan. Try scanning your VM's subnet, on TCP ports 20-25.

#Take a look at nmap manpage again, under TARGET SPECIFICATION. Try some of the other options:
#
#    combine CIDR notation and an exclude list specified on the command line
#    create a list of hosts to scan and pass that
#    any other option that captures your interest

#Wildcards and ranges are no longer supported in Net() :(
#I think I am going to implement this wildcards otherwise its just gonna be a lot of work. I might do a file if I am feeling up to it as well. 
def wildcardReplace(inputArr):
    ret = []
    if inputArr[0].count("*") == 0 :
        return inputArr

    for i in inputArr: 
        chopIP = i.split("*",1)
     
        for j in range(0, 256):
            if len(chopIP) > 1:
                ret.append( chopIP[0] + str(j) + chopIP[1])
            else:
                ret.append(chopIP[0] + str(j))
    if ret[0].count("*") != 0 :
        return wildcardReplace(ret)
    return ret
    

def subnetscantcp(inputstr):
    ipArr = wildcardReplace([inputstr])
    for ip in ipArr:
       if pingAddr(ip, 3):
           a, b = tcpScan(ip, 20, 25)
           print(ip)
           print("Open Ports       : ", a)
           print("Filter Ports     : ", b)
     


    

def subnetScanTCPFile(fileName):
    with open(fileName) as file:
        lines = file.readlines()
        ipArr = [line.rstrip() for line in lines]   
    
    for ip in ipArr:
        if pingAddr(ip, 3):
            a, b = tcpScan(ip, 20, 25)
            print(ip)
            print("Open Ports       : ", a)
            print("Filter Ports     : ", b)
     

#subnetScanTCP("192.168.0.*")


#---------------------------------------------------------------------------------------------

def subnetscan(inputstr):
    iparr = wildcardReplace([inputstr])
    for ip in iparr:
        if pingAddr(ip, 3):
            islin = isLinux(ip)
            a, b = tcpScan(ip, 1, 1024 )
             
                
            of,o,f,c = udpScan(ip, TOP100UDPINT, 3, 3) #I changed this to top 100 udp otherwise this would take years
            print(ip) 
            print("Is Linux: ", islin) 
            print("TCP")
            print("open ports       : ", a)
            print("No Responce Ports   : ", b, "No responce means filtered or there is no ip here")
            print("UDP")
            print("No Responce: ", of)
            print("open:        ", o)
            print("Filtered:    ", f)
            print("Closed:      ", c)

def subnetscanFILE(fileName):
    with open(fileName) as file:
        lines = file.readlines()
        ipArr = [line.rstrip() for line in lines]   
    
    for ip in ipArr:
        if pingAddr(ip, 3):
            islin = isLinux(ip)
            a, b = tcpScan(ip, 1, 1024 )
             
                
            of,o,f,c = udpScan(ip, TOP100UDPINT, 3, 3) #I changed this to top 100 udp otherwise this would take years
            print(ip) 
            print("Is Linux: ", islin) 
            print("TCP")
            print("open ports       : ", a)
            print("No Responce Ports   : ", b, "No responce means filtered or there is no ip here")
            print("UDP")
            print("No Responce: ", of)
            print("open:        ", o)
            print("Filtered:    ", f)
            print("Closed:      ", c)
         
#subnetScan("192.168.0.*")

#print(pingaddr(dst_ip, 10))


#print(sys.argv)
if len(sys.argv) == 1:
    print("Command line Arguments: ")
    print("\ninput: sudo python3 scan.py 1 xx.xx.xx.xx")
    print("result: TCP connect() scan of ports 20-100, 130-150, and 400-500")
    print("\ninput: sudo python3 scan.py 2 xx.xx.xx.xx")
    print("result: a UDP scan of the top 100 ports")
    print("\ninput: sudo python3 scan.py 3 xx.xx.xx.xx")
    print("result: an OS detection scan")
    print("\ninput: sudo python3 scan.py 4 xx.xx.xx.xx")
    print("result: an IP protocol scan")
    print("\nScaning netork segments exercise")
    print("Two different Notations: ")
    print("\twild card notation with IP addresses (can put the wild card anywhere in the ip address)")
    print("examples\n\t\tsudo python3 scan.py 5 xx.xx.xx.*")
    print("\t\tsudo python3 scan.py 5 xx.xx.*.*")
    print("\t\tsudo python3 scan.py 5 xx.xx.*.xx")
    print("takes in a file filled with ip addresses") 
    print("\tsudo python3 scan.py 6 filename") 
    print("\tfile: each ip addr should be seporated by a new line. thats it. ip addr written like xx.xx.xx.xx")
    print("result: should only scan ports TCP ports 20-25")
    print("\nEXTRA CREDIT")
    print("input: sudo python3 scan.py 7 xx.xx.xx.*")
    print("\t can use any wild card notation")
    print("input: sudo python3 scan.py 8 filename")
    print("\t can use file with ips in it see 6 for formating") 
    print("output: TCP and UDP with OS detection uses pings to optimize still slow af might miss some systems because it checks with a ICMP to see if the system is there in the first place")
    print("\t note I would use the file notation so you can minimize the number of ip addresses as this scan takes forever")



elif int(sys.argv[1]) == 1:
    tcpConnect( sys.argv[2])
elif int(sys.argv[1]) == 2:
    ppUDPSCAN(sys.argv[2])
elif int(sys.argv[1]) == 3:
    print("Is Linux: ", isLinux(sys.argv[2]))
elif int(sys.argv[1]) == 4:
    ppprotoscan(sys.argv[2])  
elif int(sys.argv[1]) == 5:
    subnetscantcp(sys.argv[2]) 
elif int(sys.argv[1]) == 6:
    subnetScanTCPFile(sys.argv[2])
elif int(sys.argv[1]) == 7:
    subnetscan(sys.argv[2])
elif int(sys.argv[1]) == 8:
    subnetscanFILE(sys.argv[2])







