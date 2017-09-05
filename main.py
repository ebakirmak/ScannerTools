from scapy.all import *
import netifaces
import socket
from tkinter import *



#ICMP Protocol paketi gönderme.
def sendICMP():
    ipPacket = IP()
    icmpPacket = ICMP()
    targetIP = input('Target IP: ')
    ipPacket.dst = targetIP
    sourceIP = input('Source IP: ')
    ipPacket.src = socket.gethostbyname(socket.gethostname())
    ipPacket.show()
    icmpPacket.show()
    send(ipPacket/icmpPacket)

def packetShow(packet):
    packet.show()

def icmpPacketSniff():
    while True:
        sniff(iface="eth0", count=1, filter="icmp", prn=packetShow)

#Ping atma
def pingIPAndHost():

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP/IP socket
    server_ip = input("Enter server IP: ")
    rep = os.system("ping " + server_ip)
    if rep == 0:
        print ("n n  server is up n n")
    else:
        print("server is down")

#Aðdaki tüm ipleri tarayarak, mac adreslerini döndürecek.
def sniffIPandARP():
    gw=netifaces.gateways()
    print (gw['default'][2][0])
    ipadd=gw['default'][2][0]
    noktaSayisi=0
    IPAddr=""
    for harf in ipadd:
        if(harf=="."):
            noktaSayisi+=1
            if(noktaSayisi==3):
                IPAddr+="."
                break

        IPAddr+=harf
    for i in range(1, 255):
        ip = IPAddr + str(i)
        ans = srp1(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=0.5, retry=1)
        if ans:
            #print("IP: " + ans.psrc + " MAC : " + ans.hwsrc)
            #listReturn.delete()
            listReturn.insert(END,"IP: {0} MAC: {1} ".format(str(ans.psrc),str(ans.hwsrc)))
            #return [ans.psrc,ans.hwsrc]

#Port Tarama
def PortScan():
    targetIP = txtIP.get()


    for port in range(1, 100):
        portSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        portSocket.settimeout(0.5)
        try:
            conn = portSocket.connect((targetIP, port))
            print("Port ", port, " --> OPEN")
            listReturn.insert(END,"Port {0} --> AÇIK".format(port))
        except:
            print("Port ", port, " --> KAPALI")







#GUI
#Tkinter nesnesi oluþturuldu.
pencere=Tk()
#Pencere baþlýðýný ayarladýk.
pencere.title("Scanner Tools")
#Pencere boyutlarýný belirleme
pencere.geometry("500x500")
#Pencere boyutlandýrma engelleme
pencere.resizable(False,False)
#Label oluþturma
labelIp=Label(text="IP Giriniz: ",
              fg="black",
               font=("Arial","15","bold"))
#Buton oluþturma
btnPortScan=Button(text = "Port Tarama",
                   command=PortScan,
                   width="8",
                   height="3"
)
#Buton oluþturma
btnSniffIPandARP=Button(text = "Ýstenilen IP Ping Atma",
                   command=sniffIPandARP,
                   width="8",
                   height="3"
)
#Buton oluþturma
btnPingIPAndHost=Button(text = "Port Tarama",
                   command=pingIPAndHost,
                   width="8",
                   height="3"
)
#Buton oluþturma
btnIcmpSniffer=Button(text = "ICMP Paketlerini koklama",
                   command=icmpPacketSniff,
                   width="8",
                   height="3"
)
#Textbox Oluþturma
txtIP=Entry()
#Listbox oluþturma -> Sonuçlarý görmek için.
listReturn=Listbox()
labelIp.grid(row=0,column=0)
txtIP.grid(row=0,column=1)
btnPortScan.grid(row=1,column=0)
btnSniffIPandARP.grid(row=1,column=1)
btnPingIPAndHost.grid(row=1,column=2)
btnIcmpSniffer.grid(row=1,column=3)
listReturn.grid(row=2,column=0,rowspan=10)


#Pencerenin sürekli açýk kalmasýný saðladýk."
mainloop()



