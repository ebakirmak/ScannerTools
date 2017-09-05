from scapy.all import *
import netifaces
import socket
from tkinter import *



#ICMP Protocol paketi g�nderme.
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

#A�daki t�m ipleri tarayarak, mac adreslerini d�nd�recek.
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
            listReturn.insert(END,"Port {0} --> A�IK".format(port))
        except:
            print("Port ", port, " --> KAPALI")







#GUI
#Tkinter nesnesi olu�turuldu.
pencere=Tk()
#Pencere ba�l���n� ayarlad�k.
pencere.title("Scanner Tools")
#Pencere boyutlar�n� belirleme
pencere.geometry("500x500")
#Pencere boyutland�rma engelleme
pencere.resizable(False,False)
#Label olu�turma
labelIp=Label(text="IP Giriniz: ",
              fg="black",
               font=("Arial","15","bold"))
#Buton olu�turma
btnPortScan=Button(text = "Port Tarama",
                   command=PortScan,
                   width="8",
                   height="3"
)
#Buton olu�turma
btnSniffIPandARP=Button(text = "�stenilen IP Ping Atma",
                   command=sniffIPandARP,
                   width="8",
                   height="3"
)
#Buton olu�turma
btnPingIPAndHost=Button(text = "Port Tarama",
                   command=pingIPAndHost,
                   width="8",
                   height="3"
)
#Buton olu�turma
btnIcmpSniffer=Button(text = "ICMP Paketlerini koklama",
                   command=icmpPacketSniff,
                   width="8",
                   height="3"
)
#Textbox Olu�turma
txtIP=Entry()
#Listbox olu�turma -> Sonu�lar� g�rmek i�in.
listReturn=Listbox()
labelIp.grid(row=0,column=0)
txtIP.grid(row=0,column=1)
btnPortScan.grid(row=1,column=0)
btnSniffIPandARP.grid(row=1,column=1)
btnPingIPAndHost.grid(row=1,column=2)
btnIcmpSniffer.grid(row=1,column=3)
listReturn.grid(row=2,column=0,rowspan=10)


#Pencerenin s�rekli a��k kalmas�n� sa�lad�k."
mainloop()



