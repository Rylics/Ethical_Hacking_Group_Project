import tkinter as tk
from tkinter import *
import nmap
import ipaddress
import re
from datetime import datetime
import os
import subprocess #we use this module to exec namp commands on terminal

window = tk.Tk()
window.config(background="ghostwhite")

port_range_pattern = re.compile("([0-9]+)-([0-9]+)")
port_min = 0
port_max = 65535

#Create different pages
page1 = Frame(window,background="ghostwhite")
page2 = Frame(window)
page3 = Frame(window)
page4 =  Frame(window)

c =Canvas(page1,bg="grey",height=200,width=200)
filename = PhotoImage(file="hacking.png")
background = Label(page1,image=filename)
background.place(x=2,y=0,relwidth=1, relheight=1 )
c.place(x=0,y=0 )

#Create the layout of the frames
page1.grid(row=0,column=0, sticky="nsew")
page2.grid(row=0,column=0, sticky="nsew")
page3.grid(row=0,column=0, sticky="nsew")
page4.grid(row=0,column=0, sticky="nsew")

page2.configure(bg='ghostwhite')

page3.configure(bg='ghostwhite')


# window.wm_attributes("-transparentcolor",'green')
#Page 1 Graphical Interface
lb1 = Label(page1,text="Ethical Hacking (CNS)", font=("Bold",30), background="#10104E", fg="white")

lb1.pack(pady=50)
lb2 = Label(page1,text="Lecturer: Kevin Johnson", font=("Bold",20),background="#10104E",fg="white")
lb2.pack(pady=50)

Scan_Button = Button(page1,text="Scan Ports",font=("Bold",15),
                                bg="#1877f2",
                                fg="white",width=20, command=lambda:page2.tkraise() )

IP_Address_Button = Button(page1,text="Intrusion Detection",font=("Bold",15),
                                bg="#1877f2",
                                fg="white",width=20, command=lambda:page3.tkraise() )

OS_Detection_Button = Button(page1,text="OS Detection",font=("Bold",15),
                                bg="#1877f2",
                                fg="white",width=20, command=lambda:page4.tkraise() )
Scan_Button.pack(pady=7)
IP_Address_Button.pack(pady=20)
OS_Detection_Button.pack()

#----------------------------Page 2 ( Scan Port )------------------


#Clear the Text-Box field
def clear():
    result_text.delete(1.0,END)
    textbox.delete(1.0,END)

def Page1_Save():
    curr_datetime = datetime.now().strftime('%Y-%m-%d %H-%M-%S')
    text_file = open(f'Logs/ScanPort-{curr_datetime}.txt','w')
    text_file.write(result_text.get(1.0,END))

    
#This function execute the command nmap -sT and then populate the result using Text-Box
def Scan():
  # Get the IP address and port range from the input fields
    ip_add_entered = IP_adress_Entry.get()
    port_range = Range_Entery.get()
    
    try:
        ip_address_obj = ipaddress.ip_address(ip_add_entered)
    except:
        (tk.END, "Invalid IP address\n")
        return

    port_range_valid = port_range_pattern.search(port_range.replace(" ", ""))
    if port_range_valid:
        port_min = int(port_range_valid.group(1))
        port_max = int(port_range_valid.group(2))
    else:
        result_text.insert(tk.END, "Invalid port range\n")
        return
    
    nm = nmap.PortScanner()
    nm.scan(ip_add_entered, f'{port_min}-{port_max}')
    hosts = nm.all_hosts()
    for host in hosts:

        for proto in nm[host].all_protocols():
            
            # Get the list of open ports for the current protocol
            lport = nm[host][proto].keys()
            # Iterate through each open port
            for port in lport:
                if nm[host][proto][port]["state"] == "open":
                    result_text.insert(tk.END, f' \t {port}\t|\t{proto} \t|\t {nm[host][proto][port]["state"]} \t|\t  {nm[host][proto][port]["name"]}\n',"warning")
                else:
                    result_text.insert(tk.END, f' \t {port}\t|\t{proto} \t|\t {nm[host][proto][port]["state"]} \t|\t  {nm[host][proto][port]["name"]}\n')
                

back_Button_2 = Button(page2,text="Back",font=("Bold",8),
                                bg="#1877f2",
                                fg="white",width=15, command=lambda:page1.tkraise() )
back_Button_2.grid(row=0,column=1,padx=5, pady=5)

#Text describing what to enter
data = Label(page2,text="Enter the IP Address :",width=25, borderwidth=.5, relief="solid",padx=10, pady=8).grid(row=1, column=0 , padx=10, pady=10)
Range =Label(page2,text="Enter Port Range (1-100)  :",width=25, borderwidth=.5, relief="solid",padx=10,pady=8).grid(row=2, column=0 , padx=10, pady=10)

#Input fields for IP Address and Range
IP_adress_Entry = Entry(page2,width=29)
IP_adress_Entry.grid(row=1, column=1)
Range_Entery = Entry(page2,width=29)
Range_Entery.grid(row=2, column=1)


#Display the results from the Scan Page 2
result_text = Text(page2, height=20, width=70)
result_text.grid(row=5,columnspan=2,column=0)
result_text.tag_config('warning', foreground="red")

#Action Events
Scan_Button = Button(page2,text="Scan",bg="lightgreen",width=25,padx=10,command=Scan).grid(row=3,column=0)
clear_Button = Button(page2,text="Clear",bg="red",width=25,command=clear).grid(row=3,column=1)
Save_Button = Button(page2,text="Save",font=("Bold",15),
                                bg="#1877f2",
                                fg="white",width=20,command=Page1_Save).grid(row=6,column=1, columnspan=2)
#The state of the Scan Labels
port = Label(page2,text="Port\t\t Type",width=25,padx=10).grid(row=4,column=0)
status =Label(page2,text="Status\t\tService",width=25).grid(row=4,column=1)


#----------------------------Page 3 (Intrusion Detection)-----------------------------


def Page2_Save():
    curr_datetime = datetime.now().strftime('%Y-%m-%d %H-%M-%S')
    text_file = open(f'Logs/Intrusion-{curr_datetime}.txt','w')
    text_file.write(textbox.get(1.0,END))

def Scan_Network():

# Initialize the nmap object
    nm = nmap.PortScanner()

    # Scan the network
    print(f'{Network_input.get()}/24')
    nm.scan(hosts=f'{Network_input.get()}/24', arguments='-sP')

    # Get the list of hosts
    hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]

    # Print the host information
    for host, status in hosts_list:
        if status == 'up':
            hostname = nm[host].hostnames()
            for name in hostname:
            	
            	textbox.insert(tk.END, f'\t{host}\t\t|{status}\t\t|{name["name"]}\t|{name["type"]}\n')
      


Back_Button_3 = Button(page3,text="Back",font=("Bold",12),
                                bg="#1877f2",
                                fg="white",width=8, command=lambda:page1.tkraise() )
Back_Button_3.grid(row=0,column=1,pady=10)

Tittle = Label(page3,text="Detect Users On Network", fg="red", font=("Bold",20),background="ghostwhite" ).grid(row=1,column=0,columnspan=2)

data1 = Label(page3,text="Enter the Network to be scan:", width=30, borderwidth=.5, relief="solid", padx=10,pady=10)
data1.grid(row=2,column=0, pady=10 ,padx=10)

Network_input= Entry(page3,width=30)
Network_input.grid(row=2,column=1)

Scan_Button1 = Button(page3,text="Scan",bg="lightgreen",width=25,padx=10,command=Scan_Network).grid(row=3,column=0)
clear_Button1 = Button(page3,text="Clear",bg="red",width=25,command=clear).grid(row=3,column=1)
Save_Button = Button(page3,text="Save",font=("Bold",15),
                                bg="#1877f2",
                                fg="white",width=20,command=Page2_Save).grid(row=6,column=1, columnspan=2)

Host = Label(page3,text="Host\t\t Status",width=23,padx=5).grid(row=4,column=0)
status =Label(page3,text="HostName\t Type",width=25).grid(row=4,column=1)


textbox = Text(page3, height=20, width=70)
textbox.grid(row=5,columnspan=2,column=0)




#----------------------------Page 4 (OS Detection)-----------------------------



def OsDiscovery():
    data =  subprocess.check_call(['nmap','-n','-F','-A','-Pn','-sS','-O','-oN',"os-detection.txt",OS_Entry.get()])
    text_file = open("os-detection.txt","r")
    data = text_file.read()
    OS_textbox.insert(tk.END, data )
    text_file.close()
  



back_Button_3 = Button(page4,text="Back",font=("Bold",8),
                                bg="#1877f2",
                                fg="white",width=15, command=lambda:page1.tkraise() )
back_Button_3.grid(row=0,column=1,padx=5, pady=5)

Os_ipAddress = Label(page4,text="Enter the IP Address :", width=30, borderwidth=.5, relief="solid", padx=10,pady=10).grid(row=1,column=0)
OS_Entry = Entry(page4,width=37)
OS_Entry.grid(row=1,column=1)
OS_textbox = Text(page4, height=30, width=71)

Scan_Button_3 = Button(page4,text="Start",font=("Bold",8),
                                bg="lightgreen",
                                fg="black",width=15, command=OsDiscovery)
Scan_Button_3.grid(row=2,column=0, columnspan=2, padx=10, pady=5)

OS_textbox.grid(row=3,columnspan=2,column=0)


page1.tkraise()

window.geometry("570x590")
window.title("Ethical Hacking")
window.resizable(False,False)

window.mainloop()


