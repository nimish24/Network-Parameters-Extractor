#!/usr/bin/env python
#Nimish Kulkarni
#This program is used to extract network parameters


##################### PART 1 ###################

import MySQLdb as mdb
import paramiko #ssh module
import threading
import os.path #find and validate existance of file in the system
import subprocess #execute linux commands from python
import datetime
import time
import sys
import re #regular expressions

#module for output coloring
from colorama import init, deinit, Fore, Style
#init and deinit are for initializaton
#Fore sets the text color
# Style sets the brightness






#initialize colorama
init()

#Checking no of files passes to the script

if (len(sys.argv)) == 4:
    ip_file = sys.argv[1]
    user_file = sys.argv[2]
    sql_file = sys.argv[3]
    
    print Fore.BLUE + Style.BRIGHT + "\nThe script will be executed using following files:\n"
    print Fore.BLUE + "Cisco IP file is: " + Fore.YELLOW + "%s" %ip_file
    print Fore.BLUE + "SSHv2 User credentials file is: " + Fore.YELLOW + "%s" %user_file
    print Fore.BLUE + "MySQL connection file is: " + Fore.YELLOW + "%s" %sql_file
    print Fore.BLUE + Style.BRIGHT + "\n"
    
    
else:
    print Fore.RED + Style.BRIGHT + "\nWrong number of files entered"
    print Fore.RED + Style.BRIGHT + "\nPlease try again"
    sys.exit()
    

#Checking IP address file and content validity
def ip_is_valid():
    check = False
    global ip_list
    
    while True:
        try:
            #open the selected file
            selected_ip_file = open(ip_file,'r')
            #move the cursor to top for reading
            selected_ip_file.seek(0)
            #reading each line
            ip_list = selected_ip_file.readlines()
            #close the file
            selected_ip_file.close()
        except IOError:
            print Fore.RED + Style.BRIGHT + "\nThe file %s does not exist. Please enter the correct file name." %ip_file
            sys.exit()
            
    
        #checking octets
        for ip in ip_list:
            a = ip.split(".")
            
            if (len(a) == 4) and (1 <= int(a[0]) <= 223) and (int(a[0]) != 127) and (int(a[0]) != 169 or int(a[1]) != 254) and (0 <= int(a[1]) <= 255 and 0 <= int(a[2]) <= 255 and 0 <= int(a[3]) <= 255): 
                check = True
                break
            else:
                print Fore.RED + "\nInvalid IP address. Please try again"
                check = False
                continue
            
        if check == False:
            sys.exit()
        elif check == True:
            break
        
            
    #checking IP reachability
    print "\nChecking IP rechability....."
    check2 = False
    
    while True:
        for ip in ip_list:
            ping_reply = subprocess.call(['ping', '-c', '3', '-w', '3', '-q', '-n',ip], stdout = subprocess.PIPE)
            
            if ping_reply == 0:
                check2 = True
                continue
            
            elif ping_reply == 2:
                print Fore.RED + "\nNo ping response received"
                check2 = False
                break
            
            else:
                print Fore.RED + "\nPing to the following device has failed: %s" %ip
                check2 = False
                break
        
        if check2 == False:
            print Fore.RED + "\nPlease check the IP addresses in the file"
            break
        
        elif check2 == True:
            print Fore.YELLOW + "\nAll the devices are reachable"
            print Fore.BLUE + "\nNow establishing SSH session with devices....."
            break
 
#checking user file validity       
def user_is_valid():
    global user_file
    
    while True:
        if os.path.isfile(user_file) == True:
            print Fore.YELLOW + "\nThe user file is validated."
            break
        else:
            print Fore.RED + "\nFile %s does not exist. Please try again" %user_file
            sys.exit()

#Checking SQL connection file validity
def sql_con_is_valid():
    global sql_file
    
    while True:
        if os.path.isfile(sql_file) == True:
            print Fore.YELLOW + "\nThe SQL connection file is validated"
            print Fore.YELLOW + "\nAny errors in the will be logged in: " + Fore.GREEN + "SQL_ERROR_LOG.txt"
            print "\Reading network data and writing to MySQL database...."
            break
        else:
            print Fore.RED + "\SQL file %s does not exist. Please try again" %sql_file
            sys.exit()

#canging exception messages
try:
    ip_is_valid()
except KeyboardInterrupt:
    print Fore.RED + "\Program aborted by user. Exiting...\n"
    sys.exit()
    
try:
    user_is_valid()
except KeyboardInterrupt:
    print Fore.RED + "\Program aborted by user. Exiting...\n"
    sys.exit()
            
try:
    sql_con_is_valid()
except KeyboardInterrupt:
    print Fore.RED + "\Program aborted by user. Exiting...\n"
    sys.exit()

############################### PART 2 ############################

check_sql = True
def sql_connection(command, values):
    global check_sql
    
    selected_sql_file = open(sql_file, 'r')
    
    #Starting from the beginning of the file
    selected_sql_file.seek(0)

    sql_host = selected_sql_file.readlines()[0].split(',')[0]
    
    #Starting from the beginning of the file
    selected_sql_file.seek(0)
    
    sql_username = selected_sql_file.readlines()[0].split(',')[1]
    
    #Starting from the beginning of the file
    selected_sql_file.seek(0)
    
    sql_password = selected_sql_file.readlines()[0].split(',')[2]
    
    #Starting from the beginning of the file
    selected_sql_file.seek(0)
    
    sql_database = selected_sql_file.readlines()[0].split(',')[3].rstrip("\n")
    
    try:
        sql_conn = mdb.connect(sql_host, sql_username, sql_password, sql_database)
    
        cursor = sql_conn.cursor()
    
        cursor.execute("USE NetMon")
        
        cursor.execute(command, values)
        
        #Commit changes
        sql_conn.commit()
        
    except mdb.Error, e:
        #print Fore.RED + "Error in SQL connection. Check the log file: " + Fore.YELLOW + "SQL_ERROR_LOG.txt" + Fore.WHITE
        
        sql_log_file = open("SQL_Error_Log.txt", "a")
        
        #Print any SQL errors to the error log file
        print >>sql_log_file, str(datetime.datetime.now()) + ": Error %d: %s" % (e.args[0],e.args[1])
        
        #Closing sql log file:    
        sql_log_file.close()
        
        #Setting check_sql flag to False if any sql error occurs
        check_sql = False
        
    selected_sql_file.close()
        
#Initialize the necessary lists and dictionaries

cpu_values = []
io_mem_values = []
proc_mem_values = []
upint_values = []

top3_cpu = {}
top3_io_mem = {}
top3_proc_mem = {}
top3_upint = {}

#Open SSH connection to devices
def open_ssh_con(ip):
    global check_sql
    
    try:
        
        selected_user_file = open(user_file,'r')
        selected_user_file.seek(0)
        
        username = selected_user_file.readlines()[0].split(",")[0]
        selected_user_file.seek(0)
        password = selected_user_file.readlines()[0].split(",")[1].rstrip("\n")
        
        session = paramiko.SSHClient()
        session.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        session.connect(ip, username = username, password = password)
        
        connection = session.invoke_shell()
        connection.send("terminal length 0\n")
        time.sleep(1)
        
        #Reading commands from the script
        #"\" charachter is for line continuation for better redeability
        cisco_commands = '''show version | include (, Version|uptime is|bytes of memory|Hz)&\
                            show inventory&\
                            show interfaces | include bia&\
                            show processes cpu | include CPU utilization&\
                            show memory statistics&\
                            show ip int brief | include (Ethernet|Serial)&\
                            show cdp neighbors detail | include Device ID&\
                            show ip protocols | include Routing Protocol'''
        
        #Splitting each command
        command_list = cisco_commands.split("&")
        
        for each_command in command_list:
            connection.send(each_command + '\n')
            time.sleep(3)
            
        selected_user_file.close()
        output = connection.recv(65535)
        
        if re.search(r"%Invalid input detected at", output):
            print Fore.RED + "There was error at device: %s" %ip
        else:
            print Fore.GREEN + "All parameters were extracted successfully from device: %s" %ip
            
            
        
        
        
        
        ################# PART 3 #######################
        
        #Extracting network parameters using regular expressions
        # starting with the ones destined to NetworkDevices table in MySQL
        
        #hostname
        dev_hostname = re.search(r"(.+) uptime is", output)
        hostname = dev_hostname.group(1)
        #print hostname
        
        
        #MAC Address
        dev_mac_addr = re.findall(r"\(bia (.+?)\)", output)
        mac = dev_mac_addr[0]
        #print mac
        
        #Vendor
        dev_vendor = re.search(r"(.+?) (.+) bytes of memory", output)
        vendor = dev_vendor.group(1)
        #print vendor
        
        #model
        dev_model = re.search(r"(.+?) (.+?) (.+) bytes of memory", output)
        model = dev_model.group(2)
        #print model
        
        #Image
        dev_image_name = re.search(r" \((.+)\), Version", output)
        image_name = dev_image_name.group(1)
        #print Image
        
        #Version
        dev_os = re.search(r"\), Version (.+),", output)
        os = dev_os.group(1)
        #print Version
        
        serial_no = ""
        if len(re.findall(r"(.+), SN: (.+?)\r\n", output)) == 0:
            serial_no = "unknown"
        else:
            serial_no = re.findall(r"(.+), SN: (.+?)\r\n",output)[0][1].strip()
            
        dev_uptime = re.search(r" uptime is (.+)\n",output)
        uptime = dev_uptime.group(1)
        uptime_value_list = uptime.split(", ")
        
        #getting the uptime in seconds
        y_sec = 0
        w_sec = 0
        d_sec = 0
        h_sec = 0
        m_sec = 0
        
        for j in uptime_value_list:
            if 'year' in j:
                y_sec = int(j.split(' ')[0]) * 31449600
            elif 'week' in j:
                w_sec = int(j.split(' ')[0]) * 604800
            elif 'day' in j:
                d_sec = int(j.split(' ')[0]) * 86400
            elif 'hour' in j:
                h_sec = int(j.split(' ')[0]) * 3600
            elif 'minute' in j:
                m_sec = int(j.split(' ')[0]) * 60
            #elif 'second' in j:
                #s_sec = int(j.split(' ')[0
        total_uptime_sec = y_sec + w_sec + d_sec + h_sec + m_sec
        
        #CPU model.....show version | include bytes of memory
        
        cpu_model = ""
        if re.search(r".isco (.+?) \((.+)\) processor(.+)\n", output) == None:
            cpu_model = "unknown"
        else:
            cpu_model = re.search(r".isco (.+?) \((.+)\) processor(.+)\n",output).group(2)
        #cpu speed
        cpu_speed = ""
        if re.search(r"(.+?)at (.+?)MHz(.+)\n", output) == None:
            cpu_speed = "unknown"
        else:   
            cpu_speed = re.search(r"(.+?)at (.+?)MHz(.+)\n", output).group(2)
            
        #Serial int info
        
        serial_int = ""
        if re.findall(r"Serial([0-9]*)/([0-9]*) (.+)\n", output) == None:
            serial_int = "no serial"
        else:
            serial_int = re.findall(r"Serial([0-9]*)/([0-9]*) (.+)\n", output)
            
        #cisco neighbors...sh cdp neoghbors detail | include Device ID
        dev_cdp_neighbors = re.findall(r"Device ID: (.+)\r\n", output)
        all_cdp_neighbors = ",".join(dev_cdp_neighbors)
        
        dev_routing_protocols = re.findall(r"Routing Protocol is \"(.+)\"\r\n", output)
        is_internal = []
        is_external = []
        
        for protocol in dev_routing_protocols:
            if 'bgp' in dev_routing_protocols:
                is_external.append(protocol)
            else:
                is_internal.append(protocol)
        
        internal_pro = ",".join(is_internal)
        external_pro = ",".join(is_external)
        
        
        ########################## PART 4 #####################
        
        ############ CPU ##########
        dev_cpu_util_per5min = re.search(r"CPU utilization for five seconds: (.+) five minutes: (.+?)%", output)
        cpu_util_per5min = dev_cpu_util_per5min.group(2)
        
        #append the cpu values in the list
        cpu_values.append(int(cpu_util_per5min))
        
        #get top 3 devices
        top3_cpu[hostname] = cpu_util_per5min
        
        ###### Proc Memory #######
        dev_used_proc_mem = re.search(r"Processor(.+)\n ", output)
        dev_used_proc_mem = dev_used_proc_mem.group(1)
        
        total_proc_mem = dev_used_proc_mem.split('   ')[2].strip()
        used_proc_mem = dev_used_proc_mem.split('   ')[3].strip()
        
        proc_mem_percent = format(int(used_proc_mem) *100/float(used_proc_mem), ".2f")
        proc_mem_values.append(float(proc_mem_percent))
        top3_proc_mem[hostname] = proc_mem_values
        
        
        ################## IO values #############################
        dev_used_io_mem = re.search(r"      I/O(.+)\n", output)
        dev_used_io_mem = dev_used_io_mem.group(1)
        
        total_io_mem = dev_used_io_mem.split('   ')[2].strip()
        used_io_mem = dev_used_io_mem.split('   ')[3].strip()
        
        io_mem_percent = format(int(used_io_mem)*100 / float(total_io_mem), ".2f")
        io_mem_values.append(float(io_mem_percent))
        top3_io_mem[hostname] = io_mem_values
        
        
        ######### UP Ethernet interfaces ############
        #show interfaces | include Ethernet|Serial
        
        dev_total_int = re.findall(r"([A-Za-z]*)Ethernet([0-9]*)(.+)YES(.+)\n", output)
        total_int = len(dev_total_int)
        
        dev_total_up_int = re.findall(r"(.+)Ethernet([0-9]*)/([0-9]*)[\s]*(.+)up[\s]*up", output)
        total_up_int = len(dev_total_up_int)
        
        #percent of up ethernet interfaces
        intf_percent = format( total_up_int * 100/ float(total_int), ".2f" )
        
        upint_values.append(float(intf_percent))
        
        top3_upint[hostname] = intf_percent
        
        sql_connection("REPLACE INTO NetworkDevices(Hostname,MACAddr,Vendor,Model,Image,IOSVersion,SerialNo,Uptime,CPUModel,CPUSpeed,SerialIntfNo,CiscoNeighbors,IntRoutingPro,ExtRoutingPro) VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", (hostname, mac, vendor, model, image_name, os, serial_no, total_uptime_sec, cpu_model, cpu_speed, serial_int, all_cdp_neighbors, internal_pro, external_pro))
        
        #close SSH session
        session.close()
                
    except paramiko.AuthenticationException:
        print Fore.RED + "Invalid SSH username/password. Please check the username/password file and try again"
        check_sql = False
        
        
#Threads function


def create_threads():
    threads = []
    for ip in ip_list:
        th = threading.Thread(target = open_ssh_con, args = (ip,))
        th.start()
        threads.append(th)

    for th in threads:    
        th.join()
create_threads()


#################### PART 5 ##################

#poll date and time are based on system clock
poll_timestamp = datetime.datetime.now()


#function to get top3 devices for various paramerters
def top3(each_dict):
    global top3_list
    top3 =[]
    
    for host, usage in sorted(each_dict.items(),key = lambda x: x[1], reverse = True)[:3]:
        top3.append(host)
        top3_list = ",".join(top3)
        
def cpu_average():
    try:
        #parameters for the table CPUUtilization
        cpu = sum(cpu_values) / float(len(cpu_values))
        
        top3(top3_cpu)
        sql_connection("INSERT INTO CPUUtilization(NetworkCPUUtilizationPercent,Top3CPUDevices,PollTimestamp) VALUES(%s, %s, %s)", (cpu, top3_list, poll_timestamp))
    except ZeroDivisionError:
        print Fore.RED + "There was an error while computing network parameter. Please try again"

cpu_average()

def mem_proc_average():
    try:
        mem_proc = sum(proc_mem_values)/float(len(proc_mem_values))  
        
        top3(top3_proc_mem)
        
        sql_connection("INSERT INTO ProcMemUtilization(NetworkProcMemUtilizationPercent,Top3ProcMemDevices,PollTimestamp) VALUES(%s, %s, %s)", (mem_proc, top3_list, poll_timestamp))
    
    except ZeroDivisionError:
        print Fore.RED + "There was an error while computing network parameter. Please try again"
mem_proc_average()

def mem_io_average():
    try:
        mem_io = sum(io_mem_values) / float(len(io_mem_values))
        
        top3(top3_io_mem)
        
        sql_connection("INSERT INTO IOMemUtilization(NetworkIOMemUtilizationPercent,Top3IOMemDevices,PollTimestamp) VALUES(%s, %s, %s)", (mem_io, top3_list, poll_timestamp))        
    except ZeroDivisionError:
        print Fore.RED + "There was an error while computing network parameter. Please try again"
        
mem_io_average()

def upint_total():
    try:
        upint = sum(upint_values) / float(len(upint_values))
        
        #Calling the top3 function for the UP intf dictionary
        top3(top3_upint)
        
        #Write values to the MySQL database UPEthInterfaces table
        sql_connection("INSERT INTO UPEthInterfaces(NetworkUPEthIntfPercent,Top3UPEthIntf,PollTimestamp) VALUES(%s, %s, %s)", (upint, top3_list, poll_timestamp))
        
    except ZeroDivisionError:
        print Fore.RED + "There was an error while computing network parameter. Please try again"
        
upint_total()

if check_sql == True:
    print Fore.YELLOW + "All parameters were successfully extracted and stored in MySQL"
else:
    print Fore.RED + "There was problem exportind data to MySQL. Check the files, databases and SQL_Error_Log.txt "

deinit()
