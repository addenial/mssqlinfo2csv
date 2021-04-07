#!/usr/bin/python


#use to parse ms-sql-info nmap xml 
#https://nmap.org/nsedoc/scripts/ms-sql-info.html

#nmap -Pn -n -p135,445,1433 --script ms-sql-info <host> -oX results-ms-sql-info.xml
#nmap -Pn -n -p135,445,1433 --script ms-sql-info -iL <hosts_file> -oX results-ms-sql-info.xml


import xml.etree.ElementTree as ET
import sys


usage = "Usage: " + sys.argv[0] + " results-ms-sql-info.xml"

if len(sys.argv) == 1:
    print(usage)
    sys.exit()
if "-h" in sys.argv:
    print(usage)
    sys.exit()
if "--help" in sys.argv:
    print(usage)
    sys.exit()

masssql_file = sys.argv[1]
tree = ET.parse(masssql_file)
root = tree.getroot()


#host_data = []

ipSERV= []
dnsSERV = []
winSERV= []
scriSERV= []

hosts = root.findall('host')
for host in hosts:
        
        script_element = host.findall('hostscript')
        try:
            script_namee = script_element[0].findall('script')[0].attrib['id']
        except IndexError:
            script_namee = ''
        #filter, only show if ms-sql-info script ran and tags exist, otherwise skip.. 
        if not script_namee =='ms-sql-info':
            continue
        #print(script_namee)
        

        
        #show/find ip
        ip_address = host.findall('address')[0].attrib['addr']
        #add ip to array, [ip,dns,winhost,script]
        ipSERV.append(ip_address)
         
        #show/find hostname DNS
        host_name_element = host.findall('hostnames')
        try:
            host_name = host_name_element[0].findall('hostname')[0].attrib['name']
        except IndexError:
            host_name = ''
        dnsSERV.append(host_name)
        #print("ip addresss- " + ip_address)
        #print("hostname- " + host_name)
        


        root1=host
        #look for detailssss
        for sup in root1.iter('script'):
            root2=ET.Element('root')
            #print(supply.attrib, supply.text) #shows script id, output.. better
            root2=(sup)
            for tech in root2.iter('elem'):
                root3 = ET.Element('root')
                root3=(tech)
                #printservernames
                if tech.attrib['key']=='Windows server name':
                    #print("##windows server- " + tech.text)
                    winSERV.append(tech.text)
        
        #this pulls in script output per each IP 
        script_element = host.findall('hostscript')
        script_outt = script_element[0].findall('script')[0].attrib['output']
        #print(script_outt) 
        scriSERV.append(script_outt)
        

#debug
#print(ipSERV)
#print(dnsSERV)
#print(winSERV)
#print(scriSERV)



#####good luck..this takes array num from scriSERV,outputs parsed dict
def parsZZ(parMEplz):
    #print(parMEplz)
    #pp = {}
    from collections import defaultdict
    d = defaultdict(list)

    instanceTEMP = []
    i=0  #mssql instance -key. 
    b=0  #tcp port
    c=0  #named pipe
    #lol d is used for dictionary.. dont overwrite :P
    e=0  #if clustered check
    g=0  #name of mssql version 
    for line in parMEplz.splitlines():
        #MSSQL INSTANCE NAME-KEY
        if "Instance" in line:
            #print("yooo found it? instance name = " + line)
            x = line.split(": ")
            #print(x[1])
            instanceTEMP.append(x[1])
            d[x[1]]
            i=i+1
        #TCPPORT
        if "TCP port" in line:
            #print("yooo found tcp port " + line)
            x = line.split(": ")
            #print(x[1])
            #instanceTEMP.append(x[1])
            try:
                d[instanceTEMP[b]].append(x[1])
                b=b+1
            except (IndexError,KeyError):
                continue
        #NAMEDPIPE
        if "Named pipe" in line:
            x = line.split(": ")
            #print(x[1])
            #instanceTEMP.append(x[1])
            d[instanceTEMP[c]].append(x[1])
            c=c+1
        #cluster?
        #if "Clustered" in line:
        #    #print(x[1])
        #    x = line.split(": ") 
        #    d[instanceTEMP[e]].append(x[1])
        #    e=e+1
        #mssql version installed. 
        #overwrites named pi???s
        #if "   name" in line:
         #   #print(line)
         #   x = line.split(": ") 
         #   print(x[1])
         #   d[instanceTEMP[g]].append(x[1])
         #   g=g+1
    #print(d)
    return d

###test change here which to parse
#parMEplz = scriSERV[7]
#print(parMEplz)
#function here, send scriSERV[x], get a response of dict file back. 


#~~~~~~WIN~~~~~~~~
#print(parsZZ(scriSERV[15]))
#print(parsZZ(scriSERV[15]))

#ozz = parsZZ(scriSERV[15])
#print(ozz.items())


print("IP,DNS,Server,Instance,TCP,Named Pipe")



#o=0
for index,element in enumerate(ipSERV):
    #print(index,element)
    #print(element +","+ dnsSERV[index] + "," + winSERV[index])
    #print(element) ##prints IP only.. 
    
    #multipe ip per instance below, for each -- 5example
    #udpate-- this should be for every key in tha dict
    oi = parsZZ(scriSERV[index])
    #print(oi)
    #print(oi[1])
    #for each in oi:


    for key, value in oi.items() :
        #print(key, value)
        #sometimes when no namedpipe, then only one val

        #--almost done, only missing here is instace. is that key?
        #print(key)
        try:
            print(element +","+ dnsSERV[index] + "," + winSERV[index] +"," + key + "," + value[0] + "," + value[1])
        except IndexError as error:
            print(element +","+ dnsSERV[index] + "," + winSERV[index] +"," + key +"," + value[0])
        #print(element +","+ dnsSERV[index] + "," + winSERV[index] +"," + each)
        #print(oi)
        #print(each)
        #print(element + "," + each)
        #print(d[each])
        #good, but need to convert list to string before concating. 
        #listToStr = ' '.join(map(str, d[each])) 
        #print(listToStr)  
        #o=o+1


#ipSERV= []
#dnsSERV = []
#winSERV= []
#scriSERV= []

