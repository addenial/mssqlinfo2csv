#!/usr/bin/python


#use to parse ms-sql-info nmap xml 
#https://nmap.org/nsedoc/scripts/ms-sql-info.html

#nmap -Pn -n -p135,445,1433 --script ms-sql-info <host> -oX results-ms-sql-info.xml
#nmap -Pn -n -p135,445,1433 --script ms-sql-info -iL <hosts_file> -oX results-ms-sql-info.xml


#    python3 mssql-info-parser.py results-ms-sql-info.xml
#
# 
#
#  #ip,port - use for pw guessing
#  python3 mssql-info-parser.py results-ms-sql-info.xml | cut -d, -f1,2
#
#  ip,port,winhostname,instancename,namedpipe
#   python3 mssql-info-parser.py results-ms-sql-info.xml | cut -d, -f1,2,3,4,10
#
#
#    python3 mssql-info-parser.py results-ms-sql-info.xml | cut -d, -f1,5



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
ipSERCO= []

#ip,winserv
comboGetwinhostname= []

#ip,tcpport
soccETTT= []



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
        




        try:
            scriptoutt = script_element[0].findall('script')[0].attrib['output']
        except IndexError:
            scriptoutt = ''

        #print(scriptoutt)




        #print("@@@DBPWN- " + ip_address)
        #print(ip_address + ","  + "," + ","   + scriptoutt)
        #print("hostname- " + host_name)
        




##################
        #find details

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
                #print(tech.attrib['key'])
                #if tech.attrib['key']=='Windows server name':
                #    print(tech.text)
                    #elll = host.findall('address')[0].attrib['addr']
                    #print(elll)
                    #print(tech.text)
                    #note of servername to 
                                        
                    #print("##- " + elll + ",," + tech.text )
                 #   winSERV.append(tech.text)
                #print(ip_address)

                try:
                    if tech.attrib['key']=='Windows server name':
                        #print(tech.text)
                        #print("servername " + tech.text)
                        #print(ip_address + ","  + tech.text )
                        comboGetwinhostname.append(ip_address + "," + tech.text)
                        
                        winSERV.append(tech.text)
                    #else:
                        #winSERV.append(" ")
                except IndexError:
                    print("pinggg")
                    #ipSERCO.append(elll + ",," + tech.text)

                try:
                    if tech.attrib['key']=='TCP port':
                        #print(tech.text)
                        #print("servername " + tech.text)
                        #print(ip_address + "," + tech.text)
                        
                        soccETTT.append(ip_address + "," + tech.text)

                        #comboGetwinhostname.append(ip_address + "," + tech.text)
                        
                        #winSERV.append(tech.text)
                    #else:
                        #winSERV.append(" ")
                except IndexError:
                    print("pingggg but not rly cause faills")
                    #ipSERCO.append(elll + ",," + tech.text)
                #else:
                    #print(tech.attrib['key'])
                    #print("222222222222222222222222 no server name?????")
        
        #this pulls in script output per each IP 
        script_element = host.findall('hostscript')
        script_outt = script_element[0].findall('script')[0].attrib['output']
        #print(script_outt) 
        scriSERV.append(script_outt)
        
        #inhere is IPADDRESS
        #print(comboGetwinhostname[0].split(',')[0])
        #WINHOSTNAME
        
        #print(comboGetwinhostname[0].split(',')[0]  )
        
      
        
        #
        #
        #thaarray   IPADDRESS,winhostname
        ##try:
        #    x = len(comboGetwinhostname)
            #print(x) 
         #   #tempppIP = comboGetwinhostname[0].split(',')[0]
            #print(comboGetwinhostname[x].split(',')[0])
            #print(tempppIP)
        #except:
        #    print("a111   ") 

#debug
#print(ipSERV)
#print(dnsSERV)
#print(winSERV)
#print(scriSERV)
#print(ipSERCO)

#print tha mappings of IP,windowsServerr
#print(comboGetwinhostname)
#print(comboGetwinhostname[4])
#print(comboGetwinhostname[0].split(','))

#  from mappings, dis tha IP address ONLY from the first column
#print(comboGetwinhostname[0].split(',')[0])



#print(comboGetwinhostname[1])
#print(comboGetwinhostname[1].split(',')  )
#print(comboGetwinhostname[1].split(',') )


#try:
    #x = len(comboGetwinhostname)
    #print(x) #length starting at 1
    #bombsssss maybe try -1 cause thats correct array size for last item
    #print(comboGetwinhostname[x].split(',')  )
    #print(comboGetwinhostname[x-1].split(',')  )   #shows last item
    #print(comboGetwinhostname[x-1] )
            #tempppIP = comboGetwinhostname[0].split(',')[0]
            #print(comboGetwinhostname[x].split(',')[0])
            #print(tempppIP)
#except:
#    print("a111 000 :)  ") 




#print(soccETTT)
#print(ipSERV)




#####good luck..this takes array num from scriSERV,outputs parsed dict
def parsZZ(parMEplz):
    #print(parMEplz)
    #pp = {}
    from collections import defaultdict
    d = defaultdict(list)
    nameOO = ""
    nameOOnumm = ""
    nameOOprodd = "" 
    nameOOseripac = ""
    name00patchtho = ""

    namdddpipez = []
    npp = ""

    currTCP = ""
    instaTT = ""

    instanceTEMP = []
    i=0  #mssql instance -key. 
    b=0  #tcp port
    c=0  #named pipe
    #lol d is used for dictionary.. dont overwrite :P
    e=0  #if clustered check
    g=0  #name of mssql version 
    for line in parMEplz.splitlines():
        #MSSQL INSTANCE NAME-KEY
        #print(line)
        if "Instance" in line:
            #print("yooo found it? instance name = " + line)
            x = line.split(": ")
            #print(x[1])
            instanceTEMP.append(x[1])
            d[x[1]]
            i=i+1
            instaTT = x[1]
        #TCPPORT
        if "TCP port" in line:
            #print("yooo found tcp port " + line)
            x = line.split(": ")
            #print(x[1])
            #instanceTEMP.append(x[1])
            try:
                d[instanceTEMP[b]].append(x[1])
                currTCP = x[1]
                b=b+1
            except (IndexError,KeyError):
                continue
        #NAMEDPIPE
        if "Named pipe" in line:
            x = line.split(": ")
            #print(x[1])
            #instanceTEMP.append(x[1])
            #print(b)
            #print(currTCP)
            #d[instanceTEMP[c]].append(x[1])
            c=c+1
            namdddpipez.append(x[1])
            npp = x[1]
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
        #name
        if "name" in line:
            ee = line.split(": ")
            #print (ee[1])
            nameOO = ee[1]
        if "number" in line:
            ee = line.split(": ")
            nameOOnumm = ee[1]
        if "Product" in line:
            ee = line.split(": ")
            nameOOprodd = ee[1]
        if "Service pack" in line:
            ee = line.split(": ")
            nameOOseripac = ee[1]
        if "Post-SP patches" in line:
            ee = line.split(": ")
            name00patchtho = ee[1]
         
    #plop = namdddpipez 
    #print(plop)
    #print(npp)
    #print(instaTT)
    if instaTT == "":
        instaTT = ","
    dalista = instaTT + "," + nameOO + "," + nameOOnumm+ "," + nameOOprodd+ "," + nameOOseripac+ "," + name00patchtho + "," + npp 
    #print(nameOO + "," + nameOOnumm+ "," + nameOOprodd+ "," + nameOOseripac+ "," + name00patchtho )
    #print(d)
    #print(*namdddpipez )
    #print(d)
    #print(d.items)

#+ "," + namdddpipez 
    

    #print(instaTT)
    #import numpy as np
    #print(np.matrix(d))
    #print(d)
    #print(namdddpipez) d + "," + 
    aiiaseg = dalista
    #print(d)
    return aiiaseg

#give item1,item2
#get item2
def shoArraKEE(striin):
    #print("input funcctaia " + striin)
    rrir = striin.split(",")
    #print(rrir)
    #print(rrir[1])
    return(rrir[0])
def shoArTWOOO(striin):
    #print("input funcctaia " + striin)
    rrir = striin.split(",")
    #print(rrir)
    #print(rrir[1])
    return(rrir[1])
def shosocc(striin):
    #print("input funcctaia " + striin)
    rrir = striin.split(",")
    #print(rrir)
    #print(rrir[1])
    return(rrir[0] + "," + rrir[1])

def printteeALL():
    #print("canijsutprintll")
    finifia =[]
    #print("#####stat-ips found- " , len(ipSERV) , " ips found" )
    #print("#####sockett-ip-port--found- " , len(soccETTT) , " ip,tcpporort found" )#mostoftehse
    #print("#####ip-winhostname mapping- " , len(comboGetwinhostname) , " ips,hostnaem" )
    
    #cyclce through each socket ip:tcpport, since thatstahkey and mostuniqq^^^
    for each in soccETTT:
        #each ===== ip,port
        #each1 ===== ip,winhostnaem
        #match winhostname-to ip
        tempwinda = ""
        tempIPkeyonly = shoArraKEE(each)
        
        #print("yayayaya" , tempIPkeyonly)
        #print(comboGetwinhostname)
        tempneweachh = each
        
        for each1 in comboGetwinhostname:
        #    print("watupeachh " , each1 )
            #print("watogg? " , each ) #dontfuqwitit
            #print(shoArraKEE(each1))
            if tempIPkeyonly == shoArraKEE(each1):
                #print(each,",", shoArTWOOO(each1) )s
                tempneweachh = each + "," + shoArTWOOO(each1)
            #else:
                #print(each, "," )
            #if shoArraKEE(each1) == tempIPkeyonly:
            #    print(tempIPkeyonly, "," , shoArTWOOO(each1) )
            #print(shoArTWOOO(each1))
            #if shoArraKEE(each)
            #if each == shoArraKEE(each):
            #    print("somethinnsmatchin..:) " , each)
        #if each in comboGetwinhostname:
        #    print("don0")
        #print(tempneweachh)
        finifia.append(tempneweachh)
        #each = tempneweachh
        #print(each)
        #print(each)
        #print(each , )
    #print(finifia)
    return finifia
#print(dnsSERV)

#heh this the last item in our arrya
#peep send IP, get the 2nd column. 
#peep = comboGetwinhostname[18]
#shoArraKEE(peep)

#this just prints it out straight up
#shoArraKEE(comboGetwinhostname[0])
#shoArraKEE(comboGetwinhostname[3])


#printeeIPSSrit


#printteeALL()

latestyah = printteeALL()
#print(latestyah)


for each in latestyah:
    #print(each)
    
    ippp = shoArraKEE(each)
    ipppo = shosocc(each)
    #print(ipppo)
    
    #print(*ipppo)
    for each1 in scriSERV:
        #print(each1)
        if ippp in each1:
            print(each + "," + parsZZ(each1)  )
            #sprint()
            #shosocc(
            
            
        #if any(s in each1 for s in each):
         #   print("yooo this is tha " + ippp)

#script in array with ip indexed?? 
#print(scriSERV[1])
#print(scriSERV[0])
#print(scriSERV[2])

#ozz = parsZZ(scriSERV[1])
#ozz = parsZZ(scriSERV[99])
#print(ozz)
#print(ozz.items())
#print(parsZZ(scriSERV[0]))
#oa = parsZZ(scriSERV[0])
#sprint(oa)
#print(parsZZ(scriSERV[15]))


#arr = [2,4,5,7,9]
#arr_2d = [[1,2],[3,4]]
#print("The Array is: ", arr) #printing the array
#print("The 2D-Array is: ", arr_2d) #printing the 2D-Array
#printing the array
#print("The Array is : ")
#for i in arr:
#    print(i, end = ' ')
 
#printing the 2D-Array
#print("\nThe 2D-Array is:")
#for i in arr_2d:
#    for j in i:
#        print(j, end=" ")
#    print()
#for i in comboGetwinhostname:
#    for j in i:
#        print(j, end=" ")
#    print()

#
#+====++++++++++++++++++++++
###test change here which to parse
#parMEplz = scriSERV[7]
#print(parMEplz)
#function here, send scriSERV[x], get a response of dict file back. 


#~~~~~~WIN~~~~~~~~
#print(parsZZ(scriSERV[15]))
#print(parsZZ(scriSERV[15]))

#ozz = parsZZ(scriSERV[15])
#print(ozz.items())




########legacyyyyyyyyy
#print("IP,DNS,Server,Instance,TCP,Named Pipe")



#o=0
#for index,element in enumerate(ipSERV):
    #print(index,element)
    #print(element +","+ dnsSERV[index] + "," + winSERV[index])
    #print(element) ##prints IP only.. 
    
    #multipe ip per instance below, for each -- 5example
    #udpate-- this should be for every key in tha dict
    #oi = parsZZ(scriSERV[index])
    #print(oi)
    #print(oi[1])
    #for each in oi:


    #for key, value in oi.items() :
        #print(key, value)
        #sometimes when no namedpipe, then only one val
        #print(element)
        #print(dnsSERV[index])
        
        
        #print(index)
        #try:
        #    print(winSERV[index])
        #except:
        #    print('errrrrrr')
        #    winSERV[index] == ''       

        #--almost done, only missing here is instace. is that key?
        #print(key)
        #print(ipSERCO)
        #print(element)
        #if element == 
        
        #for iz in ipSERCO:
        #    print(ipSERCO[iz])
            #if animal == 'Bird':
            #    print('Chirp!')


        #try:
            #out of range error her.... 
            #if element == "  ":
            #    print("YOOOOOOOOOOOOOOOOOOOOOOOOOO")
            #print(element)
            #if element in comboGetwinhostname:
            #    print("idonoooooo")
#
            #print(element +","+ dnsSERV[index] + "," + "bs" +"," + key + "," + value[0] + "," + value[1])


            #print(element +","+ dnsSERV[index] + "," + winSERV[index] +"," + key + "," + value[0] + "," + value[1])
            #print(element +","+ dnsSERV[index] + "," + winSERV[index] )
        #except IndexError as error:
            #print(element +","+ dnsSERV[index] + "," + winSERV[index] +"," + key +"," + value[0])
            #print(element +","+ dnsSERV[index] + "," + "," +"," + key +"," + value[0])
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

