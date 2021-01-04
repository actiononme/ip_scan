#!/usr/bin/env python3

import click
import sys
import socket
import nmap3

class Port(object):

    save = []
    
    def __init__(self,ip,p,o):
        self.ip = ip
        self.output = o
        self.port = p

    def scan(self):
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        if type(self.port) == list:
            for num in range(int(self.port[0]),int(self.port[1])+1):
                # maybe some connect issue with other ip address such baidu.com
                result = s.connect_ex((self.ip,num))
                if result == 0:
                    self.save.append(num)
        else:
            result = s.connect_ex((self.ip,int(self.port)))
            if result == 0:
                self.save.append(int(self.port))

        s.close()
        self.detect()

    def detect(self):
        nmap = nmap3.Nmap()
        print(self.ip)

        for x in self.save:
            version_result = nmap.nmap_version_detection(self.ip,args='-p'+str(x))
            version = version_result[self.ip]['ports'][0]
            state = version['state']
            name = version['service']['name']

            if self.output != '':
                with open(self.output,'a') as f:
                    f.write(str(x)+" "+state+" "+name+"\n")
                f.close()

            print(x,state,name)



@click.command()
@click.option("-o",default='',help='to save the scan result')
@click.option("-p",default='',help='point the port to scan for:\r example 1-80 to scan 1 to 80 number of the port,or simple use 80 to scan the 80 port')
#@click.opeion("-s",default='',help='maybe use detect which port use in server')
@click.argument("ip")

def option(ip,o,p):
    if len(ip.split(".")) != 4:
        sys.exit("wrong ip address")

    for num in ip.split("."):
        if num.isnumeric():
            if int(num) > 255:
                sys.exit("wrong ip address")
        else:
            sys.exit("wrong ip adress")

    if p == '':
        sys.exit("we need -p argument to scan")
    elif "-" in p:
        portnumber = p.split("-")
        if not portnumber[0].isnumeric():
            sys.exit("wrong port select")
        elif not portnumber[1].isnumeric():
            sys.exit("wrong port select")
        elif len(portnumber) > 2:
            sys.exit("out the range -p")
        p = portnumber

    port = Port(ip,p,o)
    port.scan()

if __name__ == "__main__":
    option()
