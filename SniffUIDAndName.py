from scapy.all import *
import argparse

HostIP = "47.99.146.3"

raw_data = None
namedb = {}

def SaveToData(log):
    global fp
    log = log + "\r\n"
    fp.write(log.encode())
    fp.flush()
    
def ProcessZlongPacket(packet):
    global raw_data
    
    if len(packet) == 1506:
        if raw_data != None:
            raw_data = raw_data + packet["Raw"].load
        else:
            raw_data = packet["Raw"].load
        return
    
    if packet.haslayer("Raw"):
        if raw_data != None:
            raw_data = raw_data + packet["Raw"].load
        else:
            raw_data = packet["Raw"].load
        index = raw_data.find("\x0A\x13\x33".encode())
        
        while(index != -1):
            name = None
            p = index
            uid = raw_data[p + 2 : p + 21].decode()
            p = index + 21
            try:
                if raw_data[p] != 0x12:
                    raw_data = raw_data[p:]
                    index = raw_data.find("\x0A\x13\x33".encode())
                    continue
            except IndexError:
                index = raw_data.find("\x0A\x13\x33".encode())
                print("asdfasdfasdfasd")
                continue
            p = index + 22
            
            nameLen = raw_data[p]
            p = p + 1
            try:
                name = raw_data[p : p + nameLen].decode("UTF8")
            except:
                pass
            p = p + nameLen
        
            if namedb.get(uid) == None:
                print(uid, name)
                if (name != None):
	                SaveToData(uid + "\t" + name)
	                namedb[uid] = name
            
            raw_data = raw_data[p:]
            index = raw_data.find("\x0A\x13\x33".encode())
    
    raw_data = None

parser = argparse.ArgumentParser()
parser.add_argument("-OutFile", "-out", help="数据库文件", default="DataBase.txt")

args = parser.parse_args()
fp = open(args.OutFile, "ab+")

sniff(filter="src host " + HostIP,prn=ProcessZlongPacket, store=0)