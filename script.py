#! /usr/bin/python3

import tomlkit
from scapy.all import *
import re
import json
from intervaltree import Interval, IntervalTree
#from memory_profiler import profile
import sys
class State(object):
    def __init__(self, signatures):
        self.signatures = signatures
        self.sessions = dict()


def log_detection(tv_sec, tu_sec, ip_src, ip_dst, tcp_sport, tcp_dport, sgid):
    print(
    json.dumps(
        dict(
            tv_sec=tv_sec,
            tu_sec=tu_sec,
            source=dict(
                ipv4_address=ip_src,
                tcp_port=tcp_sport),
                target=dict(
                    ipv4_address=ip_dst,
                    tcp_port=tcp_dport),
                     attack=sgid)))


class Session(object):
    def __init__(self, init_seq,windowscale=0):
        self.init_seq = init_seq
        self.buffer = []
        self.inttree = IntervalTree()
        self.handshake=False
        self.windowscale=windowscale
        self.calcwindow=0

def datafunc1(iv, islower):
    return payload[iv.begin.iv.end]


def merger(a, b):
    return memoryview(bytes(a) + bytes(b))


def checksum_calc(p1):
	checksum1=p1.chksum
	del p1.chksum
	new_packet=p1.__class__(bytes(p1))
	if(checksum1!=new_packet.chksum):
		return False
	else:
		return True
#@profile
def process_packet(state, p):
    ip = p[IP]
    if TCP not in ip:
        return
   # print(p.show())
    tcp = p[TCP]
    flow = (ip.src, ip.dst, tcp.sport, tcp.dport)
    flags = tcp.flags
    payload = raw(tcp.payload)
    
    if not checksum_calc(ip): #ip checksum calculation
#       print("checksum fail") 
       return;
    
    if not checksum_calc(tcp): #tcp checsum calculation
        return;

#    if tcp.flags.S and not tcp.flags.A:
    if tcp.flags.S:
#    if tcp.flags.S:
#        print('tcp', type(tcp.seq), 'ip', type(ip.len))
#        print(p[TCP].options)
        for i in p[TCP].options:
            if i[0] == "WScale":
                session = Session(tcp.seq,i[1])

#        session = Session(tcp.seq,p[TCP].options[4][1])
                state.sessions[flow] = session
#        print(tcp.flags)
#    if tcp.flags.A     
    if (tcp.flags.A and tcp.flags.P==0):
        session=state.sessions.get(flow)
        if session:
            if tcp.seq==session.init_seq+1:
                session.handshake=True                 
                session.calcwindow=tcp.window*(2**session.windowscale)
            del session
    if tcp.flags.F:
        try:
            del state.sessions[flow]
        except:
            pass


    if len(payload) > 0:
#        print(flow)
        session = state.sessions.get(flow)
#        print(session)
        try:
         if session.handshake:
          if len(payload) < session.calcwindow:   
            if session:        
                segment_start = tcp.seq
                buffer_offset = segment_start - session.init_seq
                buffer_end = buffer_offset + len(payload)
    #            session.inttree[buffer_offset:buffer_end]=payload
                overlap1 = session.inttree.overlap(buffer_offset, buffer_end)
                if len(overlap1):
                    overtree = IntervalTree([Interval(buffer_offset, buffer_end)])
                    for i in session.inttree:
                        overtree.chop(i.begin, i.end, datafunc1)
    #                overlapf
                    session.inttree = session.inttree.union(overtree)
                    print(session.inttree)
    #                overtree.clear()
                else:
                  session.inttree[buffer_offset:buffer_end] = memoryview(payload)
                  session.inttree.merge_neighbors(data_initializer=None, data_reducer=merger)
                  merged_data=list(session.inttree)
#                  print("merged_data")
                  if len(session.inttree) == 1 and len(list(session.inttree)[0].data) <= session.calcwindow:
                    for i, sig in enumerate(state.signatures):
    #                print(list(session.inttree.items())[0].data)
   #                    merged_data = list(session.inttree)
                       match=sig.search(merged_data[0].data)
 #                      print(merged_data[0].data)
                       if match:
                           print("enter match")
                           tv_sec=int(p.time)
                           tu_usec=int((p.time-float(tv_sec))*1000000.0)
                           log_detection(tv_sec,tu_usec,ip.src,ip.dst,tcp.sport,tcp.dport,i)
                           del state.sessions[flow]
                  elif len(list(session.inttree)[0].data) == session.calcwindow:
 #                     print("before",len(list(session.inttree)[0].data))
                      session.inttree.removei(merged_data[0].begin,merged_data[0].end,merged_data[0].data)
                      del merged_data
   #                        print("after",len(list(session.inttree))
   #                       session.inttree[merged_data[0].begin:merged_data[0].end]=b""
          else:
              return
 
         else:
               del state.sessions[flow]
        except:
            return
                

def main():
    sig_path=sys.argv[1]
    trace_pcap=sys.argv[2]
    sig_db=tomlkit.load(open(sig_path,"r"))
    signatures = [re.compile(x.encode()) for x in sig_db["signatures"] ]
    
    state= State(signatures)
    sniff(offline=trace_pcap,quite=True,filter="ip",prn=lambda p: process_packet(state,p))



if __name__ == "__main__":
    main()
