#!/usr/bin/python
# Usage:
#   (0) Install the pyperclip or Tkinter Python plugin
#   (1) Start this python script to listen on clipboard changes
#   (2) Copy the AH IE's content from wireshark
#   (3) The python script processes the clipboard content, and prints the parsed result
#
# Note that by default the clipboard's content is retrieved through lib pyperclip, it
# could also be though the Tkinter lib, uncomment any Tkinter related lines to use it.
#

DEBUG_ENABLE = False

'''
Note 1: Always copy the _whole IE_(e.g. Tag: Vendor Specific: Aerohive), not the whole frame or just the 'Vendor Specific Data' field inside the IE, so that the python script can recognize different AH IE types

Note 2: There are several forms of content you can copy from wireshark:

#1. "Description"
Tag: Vendor Specific: Aerohive

#2. "Fieldname"
wlan_mgt.tag

#3. "Value"
1

#4. "As Filter"
frame[320:68] == dd:42:00:19:77:01:04:04:14:03:00:00:00:11:3f:0c:18:1a:3e:12:66:8f:2f:da:9c:5d:12:00:30:40:2a:e1:9c:5d:12:00:30:64:16:00:00:00:00:00:14:f4:00:00:2a:97:cf:71:00:00:00:00:28:02:22:00:a6:00:00:00:00:00:48:00

#5. "Bytes -> Offset Hex Text"
0000   dd 42 00 19 77 01 04 04 14 03 00 00 00 11 3f 0c  .B..w.........?.
0010   18 1a 3e 12 66 8f 2f da 9c 5d 12 00 30 40 2a e1  ..>.f./..]..0@*.
0020   9c 5d 12 00 30 64 16 00 00 00 00 00 14 f4 00 00  .]..0d..........
0030   2a 97 cf 71 00 00 00 00 28 02 22 00 a6 00 00 00  *..q....(.".....
0040   00 00 48 00                                      ..H.
#6. "Bytes -> Offset Hex"
0000   dd 42 00 19 77 01 04 04 14 03 00 00 00 11 3f 0c
0010   18 1a 3e 12 66 8f 2f da 9c 5d 12 00 30 40 2a e1
0020   9c 5d 12 00 30 64 16 00 00 00 00 00 14 f4 00 00
0030   2a 97 cf 71 00 00 00 00 28 02 22 00 a6 00 00 00
0040   00 00 48 00

#7. "Bytes -> Printable Text Only"
Bw?>f/]0@*]0d*q("H

#8. "Bytes -> Hex Stream"
dd420019770104041403000000113f0c181a3e12668f2fda9c5d120030402ae19c5d1200306416000000000014f400002a97cf710000000028022200a600000000004800

#9. "Bytes -> Binary Stream"

Please only use one of forms #4, #5, #6 and #8 when copying the IE content, since they provide enough information to tell both the IE types and contents
'''

#from Tkinter import *
import pyperclip
import time
import string
import array

#root = Tk();
#root.withdraw();
text_old = ''

def DEBUG(s):
    if DEBUG_ENABLE == True:
        print s

def val2str(set, val):
    try:
        return set[val]
    except:
        return 'Unknown'

def flag2str(flagset, val):
    cstr = ''
    for (k, v) in flagset.items():
       if val & k: cstr += (v+' ')
    return cstr

def byte2int(bytes = [], endian = 'L'):
    n = len(bytes); val = 0
    if n != 1 and n != 2 and n != 4:
        print 'The function takes a list with 1/2/4 bytes'
        return 0
    if endian.upper() == 'B' or endian.upper() == 'BIG':
        for i in range(n-1, -1, -1):
            val |= (bytes[i] << ((n - 1 - i) * 8))
    else:
        for i in range(0, n):
            val |= (bytes[i] << (i * 8))
    return val
         
def byte2mac(d = []):
    if len(d) != 6:
        print 'The function takes a list with 6 bytes as MAC addr'
        return 0
    return "%02x%02x:%02x%02x:%02x%02x" % (d[0], d[1], d[2], d[3], d[4], d[5])

def byte2ip(bytes = []):
    if len(bytes) != 4:
        print 'The function takes a list with 4 bytes as IP addr'
        return 0
    for i in [0, 3, 2, 1]:
        bytes[i] ^= bytes[i-1]
    return bytes


VENDOR_IE_HEADER_LEN = 5    # ie_type(1) + len(1) + oui(3)

# the common Aerohive vendor IE header
def parse_ah_ie_header(d):
    DEBUG(d)
    i = VENDOR_IE_HEADER_LEN
    print "\ttype: %d" % d[i]; i += 1
    print "\tversion: %d" % d[i]; i += 1
    return i

def parse_ah_ie_acsp(d):
    def s_acsp_state(v):
        return val2str(['INIT', 'SCAN', 'LISTEN', 'RUN', 'STATIC', 'SCHED_WAIT'], v)
    def s_radio_mode(v):
        return val2str({0xa:'AP', 0xe:'SENSOR'}, v)
    def s_fo_state(v):
        return val2str(['DISABLED', 'BACKUP', 'SCAN', 'REQUEST', 'RUN'], v)
    def s_fo_role(v):
        return val2str(['PASSIVE', 'ACTIVE'], v)

    i = parse_ah_ie_header(d)
    print "\tacsp_state: %d (%s)" % (d[i], s_acsp_state(d[i])); i += 1
    print "\tmax_tx_power: %d" % d[i]; i += 1
    print "\tcur_tx_power_limit: %d" % d[i]; i += 1
    print "\tcur_mgt_tpbo: %d" % d[i]; i += 1
    print "\tcur_data_tpbo: %d" % d[i]; i += 1
    print "\tcur_tx_power_state: %d" % d[i]; i += 1
    print "\tproduct_id: %d" % d[i]; i += 1
    print "\tdata_rev: 0x%04x" % byte2int(d[i:i+2]); i += 2
    print "\tnode_ip: %d.%d.%d.%d" % tuple(byte2ip(d[i:i+4])); i += 4
    print "\thive_id_hash: 0x%08x" % byte2int(d[i:i+4]); i += 4
    print "\tnode_id: %s" % byte2mac(d[i:i+6]); i += 6
    print "\tchanspec: 0x%04x" % byte2int(d[i:i+2]); i += 2
    print "\tradio_id: %s" % byte2mac(d[i:i+6]); i += 6
    print "\tnetmask: %d" % d[i]; i += 1
    print "\tmesh_fo_chan_quality: %d" % d[i]; i += 1
    stat = byte2int(d[i:i+2])
    print "\tmesh_status: 0x%04x, (fo_state: %s, fo_role: %s, w0_backhaul: %d, w1_backhaul: %d, portal_reach: %d)" % \
        (stat, s_fo_state(stat & 0xf), s_fo_role((stat >> 4) & 3), (stat >> 6) & 1, (stat >> 7) & 1, (stat & 0x0100)); i += 2
    print "\tmesh_fo_chan: %d" % byte2int(d[i:i+2]); i += 2
    print "\tacsp_seq: 0x%08x" % byte2int(d[i:i+4]); i += 4
    print "\thive_pwd_hash_key: 0x%08x" % byte2int(d[i:i+4]); i += 4
    print "\tbackhaul_chan: %d, %d" % (byte2int(d[i:i+2]), byte2int(d[i+2:i+4])); i += 4
    print "\ttot_cu: %d" % d[i]; i += 1
    print "\ttx_cu: %d" % d[i]; i += 1
    print "\trx_cu: %d" % d[i]; i += 1
    print "\tcrc_err: %d" % d[i]; i += 1
    print "\tnf: %d" % d[i]; i += 1
    print "\tsta_cnt: %d" % d[i]; i += 1
    print "\tduration: 0x%08x" % byte2int(d[i:i+4]); i += 4
    print "\tacsp_nbrs: %d" % d[i]; i += 1
    print "\tradio_mode: %d (%s)" % (d[i], s_radio_mode(d[i])); i += 1
        

def parse_ah_ie_meshid(d):
    i = parse_ah_ie_header(d)
    print "\tid: %s" % array.array('B', d[i:]).tostring(); i += 32


def parse_ah_ie_meshcap(d):
    def peercapa2str(val):
        return flag2str({0x8000:'ISMP', 0x4000:'UNIMODE', 0x2000:'CONNAS'}, val)
    def pwrsvcap2str(val): 
        return flag2str({0x80:'SUPPS', 0x40:'REQPS', 0x20:'PSSTATE'}, val)
    def synccap2str(val): 
        return flag2str({0x01:'SUPSYNC', 0x02:'REQSYNC', 0x04:'INSYC', 0x08:'PORTAL-REACHABLE'}, val)
    def mdacap2str(val): 
        return flag2str({0x01:'SUPDMA', 0x02:'ACTIVE', 0x04:'REQMDA', 0x08:'NOTALLOW', 0x10:'ENEDCA'}, val)

    i = parse_ah_ie_header(d)
    print "\tactprotoid.oui: %02x:%02x:%02x" % (d[i], d[i+1], d[i+2]); i += 3
    print "\tactprotoid.id: %d" % d[i]; i += 1
    print "\tactmetricid.oui: %02x:%02x:%02x" % (d[i], d[i+1], d[i+2]); i += 3
    print "\tactmetricid.id: %d" % d[i]; i += 1
    capa = byte2int(d[i:i+2])
    print "\tpeercapa: 0x%04x (%s, max_peers: %d)" % (capa, peercapa2str(capa), (capa & 0x1fff)); i += 2
    print "\tpwrsvcap: 0x%02x (%s)" % (d[i], pwrsvcap2str(d[i])); i += 1
    print "\tsynccap: 0x%02x (%s)" % (d[i], synccap2str(d[i])); i += 1
    print "\tmdacap: 0x%02x (%s)" % (d[i], mdacap2str(d[i])); i += 1
    print "\tchanprec: 0x%08x" % byte2int(d[i:i+4]); i += 4


def parse_ah_ie_meshportreach(d):
    i = parse_ah_ie_header(d)
    nportals = d[i]
    print "\tnportals: %d" % d[i]; i += 1
    for n in range(0, nportals):
        print "\tportals[%d].mac: %s" % (n, byte2mac(d[i:i+6])); i += 6
        print "\tportals[%d].metric: 0x%08x" % (n, byte2int(d[i:i+4])); i += 4


def parse_ah_ie_meshbeatiming(d):
    i = parse_ah_ie_header(d)


def parse_ah_ie_meshpeerreq(d):
    i = parse_ah_ie_header(d)
    print "\tdir: 0x%04x" % byte2int(d[i:i+2]); i += 2


def parse_ah_ie_meshpeerresp(d):
    def s_status(v):
        return val2str(['ACCEPT', 'DENY'], v)
    i = parse_ah_ie_header(d)
    print "\tstatus: %d (%s)" % (d[i], s_status(d[i])); i += 1


def parse_ah_ie_meshchanswitch(d):
    i = parse_ah_ie_header(d)
    print "\tmode: %d" % d[i]; i += 1
    print "\tnewchan: %d" % d[i]; i += 1
    print "\tnewprec: 0x%08x" % byte2int(d[i:i+4]); i += 4
    print "\tcount: %d" % d[i]; i += 1
    print "\tsrcmac: %s" % byte2mac(d[i:i+6]); i += 6


def parse_ah_ie_meshcompat(d):
    i = parse_ah_ie_header(d)
    print "\tsub_version: %d" % d[i]; i += 1



AH_IE_TYPE_ACSP            =    1
AH_IE_TYPE_MESHID          =    2
AH_IE_TYPE_MESHCAP         =    3
AH_IE_TYPE_MESHPORTREACH   =    4
AH_IE_TYPE_MESHBEATIMING   =    5
AH_IE_TYPE_MESHPEERREQ     =    6
AH_IE_TYPE_MESHPEERRESP    =    7
AH_IE_TYPE_MESHCHANSWITCH  =    8
AH_IE_TYPE_MESHCOMPAT      =    30

def str_is_hex(str):
    return all(c in string.hexdigits for c in str)
       

def parse_ah_ie(text):
    DEBUG("\n1>"+text+'<')
    if len(text) > 6 and text[0:6] == "frame[":
        DEBUG("Copyed as 'As Filter'")
        strs = text.split('==')[1].split(':')
    elif len(text) > 7 and str_is_hex(text[0:4]) == True and text[4:7] == '   ':
        lines = ''
        if len(text) > 56 and text[54:56] == '  ':
            DEBUG("Copyed as 'Bytes -> Offset Hex Text'")
            for line in text.split('\n'):
                DEBUG("2>"+line+'<')
                lines += (line[line.find('   '):line.rfind('  ')].strip() + ' ')
        else:
            DEBUG("Copyed as 'Bytes -> Offset Hex'")
            for line in text.split('\n'):
                DEBUG("3>"+line+'<')
                lines += (line[line.find('   '):len(line)].strip() + ' ')
        lines = lines.strip()
        DEBUG("4>"+lines+'<')
        strs = lines.split(' ')
        DEBUG("5>"+' '.join(strs)+'<')
    elif str_is_hex(text) == True:
        DEBUG("Copyed as 'Bytes -> Hex Stream'")
        i = 0
        line = ''
        for c in text:
            line += c
            i += 1
            if (i % 2 == 0): line += ' '
        line = line.strip()
        DEBUG("6>"+line+'<')
        strs = line.split(' ')
    else:
        DEBUG("Unknow copy form")
        return

    data = [int(s, base=16) for s in strs]
    if data[2] != 0x00 or data[3] != 0x19 or data[4] != 0x77:
        DEBUG("Non-Aerohive IE, ignore")
        return

    if data[5] == AH_IE_TYPE_ACSP:
        print '\n==[ACSP] =========================================================='
        parse_ah_ie_acsp(data) 
    elif data[5] == AH_IE_TYPE_MESHID:
        print '\n==[MESHID] ========================================================'
        parse_ah_ie_meshid(data) 
    elif data[5] == AH_IE_TYPE_MESHCAP:
        print '\n==[MESHCAP] ======================================================='
        parse_ah_ie_meshcap(data) 
    elif data[5] == AH_IE_TYPE_MESHPORTREACH:
        print '\n==[MESHPORTREACH] ================================================='
        parse_ah_ie_meshportreach(data) 
    elif data[5] == AH_IE_TYPE_MESHBEATIMING:
        print '\n==[MESHBEATIMING] ================================================='
        parse_ah_ie_meshbeatiming(data) 
    elif data[5] == AH_IE_TYPE_MESHPEERREQ:
        print '\n==[MESHPEERREQ] ==================================================='
        parse_ah_ie_meshpeerreq(data) 
    elif data[5] == AH_IE_TYPE_MESHPEERRESP:
        print '\n==[MESHPEERRESP] =================================================='
        parse_ah_ie_meshpeerresp(data) 
    elif data[5] == AH_IE_TYPE_MESHCHANSWITCH:
        print '\n==[MESHCHANSWITCH] ================================================'
        parse_ah_ie_meshchanswitch(data) 
    elif data[5] == AH_IE_TYPE_MESHCOMPAT:
        print '\n==[MESHCOMPAT] ===================================================='
        parse_ah_ie_meshcompat(data) 
    

print "Please copy the IE's content from wireshark, no need to paste"

text_new = ''
while True:
    #text_new = root.clipboard_get(type='STRING');
    text_new = pyperclip.paste()
    if text_new != None and text_new != text_old and len(text_new) > 5:
        text_old = text_new
        parse_ah_ie(text_new)
            
    try:
        time.sleep(1)
    except:
        break

#root.destroy();
quit()
