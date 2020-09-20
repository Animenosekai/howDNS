"""
A simple DNS Server made with Python3

Credit to HowCode.org for everything here.
Arranged by Anime no Sekai - 2020
"""

import glob
import json
import socket
import requests

port = 53
ip = '127.0.0.1'

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((ip, port))

def load_zones():
    """
    Loads the .zone files in ./zones in memory.
    """
    results = {}
    zonefiles = glob.glob('zones/*.zone')
    for zone in zonefiles:
        with open(zone) as zonefile:
            filedata = json.load(zonefile)
            url = filedata["$origin"]
            results[url] = filedata
    return results

# Global Variable Declaration (loading zone files in memory)
zonedata = load_zones()

def getflags(flags):
    """
    Parses the flags for the DNS Response
    """

    byte1 = bytes(flags[:1])
    byte2 = bytes(flags[1:2])

    rflags = ''
    QR = '1'
    OPCODE = ''
    for bit in range(1,5):
        OPCODE += str(ord(byte1)&(1<<bit))
    AA = '1'
    TC = '0'
    RD = '0'

    ##### Byte 2 #####
    RA = '0'
    Z = '000'
    RCODE = '0000'
    flagsresults = int(QR + OPCODE + AA + TC + RD, 2).to_bytes(1, byteorder='big') + int(RA + Z + RCODE, 2).to_bytes(1, byteorder='big')
    return flagsresults

def getquestiondomain(data):
    """
    Gets the Question Domain for a DNS response
    """
    state = 0
    expectedlength = 0
    domainstring = ''
    domainparts = []
    x = 0
    y = 0
    for byte in data:
        if state == 1:
            if byte != 0:
                domainstring += chr(byte)
            x += 1
            if x == expectedlength:
                domainparts.append(domainstring)
                domainstring = ''
                state = 0
                x = 0
            if byte == 0:
                domainparts.append(domainstring)
                break
        else:
            state = 1
            expectedlength = byte
        y += 1

    questiontype = data[y:y+2]

    return (domainparts, questiontype)

def getzone(domain):
    """
    Gets the .ZONE file data with the given domain
    """
    global zonedata
    zone_name = '.'.join(domain)
    if zone_name in zonedata:
        return zonedata[zone_name]
    else:
        google_dns = requests.get(f'https://dns.google.com/resolve?name={str(zone_name)}&type=A').text
        google_dns = json.loads(google_dns)
        results = {}
        results['a'] = []
        for answer in google_dns['Answer']:
            temp = {}
            for element in answer:
                if element == 'name':
                    temp['name'] = answer[element]
                elif element == 'TTL':
                    temp['ttl'] = answer[element]
                elif element == 'data':
                    temp['value'] = answer[element]
            results['a'].append(temp)
            temp = []
        return results

def getrecs(data):
    """
    Getting the records
    """
    domain, questiontype = getquestiondomain(data)
    qt = ''
    if questiontype == b'\x00\x01':
        qt = 'a'

    zone = getzone(domain)

    return (zone[qt], qt, domain)

def buildquestion(domainname, rectype):
    """
    Making the question field
    """
    qbytes = b''

    for part in domainname:
        length = len(part)
        qbytes += bytes([length])

        for char in part:
            qbytes += ord(char).to_bytes(1, byteorder='big')

    if rectype == 'a':
        qbytes += (1).to_bytes(2, byteorder='big')

    qbytes += (1).to_bytes(2, byteorder='big')

    return qbytes

def rectobytes(domainname, rectype, recttl, recval):
    """
    Records to Bytes
    """
    rbytes = b'\xc0\x0c'

    if rectype == 'a':
        rbytes = rbytes + bytes([0]) + bytes([1])

    rbytes = rbytes + bytes([0]) + bytes([1])

    rbytes += int(recttl).to_bytes(4, byteorder='big')

    if rectype == 'a':
        rbytes = rbytes + bytes([0]) + bytes([4])

        for part in recval.split('.'):
            rbytes += bytes([int(part)])
    return rbytes



def buildresponse(data):
    """
    Building the actual response
    """

    ##### HEADER #####

    # Transaction ID
    TransactionID = data[:2]

    # Get the flags
    Flags = getflags(data[2:4])

    # Question Count
    QDCOUNT = b'\x00\x01'

    # Records
    recs = getrecs(data[12:])

    # Answer Count
    ANCOUNT = len(recs[0]).to_bytes(2, byteorder='big')

    # Nameserver Count
    NSCOUNT = (0).to_bytes(2, byteorder='big')

    # Additonal Count
    ARCOUNT = (0).to_bytes(2, byteorder='big')

    dnsheader = TransactionID + Flags + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT
    ##### HEADER END #####

    ##### DNS QUESTION #####

    # Get answer for query
    records, rectype, domainname = recs

    dnsquestion = buildquestion(domainname, rectype)
    ##### DNS QUESTION END #####


    ##### BODY #####
    # Create DNS body
    dnsbody = b''
    for record in records:
        dnsbody += rectobytes(domainname, rectype, record["ttl"], record["value"])
    ##### BODY END #####


    print(f'Request came for the domain: {str(".".join(domainname))}')
    return dnsheader + dnsquestion + dnsbody

print('DNS is Ready.')
while True:
    data, addr = sock.recvfrom(512)
    response = buildresponse(data)
    sock.sendto(response, addr)
