#!/usr/bin/env python3

import os
import time

import dnslib
from colorama import init, Fore

# Inisialisasi colorama untuk mendukung Windows (akan bekerja di Shell/Windows)
init(autoreset=True)

# Warna menggunakan colorama
R = Fore.RED     # red
G = Fore.GREEN   # green
C = Fore.CYAN    # cyan
W = Fore.WHITE   # white
Y = Fore.YELLOW  # yellow

def dnsrec(domain, output, data):
    result = {}
    print('\n' + Y + '[!]' + Y + ' Memulai DNS Enumeration...' + W + '\n')
    types = ['A', 'AAAA', 'CAA', 'CNAME', 'MX', 'NS', 'TXT', 'PTR'] # Remove WWW, NS1, NS2, NS3 Because the library is not support that type
    full_ans = []
    for t in types:
        q = dnslib.DNSRecord.question(domain, t)
        pkt = q.send('8.8.8.8', 53, tcp='UDP')
        ans = str(dnslib.DNSRecord.parse(pkt)).split("\n")
        full_ans.extend(ans)
        # Add 5-second delay otherwise it trigger the dns ratelimit
        print(f"Berhasil mendapatkan query DNS untuk {t}")
        time.sleep(5)
    full_ans = set(full_ans)
    dns_found = []

    for entry in full_ans:
        if not entry.startswith(';'):
            dns_found.append(entry)
        else:
            pass
    
    if len(dns_found) != 0:
        for entry in dns_found:
            print(G + '[+]' + C + ' {}'.format(entry) + W)
            if output != 'None':
                result.setdefault('dns', []).append(entry)
    else:
        print(R + '[-]' + C + ' DNS Records Not Found!' + W)
        if output != 'None':
            result.setdefault('dns', ['DNS Records Not Found'])
    
    dmarc_target = '_dmarc.' + domain
    q = dnslib.DNSRecord.question(dmarc_target, 'TXT')
    pkt = q.send('8.8.8.8', 53, tcp='UDP')
    dmarc_ans = dnslib.DNSRecord.parse(pkt)
    dmarc_ans = str(dmarc_ans)
    dmarc_ans = dmarc_ans.split('\n')
    dmarc_found = []

    for entry in dmarc_ans:
        if entry.startswith('_dmarc') == True:
            dmarc_found.append(entry)
        else:
            pass
    if len(dmarc_found) != 0:
        for entry in dmarc_found:
            print(G + '[+]' + C + ' {}'.format(entry) + W)
            if output != 'None':
                result.setdefault('dmarc', []).append(entry)
    else:
        print('\n' + R + '[-]' + C + ' Rekam DMARC Tidak Ada!' + W)
        if output != 'None':
            result.setdefault('dmarc', ['Rekam DMARC Tidak Ada!'])

    if output != 'None':
        dns_export(output, data, result)

def dns_export(output, data, result):
    data['module-DNS Enumeration'] = result
