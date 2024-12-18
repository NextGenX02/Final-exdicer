#!/usr/bin/env python3

import requests
from colorama import init, Fore

# Inisialisasi colorama untuk menangani kompatibilitas Windows
init(autoreset=True)

# Warna untuk Shell (Unix/Linux/Mac) dan Windows
R = Fore.RED     # Merah
G = Fore.GREEN   # Hijau
C = Fore.CYAN    # Cyan
W = Fore.WHITE   # Putih
Y = Fore.YELLOW  # Kuning

def headers(target, output, data):
    result = {}
    print ('\n' + G + '[+]' + Y + ' Judul :' + W + '\n')
    try:
        rqst = requests.get(target, verify=False, timeout=10)
        for k, v in rqst.headers.items():
            print (G + '[+]' + C + ' {} : '.format(k) + W + v)
            if output != 'None':
                result.update({k: v})
    except Exception as e:
        print('\n' + R + '[-]' + C + ' Exception : ' + W + str(e) + '\n')        
        if output != 'None':
            result.update({'Exception': str(e)})

    if output != 'None':
        header_output(output, data, result)

def header_output(output, data, result):
    data['module-Headers'] = result
