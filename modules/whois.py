#!/usr/bin/env python3

import ipwhois
from colorama import init, Fore

# Inisialisasi colorama untuk mendukung terminal Windows
init(autoreset=True)

# Warna untuk terminal menggunakan colorama
R = Fore.RED      # Merah
G = Fore.GREEN    # Hijau
C = Fore.CYAN     # Cyan
W = Fore.WHITE    # Putih
Y = Fore.YELLOW   # Kuning

def whois_lookup(ip, output, data):
    collect = {}
    print('\n' + Y + '[!]' + Y + ' Whois Pencarian : ' + W + '\n')
    try:
        lookup = ipwhois.IPWhois(ip)
        results = lookup.lookup_whois()

        for k, v in results.items():
            if v is not None:
                if isinstance(v, list):
                    for item in v:
                        for k, v in item.items():
                            if v is not None:
                                print(G + '[+]' + C + ' {} : '.format(str(k)) + W + str(v).replace(',', ' ').replace('\r', ' ').replace('\n', ' '))
                                if output != 'None':
                                    collect.update({str(k): str(v).replace(',', ' ').replace('\r', ' ').replace('\n', ' ')})
                            else:
                                pass
                else:
                    print(G + '[+]' + C + ' {} : '.format(str(k)) + W + str(v).replace(',', ' ').replace('\r', ' ').replace('\n', ' '))
                    if output != 'None':
                        collect.update({str(k): str(v).replace(',', ' ').replace('\r', ' ').replace('\n', ' ')})
            else:
                pass

    except Exception as e:
        print(R + '[-] Kesalahan : ' + C + str(e) + W)
        if output != 'None':
            collect.update({'Kesalahan': str(e)})
        pass

    if output != 'None':
        whois_output(output, data, collect)

def whois_output(output, data, collect):
    data['module-Whois Lookup'] = collect
