#!/usr/bin/env python3

import socket
import aiohttp
import asyncio
from colorama import init, Fore

# Inisialisasi colorama untuk mendukung Windows
init(autoreset=True)

# Warna menggunakan colorama
R = Fore.RED     # red
G = Fore.GREEN   # green
C = Fore.CYAN    # cyan
W = Fore.WHITE   # white
Y = Fore.YELLOW  # yellow

header = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0'}
count = 0

async def fetch(url, session, redir, sslv):
    global count
    try:
        async with session.get(url, headers=header, allow_redirects=redir) as response:
            count += 1
            print(Y + '[!]' + C + ' Permintaan : ' + W + str(count), end='\r')
            return response.url, response.status
    except Exception as e:
        print(R + '[-]' + C + ' Exception : ' + W + str(e).strip('\n'))

async def run(target, threads, tout, wdlist, redir, sslv, dserv, output, data):
    tasks = []
    url = target + '/{}'
    resolver = aiohttp.AsyncResolver(nameservers=[dserv])
    conn = aiohttp.TCPConnector(limit=threads, resolver=resolver, family=socket.AF_INET, verify_ssl=sslv)
    timeout = aiohttp.ClientTimeout(total=None, sock_connect=tout, sock_read=tout)
    async with aiohttp.ClientSession(connector=conn, timeout=timeout) as session:
        with open(wdlist) as wordlist:
            for word in wordlist:
                word = word.strip()
                task = asyncio.create_task(fetch(url.format(word), session, redir, sslv))
                tasks.append(task)
        responses = await asyncio.gather(*tasks)
        dir_output(responses, output, data)

def dir_output(responses, output, data):
    found = []
    skipped = []
    result = {}

    for entry in responses:
        if entry != None:
            if entry[1] in {200}:
                print(G + '[+]' + G + ' {}'.format(str(entry[1]) + C + ' | ' + W + '{}'.format(entry[0])))
                found.append(entry[0])
                if output != 'None':
                    result.setdefault('Status 200', []).append(entry[0])
            elif entry[1] in {301, 302, 303, 307, 308}:
                print(G + '[+]' + Y + ' {}'.format(str(entry[1]) + C + ' | ' + W + '{}'.format(entry[0])))
                found.append(entry[0])
                if output != 'None':
                    result.setdefault('Status {}'.format(str(entry[1])), []).append(entry[0])
            elif entry[1] in {403}:
                print(G + '[+]' + R + ' {}'.format(str(entry[1]) + C + ' | ' + W + '{}'.format(entry[0])))
                found.append(entry[0])
                if output != 'None':
                    result.setdefault('Status 403', []).append(entry[0])
            else:
                skipped.append(entry[0])

    print('\n' + G + '[+]' + C + ' Lokasi Ditemukan   : ' + W + str(len(found)))
    print(G + '[+]' + C + ' Lokasi Dilewati : ' + W + str(len(skipped)))
    print(G + '[+]' + C + ' Jumlah Permintaan      : ' + W + str(len(found) + len(skipped)))

    if output != 'None':
        result['Lokasi Ditemukan'] = str(len(found))
        result['Lokasi Dilewati'] = str(len(skipped))
        result['Jumlah Permintaan'] = str(len(found) + len(skipped))
        data['module-Directory Search'] = result

def hammer(target, threads, tout, wdlist, redir, sslv, dserv, output, data):
    print('\n' + Y + '[!]' + Y + ' Memulai Mencari Lokasi ...' + W + '\n')
    print(G + '[+]' + C + ' Threads          : ' + W + str(threads))
    print(G + '[+]' + C + ' Waktu Habis      : ' + W + str(tout))
    print(G + '[+]' + C + ' Daftar Kata      : ' + W + wdlist)
    print(G + '[+]' + C + ' Izin Pengalihan  : ' + W + str(redir))
    print(G + '[+]' + C + ' SSL Verifikasi : ' + W + str(sslv))
    print(G + '[+]' + C + ' DNS Server      : ' + W + dserv + '\n')
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    loop = asyncio.new_event_loop()
    loop.run_until_complete(run(target, threads, tout, wdlist, redir, sslv, dserv, output, data))
    loop.close()
