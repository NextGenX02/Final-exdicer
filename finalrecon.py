import os
import sys
import atexit
import importlib.util
import platform
import subprocess
from urllib.parse import urlparse
import tldextract

# Cek jika sedang di Windows, lalu impor colorama
if platform.system() == 'Windows':
    from colorama import init, Fore
    init(autoreset=True)  # Inisialisasi colorama untuk otomatis reset warna setelah setiap print
    R = Fore.RED    # merah
    G = Fore.GREEN  # hijau
    C = Fore.CYAN   # cyan
    W = Fore.RESET  # reset warna
else:
    R = '\033[31m'  # merah untuk terminal berbasis Unix
    G = '\033[32m'  # hijau
    C = '\033[36m'  # cyan
    W = '\033[0m'   # reset warna untuk terminal berbasis Unix

fail = False

# Cek apakah sistem operasi adalah Unix atau Windows
# Fungsi pengecekan root
def is_root():
    if platform.system() == 'Windows':
        # Pada Windows, periksa apakah program dijalankan sebagai Administrator
        try:
            subprocess.check_call('net session', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except subprocess.CalledProcessError:
            return False
    else:
        # Untuk Linux/macOS/Termux, gunakan os.geteuid()
        return os.geteuid() == 0

if not is_root():
    print('\n' + R + '[-]' + C + ' Mohon Dijalankan sebagai Sistem Akar!' + W + '\n')
    sys.exit()

with open('requirements.txt', 'r') as rqr:
    pkg_list = rqr.read().strip().split('\n')

print('\n' + G + '[+]' + C + ' Memeriksa Cantolan...' + W + '\n')

for pkg in pkg_list:
    spec = importlib.util.find_spec(pkg)
    if spec is None:
        print(R + '[-]' + W + ' {}'.format(pkg) + C + ' belum diinstall!' + W)
        fail = True
    else:
        pass

if fail:
    print('\n' + R + '[-]' + C + ' Mohon Eksekusi Perintah > ' + W + 'pip3 install -r requirements.txt' + C + ' untuk Menginstal Paket yang Hilang' + W + '\n')
    sys.exit()

import argparse

# Parsing dan pengaturan argumen
version = '2.2.4'
parser = argparse.ArgumentParser(description='FinalRecon - OSINT Tool for All-In-One Web Recon | v{}'.format(version))
parser.add_argument('url', help='URL Target')
parser.add_argument('--headers', help='Informasi Judul', action='store_true')
parser.add_argument('--sslinfo', help='Informasi SSL Sertifikat', action='store_true')
parser.add_argument('--whois', help='Whois Pencarian', action='store_true')
parser.add_argument('--crawl', help='Merobek Target', action='store_true')
parser.add_argument('--dns', help='DNS Enumeration', action='store_true')
parser.add_argument('--sub', help='Sub-Domain Enumeration', action='store_true')
parser.add_argument('--trace', help='Traceroute', action='store_true')
parser.add_argument('--dir', help='Lokasi Pencarian', action='store_true')
parser.add_argument('--ps', help='Pindai Jalur Cepat', action='store_true')
parser.add_argument('--full', help='Recon Penuh', action='store_true')

# Opsi Ekstra
ext_help = parser.add_argument_group('Extra Options')
ext_help.add_argument('-t', type=int, help='Nomor dari Thread [ Bawaan : 50 ]')
ext_help.add_argument('-T', type=float, help='Permintaan Waktu Habis [ Bawaan : 10.0 ]')
ext_help.add_argument('-w', help='Path ke Daftar Kata [ Bawaan : wordlists/dirb_common.txt ]')
ext_help.add_argument('-r', action='store_true', help='Izin Pengalihan [ Bawaan : False ]')
ext_help.add_argument('-s', action='store_false', help='Beralih ke Verifikasi SSL [ Bawaan : True ]')
ext_help.add_argument('-d', help='Custom DNS Servers [ Bawaan : 1.1.1.1 ]')
ext_help.add_argument('-m', help='Traceroute Mode [ Bawaan : UDP ] [ Tersedia : TCP, ICMP ]')
ext_help.add_argument('-p', type=int, help='Jalur untuk Traceroute [ Bawaan : 80 / 33434 ]')
ext_help.add_argument('-tt', type=float, help='Waktu Habis Traceroute [ Bawaan : 1.0 ]')
ext_help.add_argument('-o', help='Ekspor Keluaran [ Bawaan : txt ] [ Bawaan : xml, csv ]')
ext_help.set_defaults(
    t=50,
    T=10.0,
    w='wordlists/dirb_common.txt',
    r=False,
    s=True,
    d='1.1.1.1',
    m='UDP',
    p=33434,
    tt=1.0,
    o='txt')

args = parser.parse_args()
target = args.url
headinfo = args.headers
sslinfo = args.sslinfo
whois = args.whois
crawl = args.crawl
dns = args.dns
trace = args.trace
dirrec = args.dir
pscan = args.ps
full = args.full
threads = args.t
tout = args.T
wdlist = args.w
redir = args.r
sslv = args.s
dserv = args.d
subd = args.sub
mode = args.m 
port = args.p
tr_tout = args.tt
output = args.o

import socket
import requests
import datetime
import ipaddress
import tldextract
import os
import sys
import platform
import subprocess

# Variabel global
type_ip = False
data = {}
meta = {}

# Fungsi pengecekan root
def is_root():
    if platform.system() == 'Windows':
        # Pada Windows, periksa apakah program dijalankan sebagai Administrator
        try:
            subprocess.check_call('net session', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except subprocess.CalledProcessError:
            return False
    else:
        # Untuk Linux/macOS/Termux, gunakan geteuid
        return os.geteuid() == 0

# Banner dan informasi
def banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    banner = r''' 
 ______ __ __ __ ______ __ 
/\ ___\/\ \ /\ "-.\ \ /\ __ \ /\ \ \ 
\ \ __\\ \ \\ \ \-. \\ \ __ \\ \ \____ 
 \_\ \_\ \_\\"\_\\ \_\ \_\\ \_____\\ 
 ______ ______ ______ ______ __ __ 
/\ == \ /\ ___\ /\ ___\ /\ __ \ /\ "-.\ \ 
\ \ __< \ \ __\ \ \ __\ \ \ \____\ \ \/\ \\ 
 \ \_\ \_\\ \_\\ \_\ \_\ \_\\ \_____\\ \_____\\ 
 \/_/ /_/ \/_____/ \/_____/ \/_____/ \/_/ \/_/ 
'''
    print(G + banner + W + '\n')
    print(G + '[>]' + C + ' Dibuat oleh : ' + W + 'thewhiteh4t')
    print(G + '[>]' + C + ' Diedit oleh : ' + G + 'Dicer-TDP')
    print(G + '[>]' + G + ' Modify by : ' + G + 'Dicer-TDP')
    print(G + '[>]' + C + ' Versi : ' + W + version + '\n')
    print(G + '[>]' + R + ' NB: ' + R + ' Perombakan total untuk Dukungan 2 Platform ')
    print(G + '[>]' + R + ' ' + R + ' Dukungan untuk semua fungsi dan modul ')
    print(G + '[>]' + R + ' ' + R + ' Perbaikan beberapa fitur yang sudah rusak ')
    print(G + '[>]' + R + ' ' + R + ' Perbaikan pada sistem pemilihan hak administrator ' + W + '\n')

if __name__ == "__main__":
    banner()

# Tambahkan folder "modules" ke jalur pencarian jika diperlukan
modules_path = os.path.join(os.getcwd(), 'modules')
if modules_path not in sys.path:
    sys.path.append(modules_path)

# Mengekstrak hostname
def extract_hostname(url):
    try:
        result = urlparse(url)
        if not all([result.scheme, result.netloc]):
            raise ValueError
        ext = tldextract.extract(url)
        hostname = f"{ext.subdomain}.{ext.domain}.{ext.suffix}" if ext.subdomain else f"{ext.domain}.{ext.suffix}"
        return hostname, ext
    except ValueError:
        print("URL tidak valid!")
        return None, None

if not target:
    print(R + '[-]' + C + ' Kesalahan: URL tidak boleh kosong!' + W + '\n')
    sys.exit()
# Mengecek versi terbaru
#def ver_check():
#    print(G + '[+]' + C + ' Memeriksa Pembaharuan...', end='')
#    ver_url = 'https://raw.githubusercontent.com/thewhiteh4t/finalrecon/master/version.txt'
#    try:
#        ver_rqst = requests.get(ver_url, timeout=5)
#        ver_sc = ver_rqst.status_code
#        if ver_sc == 200:
#            github_ver = ver_rqst.text.strip()
#            if version == github_ver:
#                print(C + '[' + G + ' Ter-Ba-Ru ' + C +']' + '\n')
#            else:
#                print(C + '[' + G + ' Tersedia : {} '.format(github_ver) + C + ']' + '\n')
#        else:
#            print(C + '[' + R + ' Status : {} '.format(ver_sc) + C + ']' + '\n')
#    except Exception as e:
#        print('\n\n' + R + '[-]' + C + ' Exception : ' + W + str(e))
#        sys.exit()

# Full Recon - Panggil berbagai modul
def full_recon():
    from modules.sslinfo import cert
    from modules.crawler import crawler
    from modules.headers import headers
    from modules.dns import dnsrec
    from modules.traceroute import troute
    from modules.whois import whois_lookup
    from modules.dirrec import hammer
    from modules.portscan import ps
    from modules.subdom import subdomains

    headers(target, output, data)
    cert(hostname, output, data)
    whois_lookup(ip, output, data)
    dnsrec(domain, output, data)
    if type_ip == False:
        subdomains(domain, tout, output, data)
    else:
        pass
    troute(ip, mode, port, tr_tout, output, data)
    ps(ip, output, data)
    crawler(target, output, data)
    hammer(target, threads, tout, wdlist, redir, sslv, dserv, output, data)

# Cek apakah kita memiliki hak akses root
if not is_root():
    print(R + '[-]' + C + ' Mohon Dijalankan sebagai Sistem Akar!' + '\n')
    sys.exit()

version = '2.2.4'

# Pengecekan input target URL
# Tambahkan http:// jika URL tidak memiliki awalan
if not target.startswith(('http://', 'https://')):
    print(C + '[*]' + W + ' URL tidak memiliki awalan. Menambahkan http:// secara otomatis.' + G)
    target = 'http://' + target

# Jika URL memiliki tanda "/" di akhir, hapus tanda tersebut
if target.endswith('/'):
    target = target[:-1]

hostname, ext = extract_hostname(target)
if hostname:
    print(G + '[+]' + C + ' Target : ' + W + target + R)
    print(G + '[+]' + C + f' Hostname: {hostname}')

# Fungsi utama program (hanya placeholder)
def main():
    print(G + "[+]" + C + " Program berjalan dengan target: " + W + target)

# Periksa apakah modul export tersedia
try:
    import importlib.util
    spec = importlib.util.spec_from_file_location("export", "modules/export.py")
    export_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(export_module)
    from export_module import export
except (ModuleNotFoundError, ImportError, FileNotFoundError):
    print(R + '[-]' + C + ' Modul "modules.export" tidak ditemukan. Pastikan folder "modules" dan file "export.py" ada.' + W)
    sys.exit()

if __name__ == "__main__":
    main()

try:
    ipaddress.ip_address(hostname)
    type_ip = True
    ip = hostname
except ValueError:
    try:
        ip = socket.gethostbyname(hostname)
        print ('\n' + G + '[+]' + C + ' Alamat IP : ' + W + str(ip))
    except Exception as e:
        print ('\n' + R + '[+]' + C + ' Gagal meminta IP : ' + W + str(e))
        if '[Errno -2]' in str(e):
            sys.exit()
        else:
            pass

# Menyimpan metadata
start_time = datetime.datetime.now()
meta.update({'Versi': str(version)})
meta.update({'Waktu': str(datetime.date.today())})
meta.update({'Target': str(target)})
meta.update({'Alamat IP': str(ip)})
meta.update({'Waktu Mulai': str(start_time.strftime('%I:%M:%S %p'))})
data['module-FinalRecon'] = meta

# Menyimpan hasil output jika diperlukan
if output != 'None':
    fname = os.getcwd() + '/dumps/' + hostname + '.' + output
    output = {
        'format': output,
        'file': fname,
        'export': False
    }

from modules.export import export

# Menjalankan berbagai modul sesuai opsi yang diberikan
if full == True:
    full_recon()

if headinfo == True:
    from modules.headers import headers
    headers(target, output, data)

if sslinfo == True:
    from modules.sslinfo import cert
    cert(hostname, output, data)

if whois == True:
    from modules.whois import whois_lookup
    whois_lookup(ip, output, data)

if crawl == True:
    from modules.crawler import crawler
    crawler(target, output, data)

if dns == True:
    from modules.dns import dnsrec
    dnsrec(domain, output, data)

if subd == True and type_ip == False:
    from modules.subdom import subdomains
    subdomains(domain, tout, output, data)
elif subd == True and type_ip == True:
    print(R + '[-]' + C + ' Sub-Domain Enumeration tidak mendukung pada Alamat IP' + W + '\n')
    sys.exit()
else:
    pass

if trace == True:
    from modules.traceroute import troute
    if mode == 'TCP' and port == 33434:
        port = 80
        troute(ip, mode, port, tr_tout, output, data)
    else:
        troute(ip, mode, port, tr_tout, output, data)

if pscan == True:
    from modules.portscan import ps
    ps(ip, output, data)

if dirrec == True:
    from modules.dirrec import hammer
    hammer(target, threads, tout, wdlist, redir, sslv, dserv, output, data)

# Memastikan bahwa setidaknya satu modul dijalankan
if any([full, headinfo, sslinfo, whois, crawl, dns, subd, trace, pscan, dirrec]) != True:
    print ('\n' + R + '[-] Kesalahan : ' + C + 'Setidaknya Satu Argumen URL Diperlukan' + W)
    output = 'None'
    sys.exit()

# Waktu eksekusi
end_time = datetime.datetime.now() - start_time
print ('\n' + G + '[+]' + C + ' Selesai dalam waktu: ' + W + str(end_time) + '\n')

# Menyimpan hasil ekspor
@atexit.register
def call_export():
    meta.update({'Waktu Akhir': str(datetime.datetime.now().strftime('%I:%M:%S %p'))})
    meta.update({'Waktu Penyelesaian': str(end_time)})
    if output != 'None':
        output['export'] = True
        export(output, data)

sys.exit()

try:
    banner()
    ver_check()

    if not target.startswith(('http', 'https')):
        print(R + '[-]' + C + ' Perintah Gagal, Kecuali ' + W + 'http://' + C + ' or ' + W + 'https://' + '\n')
        sys.exit()

    if target.endswith('/'):
        target = target[:-1]

    print(G + '[+]' + C + ' Target : ' + W + target)
    ext = tldextract.extract(target)
    domain = ext.registered_domain
    hostname = '.'.join(part for part in ext if part)

    try:
        ipaddress.ip_address(hostname)
        type_ip = True
        ip = hostname
    except ValueError:
        try:
            ip = socket.gethostbyname(hostname)
            print('\n' + G + '[+]' + C + ' Alamat IP : ' + W + str(ip))
        except Exception as e:
            print('\n' + R + '[+]' + C + ' Gagal meminta IP : ' + W + str(e))
            if '[Errno -2]' in str(e):
                sys.exit()

    start_time = datetime.datetime.now()

    meta.update({'Versi': str(version)})
    meta.update({'Waktu': str(datetime.date.today())})
    meta.update({'Target': str(target)})
    meta.update({'Alamat IP': str(ip)})
    meta.update({'Waktu Mulai': str(start_time.strftime('%I:%M:%S %p'))})
    data['module-FinalRecon'] = meta

    if output != 'None':
        fname = os.path.join(os.getcwd(), 'dumps', f'{hostname}.{output}')
        output = {'format': output, 'file': fname, 'export': False}

    from modules.export import export

    if full:
        full_recon()

    if headinfo:
        from modules.headers import headers
        headers(target, output, data)

    if sslinfo:
        from modules.sslinfo import cert
        cert(hostname, output, data)

    if whois:
        from modules.whois import whois_lookup
        whois_lookup(ip, output, data)

    if crawl:
        from modules.crawler import crawler
        crawler(target, output, data)

    if dns:
        from modules.dns import dnsrec
        dnsrec(domain, output, data)

    if subd and not type_ip:
        from modules.subdom import subdomains
        subdomains(domain, tout, output, data)
    elif subd and type_ip:
        print(R + '[-]' + C + ' Sub-Domain Enumeration tidak mendukung pada Alamat IP' + W + '\n')
        sys.exit()

    if trace:
        from modules.traceroute import troute
        if mode == 'TCP' and port == 33434:
            port = 80
        troute(ip, mode, port, tr_tout, output, data)

    if pscan:
        from modules.portscan import ps
        ps(ip, output, data)

    if dirrec:
        from modules.dirrec import hammer
        hammer(target, threads, tout, wdlist, redir, sslv, dserv, output, data)

    if not any([full, headinfo, sslinfo, whois, crawl, dns, subd, trace, pscan, dirrec]):
        print('\n' + R + '[-] Kesalahan : ' + C + 'Setidaknya Satu Argumen URL Diperlukan' + W)
        output = 'None'
        sys.exit()

    end_time = datetime.datetime.now() - start_time
    print('\n' + G + '[+]' + C + ' Selesaikan Mulai ' + W + str(end_time) + '\n')

    @atexit.register
    def call_export():
        meta.update({'Waktu Akhir': str(datetime.datetime.now().strftime('%I:%M:%S %p'))})
        meta.update({'Waktu Penyelesaian': str(end_time)})
        if output != 'None':
            output['export'] = True
            export(output, data)

    sys.exit()

except KeyboardInterrupt:
    print(R + '[-]' + C + ' Keyboard Memutuskan.' + W + '\n')
    sys.exit()

except KeyboardInterrupt:
    print(R + '[-]' + C + ' Keyboard Memutuskan.' + W + '\n')
    sys.exit()
