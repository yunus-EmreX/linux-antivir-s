#!/usr/bin/env python3

import os
import sys
import hashlib
import argparse
import requests
from datetime import datetime

# Örnek bir kötü amaçlı yazılım imza veritabanı
MALWARE_SIGNATURES = {
    'eicar': '44d88612fea8a8f36de82e1278abb02f',  # EICAR test dosyası imzası
}

QUARANTINE_DIR = 'quarantine'
CLAMAV_DB_DIR = '/var/lib/clamav'

def banner():
    print("""
    ******************************************
    *        yunuX Antivirüs Yazılımı   *
    ******************************************
    """)

def hash_file(file_path):
    """Bir dosyanın md5 hash'ini hesaplar"""
    hasher = hashlib.md5()
    with open(file_path, 'rb') as f:
        buf = f.read()
        hasher.update(buf)
    return hasher.hexdigest()

def update_signatures():
    """ClamAV imza veritabanını günceller"""
    try:
        print('[+] ClamAV imza veritabanı güncelleniyor...')
        os.system('sudo freshclam')
        print('[+] İmza veritabanı başarıyla güncellendi.')
    except Exception as e:
        print(f'[!] İmza veritabanı güncellemesi sırasında hata oluştu: {e}')

def quarantine_file(file_path):
    """Şüpheli dosyayı karantinaya alır"""
    if not os.path.exists(QUARANTINE_DIR):
        os.makedirs(QUARANTINE_DIR)
    file_name = os.path.basename(file_path)
    quarantine_path = os.path.join(QUARANTINE_DIR, file_name)
    os.rename(file_path, quarantine_path)
    print(f'[!] Dosya karantinaya alındı: {quarantine_path}')

def scan_file_with_clamav(file_path):
    """Dosyayı ClamAV ile tarar"""
    try:
        print(f'[+] ClamAV ile dosya taranıyor: {file_path}')
        result = os.system(f'clamscan --database={CLAMAV_DB_DIR} {file_path}')
        if result == 0:
            print(f'[+] Temiz (ClamAV): {file_path}')
        else:
            print(f'[!] ClamAV tehdidi bulundu: {file_path}')
            quarantine_file(file_path)
    except Exception as e:
        print(f'[!] ClamAV taraması sırasında hata oluştu: {e}')

def scan_file(file_path, use_clamav=False):
    """Belirtilen dosyayı tarar"""
    try:
        if use_clamav:
            scan_file_with_clamav(file_path)
        else:
            file_hash = hash_file(file_path)
            found = False
            for name, sig in MALWARE_SIGNATURES.items():
                if file_hash == sig:
                    print(f'[!] Tehdit Bulundu: {file_path} ({name})')
                    quarantine_file(file_path)
                    found = True
                    break
            if not found:
                print(f'[+] Temiz: {file_path}')
    except Exception as e:
        print(f'[!] Dosya taranırken hata oluştu: {e}')

def scan_directory(directory_path, use_clamav=False):
    """Belirtilen dizini tarar"""
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            scan_file(file_path, use_clamav)

def scan_multiple_files(file_paths, use_clamav=False):
    """Birden fazla dosyayı tarar"""
    for file_path in file_paths:
        scan_file(file_path, use_clamav)

def scan_entire_disk(use_clamav=False):
    """Tüm diski tarar"""
    root_directory = '/'
    scan_directory(root_directory, use_clamav)

def log_scan_results(scan_type, items_scanned, threats_found):
    """Tarama sonuçlarını loglar"""
    with open('scan_log.txt', 'a') as log_file:
        log_file.write(f'[{datetime.now()}] Tarama Tipi: {scan_type}, Taranan Öğeler: {items_scanned}, Bulunan Tehditler: {threats_found}\n')

def main():
    parser = argparse.ArgumentParser(description='Gelişmiş Antivirüs Yazılımı')
    parser.add_argument('-f', '--file', help='Belirli bir dosyayı tara')
    parser.add_argument('-d', '--directory', help='Belirli bir dizini tara')
    parser.add_argument('-a', '--all', action='store_true', help='Tüm diski tara')
    parser.add_argument('-m', '--multiple', nargs='+', help='Birden fazla dosyayı tara')
    parser.add_argument('-u', '--update', action='store_true', help='İmza veritabanını güncelle')
    parser.add_argument('-c', '--clamav', action='store_true', help='ClamAV ile tarama yap')
    args = parser.parse_args()

    banner()

    if args.update:
        update_signatures()
    elif args.file:
        if os.path.isfile(args.file):
            scan_file(args.file, args.clamav)
        else:
            print(f'[!] Dosya bulunamadı: {args.file}')
    elif args.directory:
        if os.path.isdir(args.directory):
            scan_directory(args.directory, args.clamav)
        else:
            print(f'[!] Dizin bulunamadı: {args.directory}')
    elif args.all:
        scan_entire_disk(args.clamav)
    elif args.multiple:
        scan_multiple_files(args.multiple, args.clamav)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
