#!/usr/bin/python

from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeReq, Dot11ProbeResp, RadioTap
import sys
import signal
import os
import csv
import argparse
from datetime import datetime
import time
import importlib
import serial
import pytz
import pynmea2
import io
from threading import Thread

interface=""

found_APs = []

OUIMEM = {}
with open('OUI.txt', 'r', encoding="UTF-8") as OUILookup:
    for line in csv.reader(OUILookup, delimiter='\t'):
        if not line or line[0] == "#":
            continue
        else:
            OUIMEM[line[0]] = line[1:]

def rssi(radiodata):
    if 'dBm_AntSignal=' in radiodata:
        start = radiodata.find('dBm_AntSignal=')
        return str(radiodata[start+14:start+21]).replace(' ','').replace('A','')
    else:
        return '-255dBm'

def channel(radiodata):
    if 'Channel=' in radiodata:
        start = radiodata.find('Channel=')
        freq = int(radiodata[start+8:start+12])
        if freq == 2412:
            return 'C:01 ' + str(freq)
        if freq == 2417:
            return 'C:02 ' + str(freq)
        if freq == 2422:
            return 'C:03 ' + str(freq)
        if freq == 2427:
            return 'C:04 ' + str(freq)
        if freq == 2432:
            return 'C:05 ' + str(freq)
        if freq == 2437:
            return 'C:06 ' + str(freq)
        if freq == 2442:
            return 'C:07 ' + str(freq)
        if freq == 2447:
            return 'C:08 ' + str(freq)
        if freq == 2452:
            return 'C:09 ' + str(freq)
        if freq == 2457:
            return 'C:10 ' + str(freq)
        if freq == 2462:
            return 'C:11 ' + str(freq)
        if freq == 2467:
            return 'C:12 ' + str(freq)
        if freq == 2472:
            return 'C:13 ' + str(freq)
        if freq == 2484:
            return 'C:14 ' + str(freq)
        else:
            return '-->>' + str(freq)
                    
#Function to handle Crtl+C
def signal_handler(signal, frame):
    print('\n=================')
    print('Execution aborted')
    print('=================')
    os.system("kill -9 " + str(os.getpid()))
    sys.exit(1)

def signal_exit(signal, frame):
    print ("Signal exit")
    sys.exit(1)

def change_channel():
    ch = 1
    while True:
        os.system(f"iwconfig {interface} channel {ch}")
        # switch channel from 1 to 14 each 1s
        ch = ch % 14 + 1
        time.sleep(1)

def setup_monitor (iface):
    print("Putting interface "  + iface + " in monitor mode")
    os.system('ifconfig ' + iface + ' down')
    try:
        os.system('iwconfig ' + iface + ' mode monitor')
    except:
        print("Failed to setup monitor mode")
        sys.exit(1)
    os.system('ifconfig ' + iface + ' up')
    return iface

def check_root():
    if not os.geteuid() == 0:
        print("This script requires sudo privileges")
        exit(1)

def sniff_wifi_APs(packet):

    if packet.haslayer(Dot11Beacon):

        gps_lat = ""
        gps_lon = ""
        mac_address = packet[Dot11].addr2

        if mac_address not in found_APs:

            ssid = packet[Dot11Elt].info.decode()
            gps_coord = get_gps_coord()

            try:
                dbm_signal = packet.dBm_AntSignal
            except:
                dbm_signal = "N/A"

            stats = packet[Dot11Beacon].network_stats()
            channelz = stats.get("channel")
            crypto = stats.get("crypto")

            vendor = find_mac_vendor(mac_address)
            
            if gps_coord.latitude != 0.0 or gps_coord.longitude != 0.0:
                gps_lat = str(gps_coord.latitude)
                gps_lon = str(gps_coord.longitude)

            print("AP Mac: " + str(mac_address))
            print("SSID: " + ssid)
            print("Vendor: " + str(vendor))
            print("Channel: " + str(channelz))
            print("Crypto: " + str(crypto))
            print("Signal: " + str(dbm_signal) + "dBm")
            print("Longitude: " + str(gps_lon))
            print("Latitude: " + str(gps_lat))
            print("###################################################")
            print("")
            found_APs.append(mac_address)

def sniff_wifi_probes(packet):
    print("")

def sniff_bluetooth_data(packet):
    print("")

def find_mac_vendor(mac_addr):
    vendor=""
    clientOUI = mac_addr[:8]
    firstOctet = clientOUI[:2]
    scale = 16
    num_of_bits = 8

    #needs a valid mac address
    binaryRep = str(bin(int(firstOctet, scale))[2:].zfill(num_of_bits))
    if OUIMEM.get(clientOUI) is not None:
        identifiers = len(OUIMEM[clientOUI])
        if identifiers == 2:
            vendor=(str(OUIMEM[clientOUI][1]).replace(',', '').title())
        else:
            if identifiers == 1:
                vendor=(str(OUIMEM[clientOUI][0]).replace(',', '').title())
    else:
        if binaryRep[6:7] == '1':
            vendor=('Locally Assigned')
        else:
            vendor=('Unknown OUI')
    return vendor

def get_gps_coord():
    with serial.Serial('/dev/ttyUSB0', baudrate=4800, timeout=1) as ser:
        while True: 
            line = ser.readline().decode('ascii', errors='replace')
            if line.startswith("$GPGGA"):
                gpsval = pynmea2.parse(line)
                return gpsval

def sniffpackets(packet):
    
    if(True):
        sniff_wifi_APs(packet)
        #sniff_wifi_probes(packet)
        #sniff_bluetooth_data(packet)
    else:
        print("ok")

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    check_root()

    #TODO: check if db schemas exist

    parser = argparse.ArgumentParser()
    parser.add_argument('--interface', '-i', default='wlan1',
                help='monitor mode enabled interface')
    args = parser.parse_args()

    if not args.interface:
        print("You must specify an interface in monitor mode")

    interface = args.interface

    setup_monitor(interface)

    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()

    print("Sniffing on interface " + str(interface) + "...\n")
    sniff(iface=interface, prn=sniffpackets, store=0)





