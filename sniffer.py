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
import sqlite3
from bluetoothctl import Bluetoothctl
from threading import Thread

interface=""

found_APs = []
gps_lat = ""
gps_lon = ""
OUIMEM = {}
with open('OUI.txt', 'r', encoding="UTF-8") as OUILookup:
    for line in csv.reader(OUILookup, delimiter='\t'):
        if not line or line[0] == "#":
            continue
        else:
            OUIMEM[line[0]] = line[1:]

def get_channel(freq):
    
    if freq == 2412:
        return '01'
    if freq == 2417:
        return '02'
    if freq == 2422:
        return '03'
    if freq == 2427:
        return '04'
    if freq == 2432:
        return '05'
    if freq == 2437:
        return '06'
    if freq == 2442:
        return '07'
    if freq == 2447:
        return '08'
    if freq == 2452:
        return '09'
    if freq == 2457:
        return '10'
    if freq == 2462:
        return '11'
    if freq == 2467:
        return '12'
    if freq == 2472:
        return '13'
    if freq == 2484:
        return '14'
    else:
        return ''
                    
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

#you need to check every channel (1-13)
def sniff_wifi_APs(packet):

    if packet.haslayer(Dot11Beacon):

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
            tmpvar1 = packet.getlayer(RadioTap).time
            time_stamp = datetime.fromtimestamp(tmpvar1).strftime("%Y-%m-%d %H:%M:%S")

            if gps_coord.latitude != 0.0 or gps_coord.longitude != 0.0:
                global gps_lat
                gps_lat = str(gps_coord.latitude)
                global gps_lon
                gps_lon = str(gps_coord.longitude)

            print("AP Mac: " + str(mac_address))
            print("SSID: " + ssid)
            print("Vendor: " + str(vendor))
            print("Channel: " + str(channelz))
            print("Crypto: " + str(crypto))
            print("Signal: " + str(dbm_signal) + "dBm")
            print("Longitude: " + str(gps_lon))
            print("Latitude: " + str(gps_lat))
            print("Timestamp: " + str(time_stamp))
            print("###################################################")
            print("")
            found_APs.append(mac_address)

def sniff_wifi_probes(packet):
    con = sqlite3.connect('osint.db')

    cur = con.cursor()
    try:
        if packet.haslayer(Dot11ProbeReq):
            if packet.type == 0 and packet.subtype == 4:#subtype used to be 8 (APs) but is now 4 (Probe Requests)

                mac = str(packet.addr2)
                ssid = str(packet.info.decode("utf-8"))
                timestamp = packet.getlayer(RadioTap).time
                dt = str(datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S"))
                rssi = str(packet[RadioTap].dBm_AntSignal)
                vendor = find_mac_vendor(mac)

                #chanfreq is currently the channel the wifi card is on from this device and not the signal's chanfreq
                chanfreq = get_channel(packet[RadioTap].ChannelFrequency)

                if not (ssid == ""):
                    #cur.execute("insert into wifi (date_added, mac, mac_vendor, ssid, signal, gps_coordinates, location) values (?, ?, ?, ?, ?, ?, ?)", (dt, mac, vendor, ssid, rssi, "", "home"))
                    #con.commit()
                    print("==========================================WIFI PROBE==========================")
                    print("%s | Device MAC: %s | Vendor: %s | SSID: %s | %s dBm | Frequency: %s | Latitude: %s | Longitude: %s" % (dt, mac, vendor, ssid, rssi, chanfreq, gps_lat, gps_lon))
                    print("==============================================================================")

    except UnicodeDecodeError as unicode_decode_err:
            # The ESSID is not a valid UTF-8 string.
            #raise TypeError from unicode_decode_err
        pass

def sniff_bluetooth_data(packet):

    #fix having to open a diff db instance. Can cause locks
    con = sqlite3.connect('osint.db')
    cur = con.cursor()

    #this should be on a seperate thread because it scans for 5 or 10 seconds for devices
    while True:
        database_column_list = ['Name','Alias','UUID','RSSI']
        bt = Bluetoothctl()
        bt.start_scan()
        #give 5 seconds to scan
        for i in range(1, 6):
            time.sleep(1)

        kev = []
        available_devices = bt.get_available_devices()

        for device in available_devices:
            mac_address = device['mac_address']

            #get info from bluetoothctl
            device_info = bt.get_device_info(mac_address)

            #filteredDevices = []
            #filteredDevices.append({"mac_address" : mac_address})
            uuidCounter = 0
            #loop through all properties of device
            tmp = {}
            tmp.update({"mac_address" : mac_address})
            for s in range(len(device_info)): 
                #split device name and value
                info = device_info[s].strip().split(":")
                try:
                    name = info[0].strip()
                    value = info[1].strip()
                except:
                    value = "NONE"
                if(name == "UUID"):
                    uuidCounter = uuidCounter + 1
                if(uuidCounter > 1):
                    continue
                if(name in database_column_list):
                    tmp.update({name : value})
            kev.append(tmp)


        for d in kev:
            
            name = ""
            rssi = "0"
            alias = ""
            uuid = ""
            gps_coordinates = ""
            location = "home"
            date_added = str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

            if(d.__contains__("Name")):
                name = d['Name']
            if(d.__contains__("Alias")):
                alias = d['Alias']
            if(d.__contains__("UUID")):
                uuid = d['UUID'].split("(")[0].strip()
            if(d.__contains__("RSSI")):
                rssi = d['RSSI'].strip()

            if name == "" :
                name = alias
            
            #do we need this?
            if rssi == "" :
                rssi = "0"

            mac_address = d['mac_address']

            #cur.execute("insert into bluetooth (name, mac_address, alias, uuid, rssi, date_added, gps_coordinates, location) values (?, ?, ?, ?, ?, ?, ?, ?)", (name, mac_address, alias, uuid, rssi, date_added, gps_coordinates, location))
            #con.commit()
            print("==============Bluetooth device====================")
            print("Timestamp: " + date_added)
            print("Name: " + str(name))
            print("RSSI: " + str(rssi))
            print("Alias: " + str(alias))
            print("UUID: " + uuid)
            print("MAC: " + mac_address)
            print("Longitude: " + gps_lon)
            print("Latitude: " + gps_lat)

        time.sleep(10)

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
            vendor=('Unknown')
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

        bt = Thread(target=sniff_bluetooth_data, args=(packet))
        bt.daemon = True
        bt.start()

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
    
    #probe scanner had monitor
    #sniff(iface=interface, prn=sniffPackets, store=0, monitor=True)
    while 1:
        time.sleep(1)





