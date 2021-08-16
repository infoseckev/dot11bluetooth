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
from contextlib import closing
interface= ""
location= ""
found_APs = []
gps_lat = ""
gps_lon = ""
show_output = True
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

def get_gps_coord():
    with serial.Serial('/dev/ttyUSB0', baudrate=4800, timeout=1) as ser:
        while True: 
            line = ser.readline().decode('ascii', errors='replace')
            if line.startswith("$GPGGA"):
                gpsval = pynmea2.parse(line)
                return gpsval

def set_gps_coordinates():
    while True:
        gps_coord = get_gps_coord()
        #TODO: fix gps logic. put in its own function only executed each 1 second. maybe diff
        if gps_coord.latitude != 0.0 or gps_coord.longitude != 0.0:
            global gps_lat
            gps_lat = str(gps_coord.latitude)
            global gps_lon
            gps_lon = str(gps_coord.longitude)
        time.sleep(60)

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

#you need to check every channel (1-13)
def sniff_wifi_APs(packet):

    if packet.haslayer(Dot11Beacon):

        mac_address = packet[Dot11].addr2

        if mac_address not in found_APs:

            ssid = packet[Dot11Elt].info.decode()
            
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

            if(show_output):
                print("###################################################")
                print("AP Mac: " + str(mac_address))
                print("SSID: " + ssid)
                print("Vendor: " + str(vendor))
                print("Channel: " + str(channelz))
                print("Crypto: " + str(crypto))
                print("Signal: " + str(dbm_signal) + "dBm")
                print("Longitude: " + str(gps_lon))
                print("Latitude: " + str(gps_lat))
                print("Timestamp: " + str(time_stamp))
                print("")

            found_APs.append(mac_address)
            with closing(sqlite3.connect("osint.db")) as connection:
                with closing(connection.cursor()) as cursor:
                    cursor.execute("insert into accessPoints (date_added, mac_address, mac_address_vendor, ssid, signal, longitude, latitude, location) values (?, ?, ?, ?, ?, ?, ?, ?)", (time_stamp, mac_address, vendor, ssid, dbm_signal, gps_lon, gps_lat, location))
                    connection.commit()

def sniff_wifi_probes(packet):
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
                    #type = request or response (from AP)
                    with closing(sqlite3.connect("osint.db")) as connection:
                        with closing(connection.cursor()) as cursor:
                            cursor.execute("insert into wifiProbeRequests (date_added, mac_address, mac_address_vendor, ssid, signal, location, longitude, latitude) values (?, ?, ?, ?, ?, ?, ?, ?)", (dt, mac, vendor, ssid, rssi, gps_lon, gps_lat, location))
                            connection.commit()
                    if(show_output):
                        print("========================WIFI PROBE REQUEST====================================")
                        print("%s | Device MAC: %s | Vendor: %s | SSID: %s | %s dBm | Frequency: %s | Latitude: %s | Longitude: %s" % (dt, mac, vendor, ssid, rssi, chanfreq, gps_lat, gps_lon))
                        print("==============================================================================")

    except UnicodeDecodeError as unicode_decode_err:
            # The ESSID is not a valid UTF-8 string.
            #raise TypeError from unicode_decode_err
        pass

    if packet.haslayer(Dot11ProbeResp):
        client_mac = str(packet.addr1)
        client_vendor=find_mac_vendor(client_mac)

        ap_mac = str(packet.addr2)
        ap_mac_vendor = find_mac_vendor(ap_mac)

        ssid = str(packet.info.decode("utf-8"))
        timestamp = packet.getlayer(RadioTap).time
        dt = str(datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S"))
        rssi = str(packet[RadioTap].dBm_AntSignal)

        #chanfreq is currently the channel the wifi card is on from this device and not the signal's chanfreq
        chanfreq = get_channel(packet[RadioTap].ChannelFrequency)

        if not (ssid == ""):
            #type = request or response (from AP)
            with closing(sqlite3.connect("osint.db")) as connection:
                with closing(connection.cursor()) as cursor:
                    cursor.execute("insert into wifiProbeResponses (date_added, client_mac_address, client_mac_address_vendor, ap_mac_address, ap_mac_address_vendor, ssid, signal, longitude, latitude, location) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (dt, client_mac, client_vendor, ap_mac, ap_mac_vendor, ssid, rssi,gps_lon, gps_lat, location))
                    connection.commit()
            if(show_output):
                print("*************************WIFI PROBE Response**************************************")
                print("%s | Device MAC: %s | Client MAC: %s | SSID: %s | %s dBm | Frequency: %s | Latitude: %s | Longitude: %s" % (dt, client_mac, ap_mac, ssid, rssi, chanfreq, gps_lat, gps_lon))
                print("**********************************************************************************")

def sniff_bluetooth_data():

    while True:
        database_column_list = ['Name','Alias','UUID','RSSI']
        bt = Bluetoothctl()
        bt.start_scan()
        #give 10 seconds to scan
        for i in range(1, 10):
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

            with closing(sqlite3.connect("osint.db")) as connection:
                with closing(connection.cursor()) as cursor:
                    cursor.execute("insert into bluetoothDevices (name, mac_address, alias, uuid, rssi, date_added, longitude, latitude, location) values (?, ?, ?, ?, ?, ?, ?, ?, ?)", (name, mac_address, alias, uuid, rssi, date_added, gps_lon, gps_lat, location))
                    connection.commit()
            if(show_output):
                print("==============Bluetooth device====================")
                print("Timestamp: " + date_added)
                print("Name: " + str(name))
                print("RSSI: " + str(rssi))
                print("Alias: " + str(alias))
                print("UUID: " + uuid)
                print("MAC: " + mac_address)
                print("Longitude: " + gps_lon)
                print("Latitude: " + gps_lat)

        #at home scan every 1 minutes
        #make list of known adresses and stop doing stuff maybe? instead of a 10s timer.
        time.sleep(30)

def sniffpackets(packet):
    
    sniff_wifi_APs(packet)
    sniff_wifi_probes(packet)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    check_root()

    #TODO: check if db schemas exist

    parser = argparse.ArgumentParser()
    parser.add_argument('--interface', '-i', default='wlan1',
                help='monitor mode enabled interface')
    parser.add_argument('--location', '-l', default='home',
                help='description of sniffing location')
    args = parser.parse_args()

    #if not args.interface:
    #    print("You must specify an interface in monitor mode")

    interface = args.interface
    location = args.location

    setup_monitor(interface)

    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()

    bt = Thread(target=sniff_bluetooth_data)
    bt.daemon = True
    bt.start()

    gps_location = Thread(target=set_gps_coordinates)
    gps_location.daemon = True
    gps_location.start()

    print("Sniffing WIFI on " + str(interface) + "...\n")
    sniff(iface=interface, prn=sniffpackets, store=0, monitor=True)

    while 1:
        time.sleep(1)





