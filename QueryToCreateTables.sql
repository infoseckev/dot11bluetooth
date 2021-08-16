CREATE TABLE wifiProbeRequests (id integer primary key, date_added text, mac_address text, mac_address_vendor text, ssid text, signal text, longitude text, latitude text, location text);

CREATE TABLE wifiProbeResponses (id integer primary key, date_added text, client_mac_address text, client_mac_address_vendor text, ap_mac_address text, ap_mac_address_vendor text, ssid text, signal text, longitude text, latitude text, location text);

CREATE TABLE bluetoothDevices (id integer primary key, date_added text, mac_address text, mac_address_vendor text, alias text, uuid text, rssi text, longitude text, latitude text, location text);

CREATE TABLE accessPoints (id integer primary key, date_added text, mac_address text, mac_address_vendor, ssid text, signal text, longitude, latitude text, location text);










