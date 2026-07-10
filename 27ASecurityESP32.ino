#include <WiFi.h>
#include <WebServer.h>
#include <WiFiUdp.h>
#include <functional>
#include "switch.h"
#include "UpnpBroadcastResponder.h"
#include "CallbackFunction.h"

// Bluetooth section

int rssiThreshold = -90;         // Predefined threshold in dBm (closer to 0 is stronger) can be re defined on web page
int presenceWindowSeconds = 60;  // How long to remember a bluetooth device
int scanSliceDuration = 3;       // Scanning duration slice in seconds

#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>

#define SCAN_TIME 2

BLEScan* pBLEScan;

struct TrackedBeacon {
  String macAddress;
  int rssi;
  unsigned long lastSeen;
  unsigned long firstSeen;
  String deviceType;         // <-- Add this to store the name/manufacturer
  String findMyFingerprint;  // <- Holds the fixed unique identifier payload
};

const int MAX_DEVICES = 30;
TrackedBeacon discoveredDevices[MAX_DEVICES];
int deviceCount = 0;

String IdentifyManufacturer(String macAddress) {
  macAddress.toUpperCase();

  // 1. Direct Hardcoded Matches (Must use UPPERCASE letters!)
  if (macAddress == "38:F9:D3:19:96:BA") return "Tony's MacBook";
  if (macAddress == "84:B1:E4:08:62:AB") return "Tony's IPHONE13";
 if (macAddress == "10:00:20:72:5B:7A") return "Tony's iPad (3)";

  // 2. Extract first 3 bytes (the OUI prefix e.g., "00:05:78")
  String prefix = macAddress.substring(0, 8);

  // --- NEW: LG Smart TVs & Appliances ---
  // Covers LG Electronics, LG Innotek, and standard LG network modules
  if (prefix == "AC:5A:F0" || prefix == "00:05:C9" || prefix == "00:1C:62" || prefix == "1C:5A:6B" || prefix == "20:28:BC" || prefix == "34:FC:B9" || prefix == "4C:12:9F" || prefix == "98:D6:BB" || prefix == "A4:08:EA") {
    return "LG Smart TV";
  }

  if (prefix == "FC:45:C3") {
    return "Texas Instrument";
  }

  if (prefix == "D0:EE:DC") {
    return "Intel Corp";
  }

  if (prefix == "6C:DE:E9") {
    return "Intel Corp";
  }

  if (prefix == "C8:45:6A") {
    return "Custom IoT Node ";  // like Tuya or Espressif
  }

  if (prefix == "50:9A:63" || prefix == "6C:F3:67") {
    return "Nokia Hardware";
  }
  if (prefix == "E0:90:2E") {
    return "Murata IoT Module  (sony PlayStation)";
  }
  // --- NEW: Samsung Smart TVs ---
  // Covers major Samsung Electronics TV chassis and internal Bluetooth modules
  if (prefix == "00:00:F0" || prefix == "00:07:AB" || prefix == "00:16:32" || prefix == "64:1C:B0" || prefix == "30:62:22" || prefix == "50:CC:F8" || prefix == "64:1B:2F" || prefix == "9C:73:B1" || prefix == "DC:87:F8" || prefix == "E0:03:6B" || prefix == "FC:A6:EE") {
    return "Samsung Smart TV";
  }

  // Apple Ecosystem (Added your MacBook/Mac prefix!)
  if (prefix == "D8:E3:7C" || prefix == "F0:AA:CF" || prefix == "00:05:78" || prefix == "00:0A:95" || prefix == "74:52:63" || prefix == "00:10:FA" || prefix == "00:1C:B3" || prefix == "10:DD:B1" || prefix == "14:10:9F" || prefix == "D0:25:98" || prefix == "E0:C9:7A") {
    return "Apple Device";
  }

  // Huawei Block Update
  if (prefix == "57:1B:71") {
    return "Huawei Device";
  }

  // Xiaomi Block Update
  if (prefix == "CC:20:F8") {
    return "Xiaomi Device";
  }

  // Tuya Smart Home Appliance Block Update
  if (prefix == "E7:D6:CB") {
    return "Tuya Smart IoT Node";
  }

  // Google / Alphabet / Nest
  if (prefix == "3C:5A:B4" || prefix == "D8:EB:97" || prefix == "00:1A:11" || prefix == "08:6A:18" || prefix == "3C:5A:B4" || prefix == "D8:EB:97") {
    return "Google Device";
  }

  // Samsung Mobile / General (Distinct from targeted TV modules if needed)
  if (prefix == "BC:D1:D3" || prefix == "00:12:47" || prefix == "38:AA:3C" || prefix == "A8:7B:39" || prefix == "CC:C7:60") {
    return "Samsung Mobile";
  }

  // Espressif Systems (Other ESP32 or ESP8266 smart devices in your house)
  if (prefix == "24:4B:03" || prefix == "30:AE:A4" || prefix == "A4:CF:12" || prefix == "C8:2B:96" || prefix == "EC:FA:BC") {
    return "Espressif (ESP32/8266)";
  }

  // Amazon (Echo dots, Kindles, Fire sticks)
  if (prefix == "00:BB:3A" || prefix == "50:DC:E7" || prefix == "FC:A1:3E" || prefix == "F4:DD:FA") {
    return "Amazon Echo/Device";
  }

  // Matches Dialog/Renesas BLE chipsets exclusively used by static Tiles
  if (prefix == "00:25:BF" || prefix == "D8:24:BD" || prefix == "60:C0:BF" || prefix == "24:4C:E3" || prefix == "D4:C1:FC" || prefix == "80:EA:CA") {
    return "Tile Tracker (Static)";
  }

  // 3. Fallback Smart Check: Detect Randomized Privacy & Local Mobile Addresses
  // Extract the second character of the MAC string
  char privateChar = macAddress.charAt(1);

  // Checks for BOTH uppercase and lowercase definitions of privacy characters (2, 6, A/a, E/e)
  // Also added direct flags for common mobile randomizations (b, 9, 5, f)
  if (privateChar == 'B' || privateChar == 'b' || privateChar == 'F' || privateChar == 'f' || privateChar == '9') {
    return "Randomised Private Smartphone/Tablet";
  }

  if (privateChar == '2' || privateChar == '3' || privateChar == '6' || privateChar == '5' || privateChar == '7' || privateChar == 'A' || privateChar == 'a' || privateChar == 'E' || privateChar == 'e') {
    return "Locally Administered / Private Randomized";
  }

  // Final catch-all if it survives all hardcoded vendor rules and privacy checks
  return "Unknown Brand";
}
/* prior to changes to add apple Find My devices 

class MyAdvertisedDeviceCallbacks : public BLEAdvertisedDeviceCallbacks {
  void onResult(BLEAdvertisedDevice advertisedDevice) {
    int currentRssi = advertisedDevice.getRSSI();

    String currentMac = advertisedDevice.getAddress().toString().c_str();

    // --- ADD THESE LINES TO PRINT TO SERIAL MONITOR ---
    Serial.print("BLE Device Found: ");
    Serial.print(currentMac);
    Serial.print(" | RSSI: ");
    Serial.println(currentRssi);
    Serial.println(IdentifyManufacturer(currentMac));
    // --------------------------------------------------

    // Ignore the device completely if the signal is too weak
    if (currentRssi < rssiThreshold) {
      return;
    }
String manufacturer = IdentifyManufacturer(currentMac);

    unsigned long now = millis();



    bool found = false;
    for (int i = 0; i < deviceCount; i++) {
      if (discoveredDevices[i].macAddress == currentMac) {
        // If the device has been missing for over 30 seconds, reset arrival timer
        if (now - discoveredDevices[i].lastSeen > 30000) {
          discoveredDevices[i].firstSeen = now;
        }

        discoveredDevices[i].rssi = currentRssi;
        discoveredDevices[i].lastSeen = now;
        discoveredDevices[i].deviceType = manufacturer; 
        found = true;
        break;
      }
    }

    if (!found && deviceCount < MAX_DEVICES) {
      discoveredDevices[deviceCount].macAddress = currentMac;
      discoveredDevices[deviceCount].rssi = currentRssi;
      discoveredDevices[deviceCount].lastSeen = now;
      discoveredDevices[deviceCount].firstSeen = now;
      discoveredDevices[deviceCount].deviceType = manufacturer; // Save details
      deviceCount++;
    }
  }
};

*/

/*

class MyAdvertisedDeviceCallbacks : public BLEAdvertisedDeviceCallbacks {
  void onResult(BLEAdvertisedDevice advertisedDevice) {
    int currentRssi = advertisedDevice.getRSSI();
    
    // 1. Immediately drop devices below your custom live web slider threshold
    if (currentRssi < rssiThreshold) {
      return;
    }

    String currentMac = advertisedDevice.getAddress().toString().c_str();
    currentMac.toUpperCase();
    
    String manufacturer = "Unknown Brand";
    String payloadSignature = ""; // Holds the permanent fingerprint if it's a dynamic Apple tag

    // 2. CHECK FOR TILE SERVICE PAYLOAD OVERRIDES (0xFEED / 0xFEEC)
    if (advertisedDevice.haveServiceUUID()) {
      String serviceUUID = advertisedDevice.getServiceUUID().toString().c_str();
      if (serviceUUID.indexOf("feed") != -1 || serviceUUID.indexOf("feec") != -1) {
        manufacturer = "Tile Tracker";
         Serial.println("Tile Tracker found");
      }
    }

    // 3. CHECK FOR APPLE FIND MY PAYLOADS (Company ID: 0x004C)
    if (manufacturer == "Unknown Brand" && advertisedDevice.haveManufacturerData()) {
      // FIX: Changed from std::string to Arduino String to match library return type
      String rawData = advertisedDevice.getManufacturerData().c_str(); 
      
      if (rawData.length() >= 7 && (uint8_t)rawData[0] == 0x4C && (uint8_t)rawData[1] == 0x00) {
        manufacturer = "Apple Find My Tracker";
         Serial.println("Apple Found my Tracker found");
        
        // Extract 6 bytes starting at index 4 as a permanent software tracking fingerprint
        char buff[13];
        snprintf(buff, sizeof(buff), "%02X%02X%02X%02X%02X%02X", 
                 (uint8_t)rawData[4], (uint8_t)rawData[5], (uint8_t)rawData[6], 
                 (uint8_t)rawData[7], (uint8_t)rawData[8], (uint8_t)rawData[9]);
        payloadSignature = String(buff);
      }
    }

    // 4. CENTRALIZED FALLBACK: Run your regular OUI vendor prefix check if it's a standard MAC
    if (manufacturer == "Unknown Brand") {
      manufacturer = IdentifyManufacturer(currentMac);
    }

    // 5. FUTURE ASSIGNMENT PLACEHOLDER: 
    // Once you read the blue key text codes off your web dashboard, paste them here!
    // if (payloadSignature == "A1B2C3D4E5F6") manufacturer = "Tony's Keys (FindMy)";
    // if (payloadSignature == "F6E5D4C3B2A1") manufacturer = "Tony's Wallet (FindMy)";

    unsigned long now = millis();
    bool found = false;
    
    // 6. LOOP TRACKING STORAGE MATCH MATCH ENGINE (MAX_DEVICES = 30)
    for (int i = 0; i < deviceCount; i++) {
      // Clean cross-match: Match by signature for Find My tags, match by MAC for static gear
      if ((payloadSignature != "" && discoveredDevices[i].findMyFingerprint == payloadSignature) || 
          (payloadSignature == "" && discoveredDevices[i].macAddress == currentMac)) {
        
        // Reset arrival window timer if device has been gone for over 30 seconds
        if (now - discoveredDevices[i].lastSeen > 30000) {
          discoveredDevices[i].firstSeen = now;
        }

        // Keep updating fields (updates shifting temporary MACs dynamically)
        discoveredDevices[i].macAddress = currentMac; 
        discoveredDevices[i].rssi = currentRssi;
        discoveredDevices[i].lastSeen = now;
        discoveredDevices[i].deviceType = manufacturer; 
        found = true;
        break;
      }
    }

    // 7. SLOT RESERVATION FOR NEW INCOMING DEVICE IDENTITIES
    if (!found && deviceCount < MAX_DEVICES) {
      discoveredDevices[deviceCount].macAddress = currentMac;
      discoveredDevices[deviceCount].rssi = currentRssi;
      discoveredDevices[deviceCount].lastSeen = now;
      discoveredDevices[deviceCount].firstSeen = now;
      discoveredDevices[deviceCount].deviceType = manufacturer;
      discoveredDevices[deviceCount].findMyFingerprint = payloadSignature; // Commit key fingerprint
      deviceCount++;
    }
  }
};

*/

/* 
this still doesnt work, no apple find my stuff to be seen

a new thread AI (the old one crashed) says 
he reason your code is completely missing the nearby Apple Find My devices comes down to a critical memory vulnerability introduced in your fix: the C-string null-byte truncation bug.
When you modified the code to use .c_str(), you inadvertently caused the ESP32 to drop the payload. 
Apple Find My payload packets use standard raw binary data. The very second byte of an Apple manufacturer beacon is 0x00 (from Apple's registered ID: 0x4C, 0x00). In C/C++, a 0x00 byte is interpreted as a null-terminator character, which signals the end of a text string. As a result, when you called .c_str(), your data length immediately truncated to exactly 1 byte long (0x4C), failing your code's check if (rawBytes.length() >= 7).

class MyAdvertisedDeviceCallbacks : public BLEAdvertisedDeviceCallbacks {
  void onResult(BLEAdvertisedDevice advertisedDevice) {
    int currentRssi = advertisedDevice.getRSSI();
    if (currentRssi < rssiThreshold) return;

    String currentMac = advertisedDevice.getAddress().toString().c_str();
    currentMac.toUpperCase();
    
    String manufacturer = "Unknown Brand";
    String payloadSignature = ""; 

    // 1. CHECK FOR TILE SERVICE PAYLOAD OVERRIDES (0xFEED / 0xFEEC)
    if (advertisedDevice.haveServiceUUID()) {
      String serviceUUID = advertisedDevice.getServiceUUID().toString().c_str();
      if (serviceUUID.indexOf("feed") != -1 || serviceUUID.indexOf("feec") != -1) {
        manufacturer = "Tile Tracker";
      }
    }

    // 2. FIXED: ROBUST RAW BYTE MEMORY INSPECTION FOR APPLE FIND MY TAGS
    if (manufacturer == "Unknown Brand" && advertisedDevice.haveManufacturerData()) {
     // std::string rawBytes = advertisedDevice.getManufacturerData();
     std::string rawBytes = advertisedDevice.getManufacturerData().c_str();
      
      // Access the raw C-string data pointer safely to bypass typecast quirks
      if (rawBytes.length() >= 7) {
        uint8_t* pData = (uint8_t*)rawBytes.data();
        
        // Match Apple's specific Company Identifier (0x4C, 0x00)
        if (pData[0] == 0x4C && pData[1] == 0x00) {
          manufacturer = "Apple Find My Tracker";
          
          // Build the unique 6-byte software signature fingerprint from the beacon data
          char buff[13];
          snprintf(buff, sizeof(buff), "%02X%02X%02X%02X%02X%02X", 
                   pData[4], pData[5], pData[6], pData[7], pData[8], pData[9]);
          payloadSignature = String(buff);
        }
      }
    }

    // 3. Fallback to standard MAC lookup if no special payloads were triggered
    if (manufacturer == "Unknown Brand") {
      manufacturer = IdentifyManufacturer(currentMac);
    }

      // 4. CENTRALIZED FALLBACK: Run your regular OUI vendor prefix check if it's a standard MAC
    if (manufacturer == "Unknown Brand") {
      manufacturer = IdentifyManufacturer(currentMac);
    }

    unsigned long now = millis();
    bool found = false;
    
    // 5. MASTER TRACKING MEMORY ARRAY MATCH ENGINE
    for (int i = 0; i < deviceCount; i++) {
      if ((payloadSignature != "" && discoveredDevices[i].findMyFingerprint == payloadSignature) || 
          (payloadSignature == "" && discoveredDevices[i].macAddress == currentMac)) {
        
        if (now - discoveredDevices[i].lastSeen > 30000) {
          discoveredDevices[i].firstSeen = now;
        }

        discoveredDevices[i].macAddress = currentMac; 
        discoveredDevices[i].rssi = currentRssi;
        discoveredDevices[i].lastSeen = now;
        discoveredDevices[i].deviceType = manufacturer; 
        found = true;
        break;
      }
    }

    // 6. STORAGE RESERVATION FOR UNLINKED DEVICE SIGNATURES
    if (!found && deviceCount < MAX_DEVICES) {
      discoveredDevices[deviceCount].macAddress = currentMac;
      discoveredDevices[deviceCount].rssi = currentRssi;
      discoveredDevices[deviceCount].lastSeen = now;
      discoveredDevices[deviceCount].firstSeen = now;
      discoveredDevices[deviceCount].deviceType = manufacturer;
      discoveredDevices[deviceCount].findMyFingerprint = payloadSignature; 
      deviceCount++;
    }
  }
};

*/

/* fixing order of checking devices 
class MyAdvertisedDeviceCallbacks : public BLEAdvertisedDeviceCallbacks {
  void onResult(BLEAdvertisedDevice advertisedDevice) {
    int currentRssi = advertisedDevice.getRSSI();
    if (currentRssi < rssiThreshold) return;

    String currentMac = advertisedDevice.getAddress().toString().c_str();
    currentMac.toUpperCase();
    
    String manufacturer = "Unknown Brand";
    String payloadSignature = ""; 

    // 1. CHECK FOR TILE SERVICE PAYLOAD OVERRIDES (0xFEED / 0xFEEC)
    if (advertisedDevice.haveServiceUUID()) {
      String serviceUUID = advertisedDevice.getServiceUUID().toString().c_str();
      if (serviceUUID.indexOf("feed") != -1 || serviceUUID.indexOf("feec") != -1) {
        manufacturer = "Tile Tracker";
      }
    }
****
This version of the class assumed anything Apple is a find my tracker , it showed 10 of them!

    // 2. FIXED: PARSE MANUFACTURE DATA AS RAW BINARY TO PREVENT NULL-TERMINATOR TRUNCATION
    if (manufacturer == "Unknown Brand" && advertisedDevice.haveManufacturerData()) {
      // Fetch as native Arduino String but extract underlying byte length safely
      String mfgDataStr = advertisedDevice.getManufacturerData();
      int dataLength = mfgDataStr.length();
      
      // Ensure we have enough data bytes to check (Apple headers need at least 7+ bytes)
      if (dataLength >= 7) {
        const uint8_t* pData = (const uint8_t*)mfgDataStr.c_str();
        
        // Match Apple's specific Company Identifier (0x4C, 0x00)
        // Note: Even if c_str() hits a null-terminator, the array buffer itself still holds the bytes!
        if (pData[0] == 0x4C && pData[1] == 0x00) {
          manufacturer = "Apple Find My Tracker";
          
          // Build the unique 6-byte software signature fingerprint from the beacon data
          char buff[13];
          snprintf(buff, sizeof(buff), "%02X%02X%02X%02X%02X%02X", 
                   pData[4], pData[5], pData[6], pData[7], pData[8], pData[9]);
          payloadSignature = String(buff);
        }
      }
    }
****

// 2. FIXED: STRICT VALIDATION FOR ACTUAL APPLE FIND MY BEACONS ONLY
    if (manufacturer == "Unknown Brand" && advertisedDevice.haveManufacturerData()) {
      String mfgDataStr = advertisedDevice.getManufacturerData();
      int dataLength = mfgDataStr.length();
      
      if (dataLength >= 7) {
        const uint8_t* pData = (const uint8_t*)mfgDataStr.c_str();
        
        // 1. Must be Apple (0x4C, 0x00)
        // 2. Must match Find My Beacon Subtype (0x12)
        // 3. Must match the exact standard tracking payload length (0x19)
        if (pData[0] == 0x4C && pData[1] == 0x00 && pData[2] == 0x12 && pData[3] == 0x19) {
          manufacturer = "Apple Find My Tracker";
          
          // The actual unique public key fingerprint starts at byte index 6
          char buff[13];
          snprintf(buff, sizeof(buff), "%02X%02X%02X%02X%02X%02X", 
                   pData[6], pData[7], pData[8], pData[9], pData[10], pData[11]);
          payloadSignature = String(buff);
        }
      }
    }

    // 3. Fallback to standard MAC lookup if no special payloads were triggered
    if (manufacturer == "Unknown Brand") {
      manufacturer = IdentifyManufacturer(currentMac);
    }

    unsigned long now = millis();
    bool found = false;
    
    // 4. MASTER TRACKING MEMORY ARRAY MATCH ENGINE
    for (int i = 0; i < deviceCount; i++) {
      if ((payloadSignature != "" && discoveredDevices[i].findMyFingerprint == payloadSignature) || 
          (payloadSignature == "" && discoveredDevices[i].macAddress == currentMac)) {
        
        if (now - discoveredDevices[i].lastSeen > 30000) {
          discoveredDevices[i].firstSeen = now;
        }

        discoveredDevices[i].macAddress = currentMac; 
        discoveredDevices[i].rssi = currentRssi;
        discoveredDevices[i].lastSeen = now;
        discoveredDevices[i].deviceType = manufacturer; 
        found = true;
        break;
      }
    }

    // 5. STORAGE RESERVATION FOR UNLINKED DEVICE SIGNATURES
    if (!found && deviceCount < MAX_DEVICES) {
      discoveredDevices[deviceCount].macAddress = currentMac;
      discoveredDevices[deviceCount].rssi = currentRssi;
      discoveredDevices[deviceCount].lastSeen = now;
      discoveredDevices[deviceCount].firstSeen = now;
      discoveredDevices[deviceCount].deviceType = manufacturer;
      discoveredDevices[deviceCount].findMyFingerprint = payloadSignature; 
      deviceCount++;
    }
  }
};
*/

class MyAdvertisedDeviceCallbacks : public BLEAdvertisedDeviceCallbacks {
  void onResult(BLEAdvertisedDevice advertisedDevice) {
    int currentRssi = advertisedDevice.getRSSI();
    if (currentRssi < rssiThreshold) return;

    String currentMac = advertisedDevice.getAddress().toString().c_str();
    currentMac.toUpperCase();

    String manufacturer = "Unknown Brand";
    String payloadSignature = "";

    // ==========================================
    // 1. TOP PRIORITY: STATIC HARDCODED OVERRIDES
    // ==========================================
    if (currentMac == "38:F9:D3:19:96:BA") {
      manufacturer = "Tony's MacBook";
    }

    // ==========================================
    // 2. CHECK FOR REAL TILE SERVICE PAYLOADS (Only if still unknown)
    // ==========================================
    if (manufacturer == "Unknown Brand" && advertisedDevice.haveServiceUUID()) {
      String serviceUUID = advertisedDevice.getServiceUUID().toString().c_str();
      if (serviceUUID.indexOf("feed") != -1 || serviceUUID.indexOf("feec") != -1) {
        manufacturer = "Tile Tracker";
      }
    }

    // ==========================================
    // 3. STRICT VALIDATION FOR ACTUAL APPLE FIND MY BEACONS ONLY
    // ==========================================
    if (manufacturer == "Unknown Brand" && advertisedDevice.haveManufacturerData()) {
      String mfgDataStr = advertisedDevice.getManufacturerData();
      int dataLength = mfgDataStr.length();

      if (dataLength >= 7) {
        const uint8_t* pData = (const uint8_t*)mfgDataStr.c_str();

        // Byte 0-1: Apple (0x4C, 0x00)
        // Byte 2: Find My Subtype (0x12)
        // Byte 3: Exact Tracking Payload Length (0x19)
        if (pData[0] == 0x4C && pData[1] == 0x00 && pData[2] == 0x12 && pData[3] == 0x19) {
          manufacturer = "Apple Find My Tracker";

          // Fingerprint generation
          char buff[13];
          snprintf(buff, sizeof(buff), "%02X%02X%02X%02X%02X%02X",
                   pData[6], pData[7], pData[8], pData[9], pData[10], pData[11]);
          payloadSignature = String(buff);
        }
      }
    }

    // ==========================================
    // 4. FALLBACK: Run standard OUI vendor lookup
    // ==========================================
    if (manufacturer == "Unknown Brand") {
      manufacturer = IdentifyManufacturer(currentMac);
    }

    // ==========================================
    // 5. MASTER TRACKING MEMORY ENGINE
    // ==========================================
    unsigned long now = millis();
    bool found = false;

    for (int i = 0; i < deviceCount; i++) {
      if ((payloadSignature != "" && discoveredDevices[i].findMyFingerprint == payloadSignature) || (payloadSignature == "" && discoveredDevices[i].macAddress == currentMac)) {

        if (now - discoveredDevices[i].lastSeen > 30000) {
          discoveredDevices[i].firstSeen = now;
        }

        discoveredDevices[i].macAddress = currentMac;
        discoveredDevices[i].rssi = currentRssi;
        discoveredDevices[i].lastSeen = now;
        discoveredDevices[i].deviceType = manufacturer;
        found = true;
        break;
      }
    }

    if (!found && deviceCount < MAX_DEVICES) {
      discoveredDevices[deviceCount].macAddress = currentMac;
      discoveredDevices[deviceCount].rssi = currentRssi;
      discoveredDevices[deviceCount].lastSeen = now;
      discoveredDevices[deviceCount].firstSeen = now;
      discoveredDevices[deviceCount].deviceType = manufacturer;
      discoveredDevices[deviceCount].findMyFingerprint = payloadSignature;
      deviceCount++;
    }
  }
};

// prototypes
boolean connectWifi();  // router handed out 192.168.1.169 for this initially

//on/off callbacks
bool Sec27ASetOn();
bool Sec27ASetOff();
bool Sec27AUnsetOn();
bool Sec27AUnsetOff();
bool Sec27APanicOn();
bool Sec27APanicOff();
bool AlarmSetLockout = LOW;  // HIGH is lockout state

// Change this before you flash
//const char* ssid = "SmartStuff";
//const char* password = "Password123456";

const char* ssid = "Inspire Net 2.4G";
const char* password = "cexekocura";

boolean wifiConnected = false;

UpnpBroadcastResponder upnpBroadcastResponder;

Switch* Sec27ASet = NULL;
Switch* Sec27AUnset = NULL;
Switch* Sec27APanic = NULL;

bool isSec27ASetOn = false;
bool isSec27AUnsetOn = false;
bool isSec27APanicOn = false;
bool Sec27ASetState = LOW;
bool PrevSec27ASetState = LOW;
bool Sec27ASoundingState = LOW;
bool PrevSec27ASoundingState = LOW;

//const int SetUnsetInputPin = 0;  // SetUnsetInputPin pin on ESP-01
const int SetUnsetInputPin = 9;  // SetUnsetInputPin pin on ESP32 -C3 - The BOOT button
//const int LedPin = 2;             // GPIO2 pin. used as LED Driver on ESP-01 / 8266
const int LedPin = 8;                 //  used as LED Driver on an ESP32-C3
const int AlarmSoundingInputPin = 3;  //
/*
IO for an ESP-01 setup on a dual relay board
GPIO0 - Alarm Panel Set/Unset input
GPIO1 (TXD) = unused exept for serial debug
GPIO2 -LED Driver 
GPIO3 (RXD) - potentially the AlarmSounding input . Not used by current code except logging alarm activity towards the local web page and watchdog proxy

Onboard relay1 = AlarmSet/Unset control
Onboard relay2 = Panic Input or outside siren
*/

byte VBNumber = 40;          // 40 is the watchdog post value for the 27A Security Interface
String VBNumberString = "";  // also need a string as leading zero needed for later string matching accuracy

const char* WatchDogHost = "192.168.1.60";  // ip address of the watchdog esp8266

long WatchDogCounterLoopThreshold = 200;  // value of 30 is about 5secs. 200 is about 20 sec
long WatchDogLoopCounter = 0;

byte rel1ON[] = { 0xA0, 0x01, 0x01, 0xA2 };   //Hex command to send to serial for open relay 1 - set/unset alarm
byte rel1OFF[] = { 0xA0, 0x01, 0x00, 0xA1 };  //Hex command to send to serial for close relay 1
byte rel2ON[] = { 0xA0, 0x02, 0x01, 0xA3 };   //Hex command to send to serial for open relay 2 - Panic zone or outside siren
byte rel2OFF[] = { 0xA0, 0x02, 0x00, 0xA2 };  //Hex command to send to serial for close relay 2

//WiFiServer server(80);  // start bWebServer
WebServer server(80);

String ledState = "OFF";
//const int ledPin = 2;  // Built-in LED pin on 8266

int ProxyLogArrayIndex = 0;

byte currentseconds = 0;
byte currentminutes = 55;
byte currenthours = 12;
long currentday = 0;
long currentmonth = 0;
String ProxyLogArray[64];  // 20 events each containing Date [0], Time[1], Proxt [2]. last 3 entries (60,61,62) are headers
String LastRebootDate;
String LastRebootTime;
float UpTimeDays = 0;
byte ProxyRequestID = 0;
String ProxyRequestText;
bool SetTimeWasSuccesfull;
int DSTOffset = 1;

int StackedIndex = 0;
byte WebPageMode = 2;  // 1 = Setup, 2 = Runtime

unsigned long currentTime = millis();

unsigned long previousTime = 0;
unsigned long previousMillis = 0;


int AlarmSetLockoutCounter;
int AlarmSetLockoutCounterThreshold = 30;

// Set your Static IP address
//IPAddress local_IP(192, 168, 1, 169);  // fixed IP address for the 27A Security Interface (this code) at 27A
//IPAddress gateway(192, 168, 1, 1);
IPAddress local_IP(192, 168, 20, 20);  // fixed IP address for the 27A Security Interface (this code) at Dougs place
IPAddress gateway(192, 168, 20, 1);
IPAddress subnet(255, 255, 255, 0);
IPAddress primaryDNS(8, 8, 8, 8);    // Google DNS (crucial for NTP time sync)
IPAddress secondaryDNS(8, 8, 4, 4);  // Optional backup DNS

void setup() {

  pinMode(LedPin, OUTPUT);

  Serial.begin(115200);
  delay(1000);

  Serial.println("Booting 27a Security Interface...");
  delay(1000);

  //flash fast a few times to indicate CPU is booting
  digitalWrite(LedPin, LOW);
  delay(100);
  digitalWrite(LedPin, HIGH);
  delay(100);
  digitalWrite(LedPin, LOW);
  delay(100);
  digitalWrite(LedPin, HIGH);
  delay(100);
  digitalWrite(LedPin, LOW);
  delay(100);
  digitalWrite(LedPin, HIGH);
  delay(100);
  digitalWrite(LedPin, LOW);
  delay(100);
  digitalWrite(LedPin, HIGH);
  delay(100);
  digitalWrite(LedPin, LOW);
  delay(100);
  digitalWrite(LedPin, HIGH);
  delay(100);
  digitalWrite(LedPin, LOW);
  delay(100);
  digitalWrite(LedPin, HIGH);

  Serial.println("Booting 27A Security Interface.    Delaying a bit...");
  delay(2000);

  //WiFi.setSleepMode(WIFI_NONE_SLEEP); 8266 style
  WiFi.setSleep(false);

  // Initialise wifi connection
  wifiConnected = connectWifi();

  if (wifiConnected) {

    //flash slow a few times to indicate wifi connected OK
    digitalWrite(LedPin, LOW);
    delay(1000);
    digitalWrite(LedPin, HIGH);
    delay(1000);
    digitalWrite(LedPin, LOW);
    delay(1000);
    digitalWrite(LedPin, HIGH);
    delay(1000);
    digitalWrite(LedPin, LOW);
    delay(1000);
    digitalWrite(LedPin, HIGH);

    upnpBroadcastResponder.beginUdpMulticast();

    // Define your switches here. Max 10
    // Format: Alexa invocation name, local port no, on callback, off callback
    Sec27ASet = new Switch("Enable 27A Perimeter Monitor", 67, Sec27ASetOn, Sec27ASetOff);
    Sec27AUnset = new Switch("Disable 27A Perimeter Monitor", 68, Sec27AUnsetOn, Sec27AUnsetOff);
    Sec27APanic = new Switch("27A Panic", 69, Sec27APanicOn, Sec27APanicOff);

    Serial.println("Adding switches upnp broadcast responder");
    upnpBroadcastResponder.addDevice(*Sec27ASet);
    upnpBroadcastResponder.addDevice(*Sec27AUnset);
    upnpBroadcastResponder.addDevice(*Sec27APanic);
  }
  digitalWrite(LedPin, HIGH);  // turn off LED

  Serial.println("Making AlarmSoundingInputPin into an INPUT_PULLUP");
  //pinMode(AlarmSoundingInputPin, FUNCTION_3); old 8266 function, not needed in ESP32
  pinMode(AlarmSoundingInputPin, INPUT_PULLUP);

  Serial.println("Making SetUnsetInputPin into an INPUT_PULLUP");  // used to detect 27A Security  Set/Unset state

  //pinMode(SetUnsetInputPin, FUNCTION_3);
  pinMode(SetUnsetInputPin, INPUT);

  // Start the server and print local IP address
  server.begin();
  Serial.println("");
  Serial.println("Wi-Fi connected.");
  Serial.print("IP address to visit: http://");
  Serial.println(WiFi.localIP());

  // populate event log headers
  ProxyLogArray[60] = "Date";
  ProxyLogArray[61] = "Time";
  ProxyLogArray[62] = "Event Info";

  ProxyLogArray[57] = "1st Entry date";
  ProxyLogArray[58] = "1st Entry time";
  ProxyLogArray[59] = "1st Entry Event";

  ProxyLogArray[54] = "2 Entry date";
  ProxyLogArray[55] = "2 Entry time";
  ProxyLogArray[56] = "2 Entry Event";

  ProxyLogArray[51] = "3 Entry date";
  ProxyLogArray[52] = "3 Entry time";
  ProxyLogArray[53] = "3 Entry Event";

  ProxyLogArray[30] = "1/2way date";
  ProxyLogArray[31] = " 1/2way Time";
  ProxyLogArray[32] = "1/2way Event Info";



  ProxyLogArray[3] = "2nd2Last Entry date";
  ProxyLogArray[4] = "2nd2Last Entry time";
  ProxyLogArray[5] = "2nd2Last Entry Event";

  ProxyLogArray[0] = "oldest Entry date";
  ProxyLogArray[1] = "oldest Entry time";
  ProxyLogArray[2] = "oldest Entry Event";

  SetTime();  // sync the clock..
  Serial.println(" Delaying 1 sec before trying clock sync again...");
  delay(1000);
  SetTime();  // sync the clock..
  Serial.println(" completed 2nd clock sync ..");
  // Load root certificate in DER format into WiFiClientSecure object
  bool res = 0;  //client.setCACert_P(caCert, caCertLen);
                 //if (!res) {
  Serial.println("Failed to load root CA certificate!");
  // while (true) {
  //  yield();
  // }
  //  Serial.println("root CA certificate loaded");
  //}

  // Populate " - " in all Proxy log slots

  Serial.println("populating array with - ");

  for (ProxyLogArrayIndex = 0; ProxyLogArrayIndex < 57; ProxyLogArrayIndex = ProxyLogArrayIndex + 1) {

    ProxyLogArray[ProxyLogArrayIndex] = " - ";
  }

  // Save reboot date/time
  LastRebootDate = (String(currentday) + " / " + String(currentmonth));
  LastRebootTime = (String(currenthours) + ":" + String(currentminutes) + ":" + String(currentseconds));

  // Insert reboot time as first event in event table
  Serial.println("populating array with boot time");
  ProxyLogArray[57] = (String(currentday) + " / " + String(currentmonth));
  ProxyLogArray[58] = (String(currenthours) + ":" + String(currentminutes) + ":" + String(currentseconds));
  ProxyLogArray[59] = "Restarted";

  // Rotate WDFailLog towards index 0 each log entry is 3 entries

  for (ProxyLogArrayIndex = 0; ProxyLogArrayIndex < 30; ProxyLogArrayIndex = ProxyLogArrayIndex + 1) {

    ProxyLogArray[ProxyLogArrayIndex] = ProxyLogArray[(ProxyLogArrayIndex + 3)];
  }

  // BLUETOOTH SECTION


  BLEDevice::init("SecurityGateway");
  pBLEScan = BLEDevice::getScan();
  pBLEScan->setAdvertisedDeviceCallbacks(new MyAdvertisedDeviceCallbacks());
  pBLEScan->setActiveScan(true);
  pBLEScan->setInterval(100);
  pBLEScan->setWindow(99);

  server.on("/", handleRoot);  // Tells the ESP32 to run handleRoot when someone visits
  server.on("/RTCReSync", handleRTCReSync);
  server.on("/Reboot", handleReboot);
  server.on("/ProxyLog2", handleProxyLog2);
  server.on("/H", handleLedOn);
  server.on("/L", handleLedOff);
  server.on("/SET", handleSet);
  server.on("/UNSET", handleUnSet);
  server.on("/setRadioParams", handleRadioParams);

  server.begin();

  Serial.println("end of void setup... Delaying 1 sec...");
  delay(1000);

}  // end of void setup


void loop() {

  if (WiFi.status() != WL_CONNECTED) {
    delay(1);
    connectWifi();
    return;
  }

  Sec27ASetState = digitalRead(SetUnsetInputPin);  //
  delay(100);
  if (Sec27ASetState == LOW) {
    if (PrevSec27ASetState == HIGH) {
      Serial.println("27a security has just entered Set State");
      VBNumber = 02;  // 27a Security Set code
      VBNumberString = "02";
      ProxyPost();
      ProxyRequestText = "Alarm is Set";
      RotateProxyLogArray();
    }
  }


  if (Sec27ASetState == HIGH) {
    if (PrevSec27ASetState == LOW) {
      Serial.println("27a security has just entered Unset State ");
      VBNumber = 03;  // 27a Security Unset code
      VBNumberString = "03";
      ProxyPost();
      ProxyRequestText = "Alarm is UnSet";
      RotateProxyLogArray();
    }
  }


  Sec27ASoundingState = !digitalRead(AlarmSoundingInputPin);  // Used for Detecting the Alarm sounding
  delay(100);
  if (Sec27ASoundingState == LOW) {
    if (PrevSec27ASoundingState == HIGH) {
      Serial.println("27a security  has just gone into the alarm sounding state ");
      VBNumber = 04;  // 27a Security Sounding code
      VBNumberString = "04";
      ProxyPost();
      ProxyRequestText = "Alarm is Sounding";
      RotateProxyLogArray();
    }
  }


  if (Sec27ASoundingState == HIGH) {
    if (PrevSec27ASoundingState == LOW) {
      Serial.println("27a security has just stopped sounding ");
      ProxyRequestText = "Alarm has stopped Sounding";
      RotateProxyLogArray();
    }
  }

  PrevSec27ASoundingState = Sec27ASoundingState;  // remember prev state for next pass
  PrevSec27ASetState = Sec27ASetState;            // edge detection of Burglar Alarm state

  if (wifiConnected) {
    // digitalWrite(LedPin, LOW); // turn on LED with voltage Low
    upnpBroadcastResponder.serverLoop();

    Sec27APanic->serverLoop();
    Sec27AUnset->serverLoop();
    Sec27ASet->serverLoop();
  }

  WatchDogLoopCounter = WatchDogLoopCounter + 1;
  //Serial.println(WatchDogLoopCounter);
  if (WatchDogLoopCounter > WatchDogCounterLoopThreshold) {
    //PanelBuzzerCount = (PanelBuzzerCountThreshold - 4);
    WatchDogLoopCounter = 0;
    VBNumber = 40;  // 27A security watchdog code
    WatchDogPost();
  }



  //Keep time
  if (millis() >= (previousMillis)) {
    //Serial.print(" millis = ");

    previousMillis = previousMillis + 1000;
    //Serial.print(" prevmillis = ");
    //Serial.print(String (previousMillis));
    // should be here every second...

    // Maintain RTC

    currentseconds = currentseconds + 1;
    if (currentseconds == 60) {
      // Things to do every second here
      currentseconds = 0;
      currentminutes = currentminutes + 1;
      //Serial.println("another minute has passed");
    }
    if (currentminutes == 60) {


      // Things to do every hour here
      currentminutes = 0;
      currenthours = currenthours + 1;
      UpTimeDays = UpTimeDays + 0.0417;  // (1/24)
                                         //Serial.println("UpTimeDays =  " + String(UpTimeDays) );
    }
    if (currenthours == 24) {
      // Things to do every day here
      currentseconds = 0;
      currentminutes = 0;
      currenthours = 0;
      ProxyRequestText = "Midnight Rollover";
      RotateProxyLogArray();
      //SetTime();  // resync the clock


      //UpTimeDays = UpTimeDays + 0.5; IDK why but it sometimes counts 2X at this point
    }

    //Detect 09:45 and resync the RTC
    if (currenthours == 9) {
      if (currentminutes == 45) {
        if (currentseconds == 0) {

          ProxyRequestText = "Its 09:45, as good time as any to resync";
          RotateProxyLogArray();
          SetTime();           // resync the clock
          currentseconds = 1;  //make sure this only runs once
        }
      }
    }

  }  // end 1 second


  // Check if the AlarmSetLockout needs to be released

  if (AlarmSetLockout == HIGH) {  // lockout is active
    AlarmSetLockoutCounter = AlarmSetLockoutCounter + 1;
    Serial.println(AlarmSetLockoutCounter);
    if (AlarmSetLockoutCounter > AlarmSetLockoutCounterThreshold) {  // its time to release lockout
      AlarmSetLockout = LOW;                                         // reset the lockout for the turn on function
      AlarmSetLockoutCounter = 0;                                    //Dump for next time
    }
  }


  server.handleClient();  // Processes web requests in milliseconds

  /*
// --- HIGH-RELIABILITY NON-BLOCKING SNAPSHOT ENGINE ---
  static unsigned long lastBleCycle = 0;
  static bool scanTriggered = false;
  unsigned long currentMillis = millis();

  // Step A: Kick off a fresh 3-second background scan at the 3-second mark
  if (currentMillis - lastBleCycle > 3000 && !scanTriggered) {
    // Hard reset the chip's internal hardware duplicate filters
    pBLEScan->clearResults(); 
    
    // Scan for 3 seconds, use no completion callback, set continue to false
    pBLEScan->start(3, nullptr, false); 
    
    scanTriggered = true;
  }

// Step B: The 6-second printing and maintenance boundary
  if (currentMillis - lastBleCycle > 6000) {
    scanTriggered = false; // Release trigger for the next round

    Serial.println("\n--- Active BLE Tokens In Range ---");
    int activeCount = 0;

    for (int i = 0; i < deviceCount; i++) {
      // Check if the token was detected within a safe 60-second window
      if (currentMillis - discoveredDevices[i].lastSeen < 60000) {
        Serial.print("MAC: ");
        Serial.print(discoveredDevices[i].macAddress);
        Serial.print(" [");
        Serial.print(discoveredDevices[i].deviceType);
        Serial.print("] | RSSI: ");
        Serial.print(discoveredDevices[i].rssi);
        Serial.print(" dBm | ");

        // Calculate Last Seen timing
        unsigned long lastSeenSec = (currentMillis - discoveredDevices[i].lastSeen) / 1000;
        Serial.print("Last seen: ");
        Serial.print(lastSeenSec);
        Serial.print("s ago | ");

        // NEW: Uncapped Exact Duration tracking (Minutes and Seconds breakdown)
        unsigned long totalTimeSec = (currentMillis - discoveredDevices[i].firstSeen) / 1000;
        unsigned long mins = totalTimeSec / 60;
        unsigned long secs = totalTimeSec % 60;
        
        Serial.print("Duration: ");
        if (mins > 0) {
          Serial.print(mins);
          Serial.print("m ");
        }
        Serial.print(secs);
        Serial.println("s in range");

        activeCount++;
      }
    }

    if (activeCount == 0) {
      Serial.println("No active beacons nearby.");
    }
    Serial.println("----------------------------------");

    lastBleCycle = currentMillis;
  }
*/

  /*

// --- DYNAMIC SLIDER-CONTROLLED BACKGROUND ENGINE ---
  static unsigned long lastBleCycle = 0;
  static bool scanTriggered = false;
  unsigned long currentMillis = millis();

  // Dynamically calculate our timing intervals based on your slider choice
  unsigned long scanMs = (unsigned long)scanSliceDuration * 1000;
  unsigned long totalCycleMs = scanMs * 2; // Keeps the pause window equal to scan window

  // Step A: Kick off a fresh background scan based on your slider length
  if (currentMillis - lastBleCycle > scanMs && !scanTriggered) {
    pBLEScan->clearResults(); // Reset hardware cache
    
    // Scan asynchronously for the exact duration chosen on the web page slider
    pBLEScan->start(scanSliceDuration, nullptr, false); 
    scanTriggered = true;
  }

  // Step B: Printing and table lifecycle boundary
  if (currentMillis - lastBleCycle > totalCycleMs) {
    scanTriggered = false; // Release trigger for the next round
    
    // ... Your standard table printing / loop reporting lines go here exactly as before ...

        Serial.println("\n--- Active BLE Tokens In Range ---");
    int activeCount = 0;

    for (int i = 0; i < deviceCount; i++) {
      // Check if the token was detected within a safe 60-second window
      if (currentMillis - discoveredDevices[i].lastSeen < 60000) {
        Serial.print("MAC: ");
        Serial.print(discoveredDevices[i].macAddress);
        Serial.print(" [");
        Serial.print(discoveredDevices[i].deviceType);
        Serial.print("] | RSSI: ");
        Serial.print(discoveredDevices[i].rssi);
        Serial.print(" dBm | ");

        // Calculate Last Seen timing
        unsigned long lastSeenSec = (currentMillis - discoveredDevices[i].lastSeen) / 1000;
        Serial.print("Last seen: ");
        Serial.print(lastSeenSec);
        Serial.print("s ago | ");

        // NEW: Uncapped Exact Duration tracking (Minutes and Seconds breakdown)
        unsigned long totalTimeSec = (currentMillis - discoveredDevices[i].firstSeen) / 1000;
        unsigned long mins = totalTimeSec / 60;
        unsigned long secs = totalTimeSec % 60;
        
        Serial.print("Duration: ");
        if (mins > 0) {
          Serial.print(mins);
          Serial.print("m ");
        }
        Serial.print(secs);
        Serial.println("s in range");

        activeCount++;
      }
    }

    if (activeCount == 0) {
      Serial.println("No active beacons nearby.");
    }
    Serial.println("----------------------------------");

    lastBleCycle = currentMillis;
  }

*/

  // --- DYNAMIC SLIDER-CONTROLLED BACKGROUND ENGINE WITH LIVE CLEANUP ---
  static unsigned long lastBleCycle = 0;
  static bool scanTriggered = false;
  unsigned long currentMillis = millis();

  // Calculate timing intervals dynamically based on your web slider choice
  unsigned long scanMs = (unsigned long)scanSliceDuration * 1000;
  unsigned long totalCycleMs = scanMs * 2;

  // Step A: Kick off a fresh background scan based on your slider length
  if (currentMillis - lastBleCycle > scanMs && !scanTriggered) {
    pBLEScan->clearResults();  // Reset hardware cache

    // Scan asynchronously for the duration chosen on the web page slider
    pBLEScan->start(scanSliceDuration, nullptr, false);
    scanTriggered = true;
  }

  // Step B: Dynamic Printing, Maintenance & Storage Cleanup Boundary
  if (currentMillis - lastBleCycle > totalCycleMs) {
    scanTriggered = false;  // Release trigger for the next round

    // ... Keep your existing Serial reporting table lines here exactly as they are ...

    Serial.println("\n--- Active BLE Tokens In Range ---");
    int activeCount = 0;

    for (int i = 0; i < deviceCount; i++) {
      // Check if the token was detected within a safe 60-second window
      if (currentMillis - discoveredDevices[i].lastSeen < 60000) {
        Serial.print("MAC: ");
        Serial.print(discoveredDevices[i].macAddress);
        Serial.print(" [");
        Serial.print(discoveredDevices[i].deviceType);
        Serial.print("] | RSSI: ");
        Serial.print(discoveredDevices[i].rssi);
        Serial.print(" dBm | ");

        // Calculate Last Seen timing
        unsigned long lastSeenSec = (currentMillis - discoveredDevices[i].lastSeen) / 1000;
        Serial.print("Last seen: ");
        Serial.print(lastSeenSec);
        Serial.print("s ago | ");

        // NEW: Uncapped Exact Duration tracking (Minutes and Seconds breakdown)
        unsigned long totalTimeSec = (currentMillis - discoveredDevices[i].firstSeen) / 1000;
        unsigned long mins = totalTimeSec / 60;
        unsigned long secs = totalTimeSec % 60;

        Serial.print("Duration: ");
        if (mins > 0) {
          Serial.print(mins);
          Serial.print("m ");
        }
        Serial.print(secs);
        Serial.println("s in range");

        activeCount++;
      }
    }

    if (activeCount == 0) {
      Serial.println("No active beacons nearby.");
    }
    Serial.println("----------------------------------");


    // --- NEW: AUTOMATED ACTIVE BUFFER MANAGEMENT ---
    // Cleans out expired slots dynamically to keep your 20-device space open
    unsigned long maxAllowedAgeMs = (unsigned long)presenceWindowSeconds * 1000;

    for (int i = deviceCount - 1; i >= 0; i--) {
      unsigned long elementAgeMs = currentMillis - discoveredDevices[i].lastSeen;

      if (elementAgeMs >= maxAllowedAgeMs) {
        // Shift remaining array slots left to overwrite the expired device entry
        for (int j = i; j < deviceCount - 1; j++) {
          discoveredDevices[j] = discoveredDevices[j + 1];
        }
        deviceCount--;  // Free up a slot for the next scan cycle
      }
    }

    lastBleCycle = currentMillis;
  }

}  // end Void Loop


void handleRoot() {

  Serial.println("New Client in handleRoot.");  // print a message out in the serial port




  //Serial.print("Incoming Request URI: ");
  //Serial.println(request->url());  Compilation error: 'request' was not declared in this scope

  //Serial.print("Host Header Data: ");
  //Serial.println(request->hostHeader());

  /* Serial.print("Checking 'key' argument: ");
if (request->hasArg("key")) {
  Serial.println(request->arg("key"));
} else {
  Serial.println("No 'key' argument found in URL");
}
*/

  // Start building your HTML response string
  // --- START OF HTML WEB PAGE ---
  String html = "<!DOCTYPE html><html>";

  html += "<head><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">";
  html += "<link rel=\"icon\" href=\"data:,\">";

  // Auto-refresh the page every 5 seconds to keep the BT list live
  html += "<meta http-equiv='refresh' content='5'>";

  // Simple CSS styling for mobile-responsiveness
  html += "<style>html { font-family: Helvetica; display: inline-block; margin: 0px auto; text-align: center;}";
  html += ".button { background-color: #4CAF50; border: none; color: white; padding: 16px 40px;";
  html += "text-decoration: none; font-size: 30px; margin: 2px; cursor: pointer;}";
  html += ".button2 {background-color: #555555;}</style></head>";

  // Web Page Heading
  html += "<body><h1>27A Security Interface Log</h1>";

  // Display date
  html += "<p>Current Date is " + String(currentday) + " / " + String(currentmonth) + "</p>";

  // Display current time of day
  html += "<p>Current Time is " + String(currenthours) + ":" + String(currentminutes) + ":" + String(currentseconds) + ":" + "</p>";

  // Display last Reboot Time
  html += "<p>Last Restart was " + LastRebootTime + " on " + LastRebootDate + " which was " + String(UpTimeDays) + " days ago" + "</p>";

  // Display current state, and show ON/OFF buttons
  html += "<p>LED Status: <strong>" + ledState + "</strong></p>";
  if (ledState == "OFF") {
    html += "<p><a href=\"/H\"><button class=\"button\">TURN ON</button></a></p>";

  } else {
    html += "<p><a href=\"/L\"><button class=\"button button2\">TURN OFF</button></a></p>";
  }

  //Display Alarm set/Unset State

  if (Sec27ASetState == HIGH) {  // High is alarm unset state
    html += "<p>Alarm Panel Status: <strong> UNSET (disabled/off) </strong></p>";
    html += "<p><a href=\"/SET\"><button class=\"button\">SET Alarm</button></a></p>";

  } else {
    html += "<p>Alarm Panel Status: <strong> SET (enabled/on) </strong></p>";
    html += "<p><a href=\"UNSET\"><button class=\"button button2\">UnSET Alarm</button></a></p>";
  }
  /* old (big form)
// --- ADD RSSI THRESHOLD CONTROLLER FORM ---
html += "<div style='text-align: center; margin: 20px auto; padding: 15px; width: 80%; max-width: 500px; border: 1px solid #ccc; border-radius: 8px;'>";
html += "<h4>Adjust Filter Sensitivity</h4>";
html += "<form action='/setRSSI' method='GET'>";
html += "  <p>Current Threshold: <b>" + String(rssiThreshold) + " dBm</b></p>";
html += "  <input type='range' name='value' min='-100' max='-10' step='1' value='" + String(rssiThreshold) + "' style='width: 80%;'>";
html += "  <br><br>";
html += "  <input type='submit' class='buttonsmall' value='Apply Changes'>";
html += "</form>";
html += "</div>";
*/

  // --- STREAMLINED FILTER CONTROLLER BOX ---
  html += "<div style='text-align: center; margin: 10px auto; padding: 10px; width: 90%; max-width: 380px; border: 1px solid #bbb; border-radius: 6px; font-size: 0.9em; background-color: #f9f9f9;'>";
  html += "  <h5 style='margin: 0 0 8px 0;'>Radio & Filter Tweaks</h5>";
  html += "  <form action='/setRadioParams' method='GET'>";

  // Slider 1: RSSI Sensitivity
  html += "    <div style='margin-bottom: 6px;'>";
  html += "      <label style='display:block; margin-bottom:2px;'>RSSI Gate: <b>" + String(rssiThreshold) + " dBm</b></label>";
  html += "      <input type='range' name='rssi' min='-100' max='-10' step='1' value='" + String(rssiThreshold) + "' style='width: 85; height: 4px;'>";
  html += "    </div>";

  // Slider 2: Detection Window Timeout
  html += "    <div style='margin-bottom: 6px;'>";
  html += "      <label style='display:block; margin-bottom:2px;'>Keep-Alive Window: <b>" + String(presenceWindowSeconds) + "s</b></label>";
  html += "      <input type='range' name='window' min='10' max='300' step='5' value='" + String(presenceWindowSeconds) + "' style='width: 85%; height: 4px;'>";
  html += "    </div>";

  // Slider 3: NEW Scan Slice Duration
  html += "    <div style='margin-bottom: 10px;'>";
  html += "      <label style='display:block; margin-bottom:2px;'>Scan Slice: <b>" + String(scanSliceDuration) + "s</b></label>";
  html += "      <input type='range' name='scantime' min='1' max='10' step='1' value='" + String(scanSliceDuration) + "' style='width: 85%; height: 4px;'>";
  html += "    </div>";

  html += "    <input type='submit' class='buttonsmall' style='padding: 4px 10px; font-size: 0.85em;' value='Apply Changes'>";
  html += "  </form>";
  html += "</div>";

  /*

// --- TABLE HEADERS ---
  html += "<h3>Active Bluetooth Tokens (RSSI > " + String(rssiThreshold) + " dBm)</h3>";
  html += "<table border='1' align='center' style='margin-bottom: 20px; width: 95%; max-width: 650px;'>";
  html += "<tr><th>MAC Address</th><th>Device Info</th><th>RSSI</th><th>Last Seen</th><th>Total Duration</th></tr>";

 unsigned long currentMillis = millis();
  int count = 0;

// --- ROW INJECTION LOOP WITH FIND MY FINGERPRINT DISPLAY ---
  for (int i = 0; i < deviceCount; i++) {
    if (currentMillis - discoveredDevices[i].lastSeen < ((unsigned long)presenceWindowSeconds * 1000)) {
      html += "<tr><td><code>" + discoveredDevices[i].macAddress + "</code></td>";
      
      // NEW: If it's a Find My tag, print its type AND its permanent blue tracking key right below it
      if (discoveredDevices[i].findMyFingerprint != "") {
        html += "<td><b>" + discoveredDevices[i].deviceType + "</b><br><small style='color:blue;'>Key: " + discoveredDevices[i].findMyFingerprint + "</small></td>";
      } else {
        html += "<td>" + discoveredDevices[i].deviceType + "</td>";
      }
      
      html += "<td>" + String(discoveredDevices[i].rssi) + " dBm</td>";

      unsigned long lastSeenSec = (currentMillis - discoveredDevices[i].lastSeen) / 1000;
      html += "<td>" + String(lastSeenSec) + "s ago</td>";

      unsigned long totalTimeSec = (currentMillis - discoveredDevices[i].firstSeen) / 1000;
      unsigned long mins = totalTimeSec / 60;
      unsigned long secs = totalTimeSec % 60;
      
      html += "<td>";
      if (mins > 0) { html += String(mins) + "m "; }
      html += String(secs) + "s in range</td></tr>";

      count++;
    }
  }

  if (count == 0) {
    html += "<tr><td colspan='5' style='color: red;'>No authorized tokens in range.</td></tr>";
  }
  html += "</table>";

*/

  // ==========================================
  //  SORT DEVICES BY RSSI (Strongest First)
  // ==========================================
  for (int i = 0; i < deviceCount - 1; i++) {
    for (int j = 0; j < deviceCount - i - 1; j++) {
      // If the next device has a stronger/higher RSSI, swap them
      if (discoveredDevices[j].rssi < discoveredDevices[j + 1].rssi) {
        auto temp = discoveredDevices[j];
        discoveredDevices[j] = discoveredDevices[j + 1];
        discoveredDevices[j + 1] = temp;
      }
    }
  }

  // --- TABLE HEADERS ---
  html += "<h3>Active Bluetooth Tokens (RSSI > " + String(rssiThreshold) + " dBm)</h3>";
  html += "<table border='1' align='center' style='margin-bottom: 20px; width: 95%; max-width: 650px;'>";
  html += "<tr><th>MAC Address</th><th>Device Info</th><th>RSSI</th><th>Last Seen</th><th>Total Duration</th></tr>";

  unsigned long currentMillis = millis();
  int count = 0;

  // --- ROW INJECTION LOOP WITH FIND MY FINGERPRINT DISPLAY ---
  for (int i = 0; i < deviceCount; i++) {
    if (currentMillis - discoveredDevices[i].lastSeen < ((unsigned long)presenceWindowSeconds * 1000)) {
      html += "<tr><td><code>" + discoveredDevices[i].macAddress + "</code></td>";

      // NEW: If it's a Find My tag, print its type AND its permanent blue tracking key right below it
      if (discoveredDevices[i].findMyFingerprint != "") {
        html += "<td><b>" + discoveredDevices[i].deviceType + "</b><br><small style='color:blue;'>Key: " + discoveredDevices[i].findMyFingerprint + "</small></td>";
      } else {
        html += "<td>" + discoveredDevices[i].deviceType + "</td>";
      }

      html += "<td>" + String(discoveredDevices[i].rssi) + " dBm</td>";

      unsigned long lastSeenSec = (currentMillis - discoveredDevices[i].lastSeen) / 1000;
      html += "<td>" + String(lastSeenSec) + "s ago</td>";

      unsigned long totalTimeSec = (currentMillis - discoveredDevices[i].firstSeen) / 1000;
      unsigned long mins = totalTimeSec / 60;
      unsigned long secs = totalTimeSec % 60;

      html += "<td>";
      if (mins > 0) { html += String(mins) + "m "; }
      html += String(secs) + "s in range</td></tr>";

      count++;
    }
  }

  if (count == 0) {
    html += "<tr><td colspan='5' style='color: red;'>No authorized tokens in range.</td></tr>";
  }
  html += "</table>";

  //Serial.println("about to write headers .");
  // 1. Explicitly display the table headers from your dedicated slots (60, 61, 62)
  html += "<h3>" + ProxyLogArray[60] + " &nbsp;&nbsp;&nbsp; " + ProxyLogArray[61] + " &nbsp;&nbsp;&nbsp; " + ProxyLogArray[62] + "</h3>";
  //Serial.println("headers written.");
  // 2. Display event logs (Indices 57 down to 0)
  // Starts precisely at 57 (the newest event date entry)
  for (ProxyLogArrayIndex = 57; ProxyLogArrayIndex >= 0; ProxyLogArrayIndex = ProxyLogArrayIndex - 3) {

    // Safely grab the 3 pieces of data without overshooting index 59
    String entryDate = ProxyLogArray[ProxyLogArrayIndex];
    String entryTime = ProxyLogArray[ProxyLogArrayIndex + 1];
    String entryEvent = ProxyLogArray[ProxyLogArrayIndex + 2];
    //Serial.println("collected arraydata.");
    // Only print the line if it actually contains a log entry
    if (entryDate.length() > 0 || entryEvent.length() > 0) {
      html += "<p>" + entryDate + " &nbsp;&nbsp;&nbsp;&nbsp; " + entryTime + " &nbsp;&nbsp;&nbsp;&nbsp; " + entryEvent + "</p>";
    }
  }
  //Serial.println("Completed logging html.");

  //Display Clock Resync, Spare1 Buttons, Spare2 Button
  html += "<p><a href=\"/RTCReSync\"><button class=\"buttonsmall\">RTC ReSync</button></a> <a href=\"/Reboot\"><button class=\"buttonsmall\">Reboot</button></a> <a href=\"/ProxyLog2\"> <button class=\"buttonsmall\">Spare2</button></a></p>";



  html += "</body></html>";


  // --- END OF HTML WEB PAGE ---

  // Instantly send the full page text to the browser non-blockingly
  server.send(200, "text/html", html);


}  // end of handleroot




bool Sec27ASetOn() {
  Serial.println("Request to Set Burglar Alarm received SW #1 On...");

  ProxyRequestText = "Alexa or Local Web Set Request";
  RotateProxyLogArray();

  if (Sec27ASetState == HIGH) {  // only pulse relay if Burglar Alarm is currently Unset
    //sometimes alexa sends this request again about 2 secs later which turned the alarm off again on the second request
    // we need to lockout multiple turn on requests that are received in quick succession
    // or maybe, just extend the pulse duration ? (was 1 sec) - didnt work...
    if (AlarmSetLockout == LOW) {  // only allows set routine to run once, initally needed the alarm off request to release this
      // but this gave rise to problems if the alarm was set via alexa and reset via keypads or RF remote.
      // changed to reset automatically after 5 secs

      Serial.println("Burglar Alarm is Unset - pulsing relay to Set it");
      AlarmSetLockout = HIGH;  // set the lockout

      Serial.println("XXX Pulsing Relay on ...");

      // Turn on #1 Relay
      delay(10);
      Serial.write(rel1ON, sizeof(rel1ON));
      delay(10);
      Serial.println("Turning Relay#1 On ...");
      ProxyRequestText = "Set Request Honored";
      RotateProxyLogArray();

      // Turn on #1 Relay
      delay(10);
      Serial.write(rel1ON, sizeof(rel1ON));
      delay(10);
      Serial.println("Turning Relay#1 On ...");

      delay(1500);
      ;

      Serial.println("XXX Pulsing Relay off again ...");  // this makes a pulse which is what the security system wants

      // Turn off #1 Relay
      delay(10);
      Serial.write(rel1OFF, sizeof(rel1OFF));
      delay(10);
      Serial.println("Turning Relay#1 Off ...");
      //ProxyRequestText = "Relay 1 pulsing off - set";
      //RotateProxyLogArray();

      // Turn off #1 Relay
      delay(10);
      Serial.write(rel1OFF, sizeof(rel1OFF));
      delay(10);
      Serial.println("Turning Relay#1 Off ...");
    }
  } else {
    Serial.println("27A Security is already Set - not pulsing relay!");
    ProxyRequestText = "Set Request NOT Honored, already set";
    RotateProxyLogArray();
  }

  isSec27ASetOn = false;
  return Sec27ASetState;
}

bool Sec27ASetOff() {

  Serial.println("Request to Set 27A Security received SW#1 Off ...");
  Serial.println("This should never happen");

  isSec27ASetOn = false;
  return Sec27ASetState;
}

bool Sec27AUnsetOn() {
  Serial.println("Request to Unset 27A Security received SW#2 On");
  ProxyRequestText = "Alexa or Local Web Unset Request";
  RotateProxyLogArray();

  if (Sec27ASetState == LOW) {  // only pulse relay if Burglar Alarm is currently Set
    Serial.println("XXX Pulsing Relay on ...");
    // AlarmSetLockout = LOW; // reset the lockout for the turn on function
    // this in asymetric and doesnt have a lockout for preventing multiple offs like the on function
    // becasue the alarm unsets immediatly and prevents any subsequent requests from alexa as being
    // processed as on commands.
    // I think.

    // Turn on #1 Relay
    delay(10);
    Serial.write(rel1ON, sizeof(rel1ON));
    delay(10);
    Serial.println("Turning Relay#1 On ...");
    ProxyRequestText = "UnSet Request Honored";
    RotateProxyLogArray();

    // Turn on #1 Relay
    delay(10);
    Serial.write(rel1ON, sizeof(rel1ON));
    delay(10);
    Serial.println("Turning Relay#1 On ...");

    delay(1500);  // 1.5 sec pulse
    ;

    Serial.println("XXX Pulsing Relay off again ...");  // this makes a pulse which is what the security system wants

    // Turn off #1 Relay
    delay(10);
    Serial.write(rel1OFF, sizeof(rel1OFF));
    delay(10);
    Serial.println("Turning Relay#1 Off ...");
    //ProxyRequestText = "Pulsing relay 1 off - unset";
    //RotateProxyLogArray();

    // Turn off #1 Relay
    delay(10);
    Serial.write(rel1OFF, sizeof(rel1OFF));
    delay(10);
    Serial.println("Turning Relay#1 Off ...");
  } else {
    Serial.println("27A Security is already Unset, not pulsing relay...");
    ProxyRequestText = "UnSet Request NOT Honored - already Unset";
    RotateProxyLogArray();
  }

  isSec27AUnsetOn = false;
  return Sec27ASetState;
}

bool Sec27AUnsetOff() {

  Serial.println("Request to Unset 27A Security received (SW#2 Off)");
  Serial.println("This should never happen");

  isSec27AUnsetOn = false;
  return Sec27ASetState;
}

bool Sec27APanicOn() {
  Serial.println("Request to set Panic Mode received SW#3 On");
  ProxyRequestText = "Alexa Panic Request";
  RotateProxyLogArray();
  // Turn on #2 Relay
  delay(10);
  Serial.write(rel2ON, sizeof(rel2ON));
  delay(10);
  Serial.println("Turning Relay#2 On ...");
  //ProxyRequestText = "Relay 2 pulsing on - panic";
  //RotateProxyLogArray();

  // Turn on #2 Relay
  delay(10);
  Serial.write(rel2ON, sizeof(rel2ON));
  delay(10);

  delay(1500);  // 1.5 sec pulse

  // Turn off #2 Relay
  delay(10);
  Serial.write(rel2OFF, sizeof(rel2OFF));
  delay(10);
  Serial.println("Turning Relay#2 Off ...");
  //ProxyRequestText = "Relay 2 pulsing off - panic";
  //RotateProxyLogArray();
  // Turn off #2 Relay
  delay(10);
  Serial.write(rel2OFF, sizeof(rel2OFF));
  delay(10);
  Serial.println("Turning Relay#2 Off ...");





  isSec27APanicOn = false;
  return isSec27APanicOn;
}

bool Sec27APanicOff() {

  Serial.println("Request to stop Panic Mode received (SW#3 Off)");
  ProxyRequestText = "Alexa Panic Off Request";
  RotateProxyLogArray();

  // Turn off #2 Relay
  delay(10);
  Serial.write(rel2OFF, sizeof(rel2OFF));
  delay(10);
  Serial.println("Turning Relay#2 Off ...");
  //ProxyRequestText = "Relay 2 pulsing off - panic";
  //RotateProxyLogArray();
  // Turn off #2 Relay
  delay(10);
  Serial.write(rel2OFF, sizeof(rel2OFF));
  delay(10);
  Serial.println("Turning Relay#2 Off ...");


  isSec27APanicOn = false;
  return Sec27ASetState;
}

// connect to wifi – returns true if successful or false if not
boolean connectWifi() {
  boolean state = true;
  int i = 0;

  WiFi.mode(WIFI_STA);


  // Configures static IP address
  if (!WiFi.config(local_IP, gateway, subnet, primaryDNS, secondaryDNS)) {
    Serial.println("STA Failed to configure");
    // this locked in ip address made the clock sync fail untill i added the DNS bits
    // if this is an issue, fix by locking mac address to ip address in the router config instead (not done as at June2026)
  }
  WiFi.begin(ssid, password);
  Serial.println("");
  Serial.println("Connecting to WiFi Network");

  // Wait for connection
  Serial.print("Connecting ...");
  while (WiFi.status() != WL_CONNECTED) {
    delay(5000);
    Serial.print(".");
    if (i > 10) {
      state = false;
      break;
    }
    i++;
  }

  if (state) {
    Serial.println("");
    Serial.print("Connected to ");
    Serial.println(ssid);
    Serial.print("IP address: ");
    Serial.println(WiFi.localIP());
  } else {
    Serial.println("");
    Serial.println("Connection failed. Bugger");
  }

  return state;
}

void ProxyPost() {
  //TwitchLED();
  // assumes VBNumber set to desired VB call to be made

  // 2 is Burglar Alarm has Seted
  // 3 is Burglar Alarm is Unset
  // 4 is Burglar Alarm Sounding
  Serial.print("Requesting POST to Proxy ");
  Serial.println(VBNumberString);

  WiFiClient client;
  const int httpPort = 80;
  if (!client.connect(WatchDogHost, httpPort)) {
    Serial.println("connection failed");
    return;
  }

  String data = "";

  // Send request to the server:
  client.println("POST / HTTP/1.1");
  //Serial.println("VB button"+(String(VBNumber))+" request sent");
  /*
// this gave problems as the data transmitted had no leading zero and the watchdog falsely matched it with values in the 30 range
  client.println("Host: ProxyRequest" + (String(VBNumber)));  // this endpoint value gets to the server and is used to transfer the identity of the calling slave
  Serial.println("Host: ProxyRequest" + (String(VBNumber)));  //
*/
  client.println("Host: ProxyRequest" + VBNumberString);  // this endpoint value gets to the server and is used to transfer the identity of the calling slave
  Serial.println("Host: ProxyRequest" + VBNumberString);  // send to serial port as well
  client.println("Accept: */*");                          // this gets to the server!
  client.println("Content-Type: application/x-www-form-urlencoded");
  client.print("Content-Length: ");
  client.println(data.length());
  client.println();
  client.print(data);

  delay(500);  // Can be changed
  if (client.connected()) {
    client.stop();  // DISCONNECT FROM THE SERVER
  }
  Serial.println();
  Serial.println("closing connection");
  delay(1000);
}  // end ProxyPost

void WatchDogPost() {

  //TwitchLED();

  // assumes VBNumber set to desired VB call to be made
  VBNumber = 40;  // 27A security watchdog code
  // 40 is Burglar Alarm watchdog

  Serial.print("Requesting POST to WatchDog ");
  Serial.println(VBNumber);

  WiFiClient client;
  const int httpPort = 80;
  if (!client.connect(WatchDogHost, httpPort)) {
    Serial.println("connection failed");
    return;
  }

  String data = "";

  // Send request to the server:
  client.println("POST / HTTP/1.1");
  Serial.println("VB button" + (String(VBNumber)) + " request sent");
  client.println("Host: WatchDog Endpoint" + (String(VBNumber)));  // this endpoint value gets to the server and is used to transfer the identity of the calling slave
  client.println("Accept: */*");                                   // this gets to the server!
  client.println("Content-Type: application/x-www-form-urlencoded");
  client.print("Content-Length: ");
  client.println(data.length());
  client.println();
  client.print(data);

  delay(500);  // Can be changed
  if (client.connected()) {
    client.stop();  // DISCONNECT FROM THE SERVER
  }
  Serial.println();
  Serial.println("closing connection");
  delay(1000);
}  // end WatchDogPost

void TwitchLED() {

  pinMode(LedPin, OUTPUT);  // switch to an output

  digitalWrite(LedPin, LOW);
  delay(10);
  digitalWrite(LedPin, HIGH);

  //pinMode(LedPin, INPUT); // switch back to an input
}  // end TwitchLED

void SetTime() {

  // AL Suggestion


  SetTimeWasSuccesfull = 0;

  Serial.println(" trying to synch clock...");
  Serial.println("Setting time using SNTP");
  configTime(-13 * 3600, DSTOffset, "pool.ntp.org", "time.nist.gov");


  time_t now = time(nullptr);
  int SNTPtimeoutCounter = 0;  // 1. Add a counter to track attempts

  // Loop runs while time is invalid AND we haven't hit the 10-second timeout (50 * 200ms)
  while (now < 100 && SNTPtimeoutCounter < 50) {
    delay(200);
    Serial.print(".");
    Serial.print(String(now));
    now = time(nullptr);
    SNTPtimeoutCounter++;  // Increment counter
  }
  Serial.println("");

  // 2. LOG THE FAILURE OR SUCCESS HERE
  if (now < 100) {
    ProxyRequestText = "RTC ReSync FAILED - SNTP Timeout After " + String((SNTPtimeoutCounter) + 1) + " Attempts";
    RotateProxyLogArray();
    Serial.println("Error: Failed to resync time. SNTP timeout reached.");
    SetTimeWasSuccesfull = 0;
  } else {
    Serial.println("Success: Time synchronized successfully!");
    ProxyRequestText = "RTC ReSync Success after " + String((SNTPtimeoutCounter) + 1) + " Attempts";
    RotateProxyLogArray();
    Serial.println("after RotateProxyLog!");
    SetTimeWasSuccesfull = 1;
  }

  struct tm* timeinfo;  //http://www.cplusplus.com/reference/ctime/tm/
  time(&now);
  timeinfo = localtime(&now);
  Serial.println(timeinfo->tm_mon);
  Serial.println(timeinfo->tm_mday);
  Serial.println(timeinfo->tm_hour);
  Serial.println(timeinfo->tm_min);
  Serial.println(timeinfo->tm_sec);
  currentseconds = timeinfo->tm_sec;
  currentminutes = timeinfo->tm_min;
  currenthours = timeinfo->tm_hour;
  currentday = timeinfo->tm_mday;
  currentmonth = timeinfo->tm_mon;
  currentmonth = currentmonth + 1;  // month counted from 0
  currentday = currentday + 1;      // day counted from 0 (I think)
  currenthours = currenthours + 1;  // it was an hour out in testing , might actually be DST issue, IDK

  //ProxyRequestText = "RTC ReSync Success";
  //RotateProxyLogArray();
  Serial.println("end of SetTime!");
}  // End SetTime

void RotateProxyLogArray() {
  //Serial.println("start of RotateProxyLogArray!");

  // Rotates ProxyLogArray[64] one slot to the left (toward index 0)
  // Safely rotates ProxyLogArray[64] three slots to the left
  // Loop stops at 60 so that (60 + 3) equals the maximum index of 63
  // Loop stops at 57. The highest slot read is 57 + 3 = 60.

  for (ProxyLogArrayIndex = 0; ProxyLogArrayIndex < 57; ProxyLogArrayIndex = ProxyLogArrayIndex + 1) {

    ProxyLogArray[ProxyLogArrayIndex] = ProxyLogArray[(ProxyLogArrayIndex + 3)];
  }

  //Serial.println("Rotate complete!");
  //Populate new log entry
  ProxyLogArray[57] = (String(currentday) + " / " + String(currentmonth));
  ProxyLogArray[58] = (String(currenthours) + ":" + String(currentminutes) + ":" + String(currentseconds));
  ProxyLogArray[59] = (String(ProxyRequestText));
  //TwitchLED();
  //Serial.println("end of RotateProxyLog");
}  // end RotateProxyLogArray



void handleRTCReSync() {
  Serial.println("Button Pressed: RTC ReSync triggered!");

  SetTime();

  // Send an HTTP Redirect (303) back to the main page immediately
  server.sendHeader("Location", "/");
  server.send(303, "text/plain", "Redirecting...");
}

void handleReboot() {
  Serial.println("Button Pressed: ESP32 Rebooting in 10 seconds");

  server.send(200, "text/html", "<h2>Device is restarting. Please wait 10 seconds...</h2>");
  delay(1000);
  ESP.restart();  // Software resets the chip
}

void handleProxyLog2() {
  Serial.println("Button Pressed: Spare2/ProxyLog2 triggered!");

  // Put whatever feature you want for the spare button here

  server.sendHeader("Location", "/");
  server.send(303, "text/plain", "Redirecting...");
}

void handleLedOn() {
  Serial.println("Button Pressed: LED On");
  digitalWrite(LedPin, LOW);
  Serial.println("Turning LED On ...");
  ledState = "ON";


  server.sendHeader("Location", "/");
  server.send(303, "text/plain", "Redirecting...");
}

void handleLedOff() {
  Serial.println("Button Pressed: LED Off");

  digitalWrite(LedPin, HIGH);
  Serial.println("Turning LED Off ...");
  ledState = "OFF";

  server.sendHeader("Location", "/");
  server.send(303, "text/plain", "Redirecting...");
}

void handleSet() {
  Serial.println("Button Pressed: Alarm Set");

  Sec27ASetOn();


  server.sendHeader("Location", "/");
  server.send(303, "text/plain", "Redirecting...");
}

void handleUnSet() {
  Serial.println("Button Pressed: Alarm UnSet");

  Sec27AUnsetOn();

  server.sendHeader("Location", "/");
  server.send(303, "text/plain", "Redirecting...");
}
/*
Compilation error: variable or field 'handleSetRSSI' declared void

void handleSetRSSI(AsyncWebServerRequest *request) {
  // Check if the URL string contains the 'value' parameter
  if (request->hasArg("value")) {
    String incomingValue = request->arg("value");
    rssiThreshold = incomingValue.toInt(); // Safely convert to a signed integer
    
    Serial.print("System Setting Updated: New RSSI Threshold is ");
    Serial.print(rssiThreshold);
    Serial.println(" dBm");
  }

  // Redirect back to main menu dashboard instantly
  request->redirect("/");
}
*/
/* old handler for only rssi
void handleSetRSSI() {
  // Check if the URL string contains the 'value' parameter
  if (server.hasArg("value")) {
    String incomingValue = server.arg("value");
    rssiThreshold = incomingValue.toInt(); // Safely convert to a signed integer
    
    Serial.print("System Setting Updated: New RSSI Threshold is ");
    Serial.print(rssiThreshold);
    Serial.println(" dBm");
  }

  // Send an HTTP Redirect (303) back to the main page immediately
  server.sendHeader("Location", "/");
  server.send(303, "text/plain", "Redirecting...");
}
*/

void handleRadioParams() {
  if (server.hasArg("rssi")) rssiThreshold = server.arg("rssi").toInt();
  if (server.hasArg("window")) presenceWindowSeconds = server.arg("window").toInt();
  if (server.hasArg("scantime")) scanSliceDuration = server.arg("scantime").toInt();  // Parse new slider

  Serial.print("Parameters Updated -> Gate: ");
  Serial.print(rssiThreshold);
  Serial.print("dBm | Window: ");
  Serial.print(presenceWindowSeconds);
  Serial.print("s | Scan Slice: ");
  Serial.print(scanSliceDuration);
  Serial.println("s");

  // Send an HTTP Redirect (303) back to dashboard root
  server.sendHeader("Location", "/");
  server.send(303, "text/plain", "Redirecting...");
}
