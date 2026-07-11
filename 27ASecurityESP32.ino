#include <WiFi.h>
#include <WebServer.h>
#include <WiFiUdp.h>
#include <functional>
#include "switch.h"
#include "UpnpBroadcastResponder.h"
#include "CallbackFunction.h"
#include <ESPping.h>
#include <Preferences.h>
Preferences prefs; // Instantiate the permanent storage core instance

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

// Structure for Bluetooth devices
struct TrackedBeacon {
  String macAddress;
  int rssi;
  unsigned long lastSeen;
  unsigned long firstSeen;
  String deviceType;         // <-- Add this to store the name/manufacturer
  String findMyFingerprint;  // <- Holds the fixed unique identifier payload
};

// Structure for Authorised Tokens
struct AuthorisedDevice {
  String macAddress;
  String deviceType;
  String friendlyName;          // 👈 NEW: Customizable friendly alias
  bool hasTrippedGate = false;  // 👈 NEW: Latches the trigger state
};

// --- NEW: IPHONE IP AUTHENTICATION STRUCTURE ---
struct AuthorisedIP {
  uint8_t lastQuad;             // Only storing the 4th quad (0-255)
  String friendlyName;          // "Tony's iPhone"
  unsigned long firstSeen = 0;  // Reset when it joins, tracks fresh arrival
  unsigned long lastSeen = 0;   // Updated on every successful ICMP response
  bool isOnline = false;        // Real-time ping state tracker
  bool hasTrippedGate = false;  // 👈 NEW: Latches the trigger state
};

#define MAX_AUTH_IPS 10
AuthorisedIP authIPs[MAX_AUTH_IPS];
int authIPCount = 0;

// --- MASTER VOICE-GATE AUTHORISATION FLAGS ---
bool securitySystemDisableAuthorised = false;  // The master boolean flag for your Alexa gate
String authorisingDeviceNames = "";            // Holds concatenated names (e.g., "Tony's Phone + Keys")
unsigned long gateActivationTime = 0;          // Tracks exactly when the fresh arrival triggered

// User-adjustable time window that the gate stays OPEN (Default: 60 seconds)
int voiceGateOpenDurationSeconds = 60;

#define MAX_AUTH_DEVICES 10
AuthorisedDevice authDevices[MAX_AUTH_DEVICES];
int authDeviceCount = 0;

const int MAX_DEVICES = 30;
TrackedBeacon discoveredDevices[MAX_DEVICES];
int deviceCount = 0;

// Adjustable 2FA validation window via web interface (Default: 30 seconds)
// Global settings configurations
int authTimeWindowSeconds = 30;
int maxArrivalAgeSeconds = 300;
unsigned long lastPingTime = 0;      // Tracks non-blocking network thread cycles
int networkPingIntervalSeconds = 2;  // 👈 NEW: User-adjustable ping delay (Default: 2s)

// ****** GLOBAL FUNCTIONS & Classes 

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

    /*
    for (int i = 0; i < deviceCount; i++) {
      if ((payloadSignature != "" && discoveredDevices[i].findMyFingerprint == payloadSignature) || (payloadSignature == "" && discoveredDevices[i].macAddress == currentMac)) {

        if (now - discoveredDevices[i].lastSeen > 30000) {
          discoveredDevices[i].firstSeen = now;
        }

        discoveredDevices[i].macAddress = currentMac;
        discoveredDevices[i].rssi = currentRssi;
        discoveredDevices[i].lastSeen = now;


*/
    /*
    for (int i = 0; i < deviceCount; i++) {
      if ((payloadSignature != "" && discoveredDevices[i].findMyFingerprint == payloadSignature) || 
          (payloadSignature == "" && discoveredDevices[i].macAddress == currentMac)) {
        
        // EDGE DETECTION: If it's been gone/unseen for longer than your presence threshold
        if (now - discoveredDevices[i].lastSeen > ((unsigned long)presenceWindowSeconds * 1000)) {
          discoveredDevices[i].firstSeen = now;
          
          // Cross-reference against your authorised list to pull its friendly name
          for(int k=0; k<authDeviceCount; k++) {
            if(authDevices[k].macAddress == currentMac) {
              String nameToLog = authDevices[k].friendlyName == "" ? "Unassigned Tile" : authDevices[k].friendlyName;
              triggerSecurityGate(nameToLog); // Open the Alexa gate!
            }
          }
        }

        discoveredDevices[i].macAddress = currentMac; 
        discoveredDevices[i].rssi = currentRssi;
        discoveredDevices[i].lastSeen = now;
        // ... rest of your tracker updates ...
        discoveredDevices[i].deviceType = manufacturer;
        found = true;
        break;
      }
    }
*/
    /* 
    // ========================================================
    // UPDATED: MASTER TRACKING MEMORY ENGINE WITH MULTI-SOURCE GATE TRIGGER
    // ========================================================
    unsigned long now = millis();
    bool found = false;
    
    for (int i = 0; i < deviceCount; i++) {
      if ((payloadSignature != "" && discoveredDevices[i].findMyFingerprint == payloadSignature) || 
          (payloadSignature == "" && discoveredDevices[i].macAddress == currentMac)) {
        
        // 1. CALCULATE EDGE-DETECTION: Has this token been gone/unseen for a while?
        unsigned long timeSinceLastSeen = now - discoveredDevices[i].lastSeen;
        
        if (timeSinceLastSeen > ((unsigned long)presenceWindowSeconds * 1000)) {
          // It was stale or gone, reset arrival cycle markers
          discoveredDevices[i].firstSeen = now;
          
          // 2. CHECK AUTHORISATION STATUS: Is this newly-returned MAC allowed?
          for (int k = 0; k < authDeviceCount; k++) {
            if (authDevices[k].macAddress == currentMac) {
              String nameToLog = authDevices[k].friendlyName;
              if (nameToLog == "") nameToLog = "Authorized Bluetooth Key";
              
              // ⚡ CRITICAL TRIPPED HANDSHAKE: Open the voice gate!
              triggerSecurityGate(nameToLog); 
            }
          }
        }

        // Keep standard trace trackers updated
        discoveredDevices[i].macAddress = currentMac; 
        discoveredDevices[i].rssi = currentRssi;
        discoveredDevices[i].lastSeen = now;
        discoveredDevices[i].deviceType = manufacturer; 
        found = true;
        break;
      }
    }
*/

    // ========================================================
    // ULTIMATE FIX: MULTI-SOURCE GAP EDGE DETECTION (TILE AND BEACONS)
    // ========================================================
    unsigned long now = millis();
    bool found = false;

    for (int i = 0; i < deviceCount; i++) {
      if ((payloadSignature != "" && discoveredDevices[i].findMyFingerprint == payloadSignature) || (payloadSignature == "" && discoveredDevices[i].macAddress == currentMac)) {

        // 1. CALCULATE SEPARATION GAP: Time elapsed since the ESP32 last processed this token
        unsigned long timeSinceLastSeen = now - discoveredDevices[i].lastSeen;

        // 2. BOOTSTRAP TRIGGER STRATEGY:
        // A) If 'firstSeen' equals 'lastSeen', it means the device has NEVER tripped the gate since boot.
        // B) If 'timeSinceLastSeen' is greater than your window, it has physically arrived from outside.
        bool isBrandNewBootCapture = (discoveredDevices[i].firstSeen == discoveredDevices[i].lastSeen);
        bool isFreshArrivalGapPassed = (timeSinceLastSeen > ((unsigned long)presenceWindowSeconds * 1000));
        /* 
        if (isBrandNewBootCapture || isFreshArrivalGapPassed) {
          // Reset arrival timestamps to frame this fresh session anchor
          discoveredDevices[i].firstSeen = now;
          
          // Cross-reference against your authorized settings list to grab its friendly label
          for (int k = 0; k < authDeviceCount; k++) {
            if (authDevices[k].macAddress == currentMac) {
              String nameToLog = authDevices[k].friendlyName;
              if (nameToLog == "") nameToLog = "Authorized Bluetooth Key";
              
              // ⚡ THE GATE OPENER: Open the voice gate instantly!
              triggerSecurityGate(nameToLog); 
            }
          }
        }
        */
        if (isBrandNewBootCapture || isFreshArrivalGapPassed) {
          discoveredDevices[i].firstSeen = now;

          for (int k = 0; k < authDeviceCount; k++) {
            if (authDevices[k].macAddress == currentMac) {
              // Only open the gate if this specific Tile hasn't locked the latch yet
              if (!authDevices[k].hasTrippedGate) {
                String nameToLog = authDevices[k].friendlyName;
                if (nameToLog == "") nameToLog = "Authorized Bluetooth Key";

                triggerSecurityGate(nameToLog, currentMac);  // 👈 Added currentMac parameter
                authDevices[k].hasTrippedGate = true;        // Lock the latch!
              }
            }
          }
        } else {
          // If the device is continuously sitting here, make sure it stays latched
          for (int k = 0; k < authDeviceCount; k++) {
            if (authDevices[k].macAddress == currentMac) {
              // Leave it locked while it's in range
            }
          }
        }

        // Keep core running metrics updated
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
};  // end of class MyAdvertisedDeviceCallbacks


bool isAuthorisedTokenPresent() {
  unsigned long now = millis();

  for (int i = 0; i < authDeviceCount; i++) {
    for (int j = 0; j < deviceCount; j++) {
      if (discoveredDevices[j].macAddress == authDevices[i].macAddress) {
        unsigned long timeDelta = (now - discoveredDevices[j].lastSeen) / 1000;
        if (timeDelta <= (unsigned long)authTimeWindowSeconds) {
          return true;  // Match found! An authorized physical token is actively inside the room.
        }
      }
    }
  }
  return false;
}

void saveConfigurationToFlash() {
  // Open the "security" flash namespace in Read/Write mode (false)
  prefs.begin("security", false);
  
  // 1. Commit stand-alone configuration adjustments
  prefs.putInt("rssiGate", rssiThreshold);
  prefs.putInt("presenceSec", presenceWindowSeconds);
  prefs.putInt("scanTimeSec", scanSliceDuration);
  prefs.putInt("authWindow", authTimeWindowSeconds);
  prefs.putInt("arrivalLimit", maxArrivalAgeSeconds);
  prefs.putInt("pingInterval", networkPingIntervalSeconds);
  prefs.putInt("gateDuration", voiceGateOpenDurationSeconds);
  
  // 2. Commit tracking counter totals
  prefs.putInt("btCount", authDeviceCount);
  prefs.putInt("ipCount", authIPCount);
  
  // 3. Commit authorized Bluetooth structural items
  for (int i = 0; i < authDeviceCount; i++) {
    prefs.putString(("btMac" + String(i)).c_str(), authDevices[i].macAddress);
    prefs.putString(("btType" + String(i)).c_str(), authDevices[i].deviceType);
    prefs.putString(("btName" + String(i)).c_str(), authDevices[i].friendlyName);
  }
  
  // 4. Commit authorized iPhone network configurations
  for (int i = 0; i < authIPCount; i++) {
    prefs.putUChar(("ipQuad" + String(i)).c_str(), authIPs[i].lastQuad);
    prefs.putString(("ipName" + String(i)).c_str(), authIPs[i].friendlyName);
  }
  
  prefs.end(); // Lock and close the storage container safely
  Serial.println("💾 SUCCESS: All user configurations backed up to Non-Volatile Flash.");
}

void loadConfigurationFromFlash() {
  // Open the "security" flash namespace in Read-Only mode (true)
  prefs.begin("security", true);
  
  // 1. Load parameters, defaulting to your current values if flash is empty
  rssiThreshold = prefs.getInt("rssiGate", -90);
  presenceWindowSeconds = prefs.getInt("presenceSec", 60);
  scanSliceDuration = prefs.getInt("scanTimeSec", 3);
  authTimeWindowSeconds = prefs.getInt("authWindow", 30);
  maxArrivalAgeSeconds = prefs.getInt("arrivalLimit", 300);
  networkPingIntervalSeconds = prefs.getInt("pingInterval", 2);
  voiceGateOpenDurationSeconds = prefs.getInt("gateDuration", 60);
  
  // 2. Load total database counts
  authDeviceCount = prefs.getInt("btCount", 0);
  authIPCount = prefs.getInt("ipCount", 0);
  
  // 3. Rebuild Authorized Bluetooth storage slots
  for (int i = 0; i < authDeviceCount; i++) {
    authDevices[i].macAddress = prefs.getString(("btMac" + String(i)).c_str(), "");
    authDevices[i].deviceType = prefs.getString(("btType" + String(i)).c_str(), "");
    authDevices[i].friendlyName = prefs.getString(("btName" + String(i)).c_str(), "");
    authDevices[i].hasTrippedGate = false; // Fresh initialization setup
  }
  
  // 4. Rebuild Authorized IP Network targets
  for (int i = 0; i < authIPCount; i++) {
    authIPs[i].lastQuad = prefs.getUChar(("ipQuad" + String(i)).c_str(), 0);
    authIPs[i].friendlyName = prefs.getString(("ipName" + String(i)).c_str(), "");
    authIPs[i].isOnline = false;
    authIPs[i].hasTrippedGate = false;
    authIPs[i].firstSeen = 0;
    authIPs[i].lastSeen = 0;
  }
  
  prefs.end();
  Serial.println("🔄 SUCCESS: Authorization databases recovered from onboard Flash.");
}




// original security system interface code  here 

boolean connectWifi();  // router handed out 192.168.1.169 for this initially at 27A

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

  loadConfigurationFromFlash();

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
  // server.begin();
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

  //server.on("/", handleRoot);  // Tells the ESP32 to run handleRoot when someone visits
  server.on("/RTCReSync", handleRTCReSync);
  server.on("/Reboot", handleReboot);
  server.on("/ProxyLog2", handleProxyLog2);
  /*
  server.on("/H", handleLedOn);
  server.on("/L", handleLedOff);
  */
  server.on("/SET", handleSet);
  server.on("/UNSET", handleUnSet);

  server.on("/setRadioParams", handleRadioParams);

/*
start of old route block
  // Route to Authorise a device
  server.on("/authorise", []() {
    String mac = server.arg("mac");
    String type = server.arg("type");
    mac.toUpperCase();

    // Check if already authorised or if array is full
    bool exists = false;
    for (int i = 0; i < authDeviceCount; i++) {
      if (authDevices[i].macAddress == mac) exists = true;
    }

    if (!exists && authDeviceCount < MAX_AUTH_DEVICES && mac != "") {
      authDevices[authDeviceCount].macAddress = mac;
      authDevices[authDeviceCount].deviceType = type;
      authDeviceCount++;
    }
    // Redirect back to main page immediately
    server.sendHeader("Location", "/");
    server.send(303);
  });

  // Route to Deauthorise a device
  server.on("/deauthorise", []() {
    String mac = server.arg("mac");
    mac.toUpperCase();

    // Search array and shift items left to remove it cleanly
    for (int i = 0; i < authDeviceCount; i++) {
      if (authDevices[i].macAddress == mac) {
        for (int j = i; j < authDeviceCount - 1; j++) {
          authDevices[j] = authDevices[j + 1];
        }
        authDeviceCount--;
        break;
      }
    }
    server.sendHeader("Location", "/");
    server.send(303);
  });

  // Route to Save the Adjustable Time Window form field
  server.on("/save-settings", []() {
    if (server.hasArg("window")) {
      authTimeWindowSeconds = server.arg("window").toInt();
    }
    if (server.hasArg("arrival_limit")) {
      maxArrivalAgeSeconds = server.arg("arrival_limit").toInt();
    }
    if (server.hasArg("ping_interval")) {  // 👈 NEW: Capture ping slider/number field
      networkPingIntervalSeconds = server.arg("ping_interval").toInt();
      if (networkPingIntervalSeconds < 1) networkPingIntervalSeconds = 1;  // Safety floor
    }
    if (server.hasArg("gate_duration")) {  // 👈 NEW: Capture Alexa open window duration
      voiceGateOpenDurationSeconds = server.arg("gate_duration").toInt();
    }
    server.sendHeader("Location", "/");
    server.send(303);
  });

  // ========================================================
  // ROUTE: UPDATE BLUETOOTH CUSTOM FRIENDLY ALIAS NAME
  // ========================================================
  server.on("/update-bt-name", []() {
    String mac = server.arg("mac");
    String name = server.arg("name");
    mac.toUpperCase();

    // Search your authorised array for a matching MAC and assign the name
    for (int i = 0; i < authDeviceCount; i++) {
      if (authDevices[i].macAddress == mac) {
        authDevices[i].friendlyName = name;
        break;
      }
    }

    // Bounce the browser cleanly back to the home page dashboard
    server.sendHeader("Location", "/");
    server.send(303);
  });

  // ========================================================
  // ROUTE: ADD NEW IPHONE IP TO DATABASE
  // ========================================================
  server.on("/add-ip", []() {
    int quad = server.arg("quad").toInt();
    String name = server.arg("name");

    // Validate boundaries (1-254) and space constraints
    if (quad > 0 && quad < 255 && authIPCount < MAX_AUTH_IPS) {
      authIPs[authIPCount].lastQuad = quad;
      authIPs[authIPCount].friendlyName = name;
      authIPs[authIPCount].isOnline = false;
      authIPs[authIPCount].firstSeen = 0;
      authIPs[authIPCount].lastSeen = 0;
      authIPCount++;
    }

    // Redirect browser cleanly back to the home panel
    server.sendHeader("Location", "/");
    server.send(303);
  });

  // ========================================================
  // ROUTE: REMOVE IPHONE IP FROM DATABASE
  // ========================================================
  server.on("/remove-ip", []() {
    int index = server.arg("index").toInt();

    // Verify target line index bounds, shift array items left to delete
    if (index >= 0 && index < authIPCount) {
      for (int i = index; i < authIPCount - 1; i++) {
        authIPs[i] = authIPs[i + 1];
      }
      authIPCount--;
    }

    server.sendHeader("Location", "/");
    server.send(303);
  });

end of old routes
*/ 

// ==========================================
  // MASTER ROOT PANEL RENDERING ENDPOINT
  // ==========================================
  server.on("/", handleRoot); 

  // ==========================================
  // ROUTE: AUTHORISE NEW BLUETOOTH DEVICE
  // ==========================================
  server.on("/authorise", []() {
    String mac = server.arg("mac");
    String type = server.arg("type");
    mac.toUpperCase();
    
    bool exists = false;
    for(int i = 0; i < authDeviceCount; i++) {
      if(authDevices[i].macAddress == mac) exists = true;
    }
    
    if (!exists && authDeviceCount < MAX_AUTH_DEVICES && mac != "") {
      authDevices[authDeviceCount].macAddress = mac;
      authDevices[authDeviceCount].deviceType = type;
      authDevices[authDeviceCount].friendlyName = ""; // Initially clear
      authDevices[authDeviceCount].hasTrippedGate = false;
      authDeviceCount++;
      
      // 💾 BACKUP INSTANTLY: Save changes to physical silicon tracking lines
      saveConfigurationToFlash(); 
    }
    server.sendHeader("Location", "/");
    server.send(303);
  });

  // ==========================================
  // ROUTE: DE-AUTHORISE/REVOKE BLUETOOTH ACCESS
  // ==========================================
  server.on("/deauthorise", []() {
    String mac = server.arg("mac");
    mac.toUpperCase();
    
    for (int i = 0; i < authDeviceCount; i++) {
      if (authDevices[i].macAddress == mac) {
        for (int j = i; j < authDeviceCount - 1; j++) {
          authDevices[j] = authDevices[j + 1];
        }
        authDeviceCount--;
        
        // 💾 BACKUP INSTANTLY
        saveConfigurationToFlash(); 
        break;
      }
    }
    server.sendHeader("Location", "/");
    server.send(303);
  });

  // ==========================================
  // ROUTE: ASSIGN/RENAME FRIENDLY ALIAS
  // ==========================================
  server.on("/update-bt-name", []() {
    String mac = server.arg("mac");
    String name = server.arg("name");
    mac.toUpperCase();
    
    for (int i = 0; i < authDeviceCount; i++) {
      if (authDevices[i].macAddress == mac) {
        authDevices[i].friendlyName = name;
        
        // 💾 BACKUP INSTANTLY
        saveConfigurationToFlash(); 
        break;
      }
    }
    server.sendHeader("Location", "/");
    server.send(303);
  });

  // ==========================================
  // ROUTE: ADD VERIFIED PHONE STATIC IP
  // ==========================================
  server.on("/add-ip", []() {
    int quad = server.arg("quad").toInt();
    String name = server.arg("name");
    
    if (quad > 0 && quad < 255 && authIPCount < MAX_AUTH_IPS) {
      authIPs[authIPCount].lastQuad = quad;
      authIPs[authIPCount].friendlyName = name;
      authIPs[authIPCount].isOnline = false;
      authIPs[authIPCount].hasTrippedGate = false;
      authIPs[authIPCount].firstSeen = 0;
      authIPs[authIPCount].lastSeen = 0;
      authIPCount++;
      
      // 💾 BACKUP INSTANTLY
      saveConfigurationToFlash(); 
    }
    server.sendHeader("Location", "/");
    server.send(303);
  });

  // ==========================================
  // ROUTE: REMOVE VERIFIED PHONE IP 
  // ==========================================
  server.on("/remove-ip", []() {
    int index = server.arg("index").toInt();
    
    if (index >= 0 && index < authIPCount) {
      for (int i = index; i < authIPCount - 1; i++) {
        authIPs[i] = authIPs[i + 1];
      }
      authIPCount--;
      
      // 💾 BACKUP INSTANTLY
      saveConfigurationToFlash(); 
    }
    server.sendHeader("Location", "/");
    server.send(303);
  });

  // ==========================================
  // ROUTE: SAVE CORE QUANTUM TIME THRESHOLDS
  // ==========================================
  server.on("/save-settings", []() {
    if (server.hasArg("window")) authTimeWindowSeconds = server.arg("window").toInt();
    if (server.hasArg("arrival_limit")) maxArrivalAgeSeconds = server.arg("arrival_limit").toInt();
    if (server.hasArg("ping_interval")) networkPingIntervalSeconds = server.arg("ping_interval").toInt();
    if (server.hasArg("gate_duration")) voiceGateOpenDurationSeconds = server.arg("gate_duration").toInt();
    
    // 💾 BACKUP INSTANTLY
    saveConfigurationToFlash(); 
    
    server.sendHeader("Location", "/");
    server.send(303);
  });

  // ==========================================
  // ROUTE: SAVE RADIO SLIDER SETTINGS
  // ==========================================
  server.on("/setRadioParams", []() {
    if (server.hasArg("rssi")) rssiThreshold = server.arg("rssi").toInt();
    if (server.hasArg("window")) presenceWindowSeconds = server.arg("window").toInt();
    if (server.hasArg("scantime")) scanSliceDuration = server.arg("scantime").toInt();
    
    // 💾 BACKUP INSTANTLY
    saveConfigurationToFlash(); 
    
    server.sendHeader("Location", "/");
    server.send(303);
  });

  
  server.begin(); // Always near the end of setup()
  Serial.println("HTTP Web Server Started!");

  // ⚡ LAUNCH THE INDEPENDENT THREAD ENGINE
  xTaskCreatePinnedToCore(
    networkPingTaskEngine,  // Function execution name
    "PingTask",             // Text identifier name for debugging
    4096,                   // Stack size allocated to this task (4KB)
    NULL,                   // Parameter input parameters
    1,                      // Core priority level status (Low priority keeps web server fast)
    NULL,                   // Task tracking handle
    0                       // Pin this background task to Core 0 (Web server stays on Core 1)
  );
  Serial.println("FreeRTOS Asynchronous Pinger Thread Spawned!");

  Serial.println("end of void setup... Delaying 1 sec...");
  delay(1000);

}  // end of void setup


void loop() {

  if (WiFi.status() != WL_CONNECTED) {
    delay(1);
    connectWifi();
    return;
  }

  Sec27ASetState = !digitalRead(SetUnsetInputPin);  //.  ******** REMOVE THE ! When deploying at 27A ***************
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

  /* 
This didnt work well
  // Always process web requests first
  server.handleClient();

  // STRICT IF-GATE: Only run the ping engine if a user isn't loading the page
  if (isUserLoadingWebPage == false) {
    runNetworkPingScanner();
  } else {
    Serial.println("Ping skipped: Web server is currently busy transmitting!");
  }
*/

  // Process incoming web browser connections instantly without locking the CPU
  server.handleClient();

  delay(1);  // Crucial safety yield to prevent watchdog timer resets

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

  // runNetworkPingScanner();  // Ping any defined IP address's

  delay(1);  // Small safety yield to prevent watchdog resets

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
  /* 
new head statemnet provided 
  // Start building your HTML response string
  // --- START OF HTML WEB PAGE ---
  String html = "<!DOCTYPE html><html>";
  html += "<meta charset='UTF-8'>";  // 👈 allows  modern 4-byte Unicode characters (like emojis)to render
  html += "<head><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">";
  html += "<link rel=\"icon\" href=\"data:,\">";

  // Auto-refresh the page every 5 seconds to keep the BT list live
  html += "<script>";
  html += "setInterval(function() {";
  html += "  if (!sessionStorage.getItem('typing')) {";
  html += "    window.location.reload();";
  html += "  }";
  html += "}, 2000);";  // Refreshes every 2 seconds, but ONLY if you aren't typing
  html += "</script>";

  // Simple CSS styling for mobile-responsiveness
  html += "<style>html { font-family: Helvetica; display: inline-block; margin: 0px auto; text-align: center;}";
  html += ".button { background-color: #4CAF50; border: none; color: white; padding: 16px 40px;";
  html += "text-decoration: none; font-size: 30px; margin: 2px; cursor: pointer;}";
  html += ".button2 {background-color: #555555;}</style></head>";

  // Web Page Heading
  html += "<body><h1>27A Security Interface Log</h1>";

  */

  // Start building your HTML response string
  // --- START OF HTML WEB PAGE ---
  String html = "<!DOCTYPE html>\n<html>\n<head>\n";
  html += "<meta charset='UTF-8'>";  // Crucial for emojis inside the header
  html += "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">";
  html += "<link rel=\"icon\" href=\"data:,\">";
  html += "<title>Security Access Hub</title>";

  // ======================================================
  // ⚡ FIXED: UN-STUCK AUTOMATIC AUTO-REFRESH ENGINE
  // ======================================================
  html += "<script>";
  // Safety override: Wipes old stuck input locks whenever the page actually updates
  html += "if (window.performance && window.performance.navigation.type === 0) {";
  html += "  sessionStorage.removeItem('typing');";
  html += "}";

  // Execution loop constraint: Reload page every 2000ms if not typing
  html += "setInterval(function() {";
  html += "  var isTypingActive = sessionStorage.getItem('typing');";
  html += "  if (isTypingActive === null || isTypingActive === 'false') {";
  html += "    window.location.reload();";
  html += "  }";
  html += "}, 2000);";
  html += "</script>";

  // ======================================================
  // RETAINED: YOUR RENDER STYLING (MOBILE CSS LAYOUT)
  // ======================================================
  html += "<style>html { font-family: Helvetica; display: inline-block; margin: 0px auto; text-align: center;}";
  html += ".button { background-color: #4CAF50; border: none; color: white; padding: 16px 40px;";
  html += "text-decoration: none; font-size: 30px; margin: 2px; cursor: pointer;}";
  html += ".button2 {background-color: #555555;}</style>\n</head>\n";

  html += "<body style='background:#f4f4f4; margin:10px;'>";

  html += "<body><h1>27A Security Interface </h1>";

  // Display date
  html += "<p>Current Date is " + String(currentday) + " / " + String(currentmonth) + "</p>";

  // Display current time of day
  html += "<p>Current Time is " + String(currenthours) + ":" + String(currentminutes) + ":" + String(currentseconds) + ":" + "</p>";

  // Display last Reboot Time
  html += "<p>Last Restart was " + LastRebootTime + " on " + LastRebootDate + " which was " + String(UpTimeDays) + " days ago" + "</p>";

/*
works, but irrelevant 
  // Display current state, and show ON/OFF buttons
  html += "<p>LED Status: <strong>" + ledState + "</strong></p>";
  if (ledState == "OFF") {
    html += "<p><a href=\"/H\"><button class=\"button\">TURN ON</button></a></p>";

  } else {
    html += "<p><a href=\"/L\"><button class=\"button button2\">TURN OFF</button></a></p>";
  }
  */

  // ======================================================
  // LIVE ALEXA DISARM GATE STATUS BANNER
  // ======================================================
  unsigned long now = millis();
  String bannerHtml = "";

  // Enforce clock validation to dynamically drop the flag if time has run out
  if (securitySystemDisableAuthorised) {
    unsigned long timeElapsed = (now - gateActivationTime) / 1000;
    if (timeElapsed >= (unsigned long)voiceGateOpenDurationSeconds) {
      // Time expired: Cleanly close the system gate back down
      securitySystemDisableAuthorised = false;
      authorisingDeviceNames = "";
    }
  }

  // Draw the resulting conditional interface boxes
  if (securitySystemDisableAuthorised) {
    unsigned long remainingTime = voiceGateOpenDurationSeconds - ((now - gateActivationTime) / 1000);
    bannerHtml += "<div style='margin: 15px auto; width: 95%; max-width: 700px; background-color: #d4edda; border: 2px solid #c3e6cb; color: #155724; padding: 15px; text-align: center; border-radius: 5px;'>";
    bannerHtml += "<h2 style='margin: 0 0 5px 0;'>🔓 Alexa Disarm Gate: OPEN</h2>";
    bannerHtml += "Authorized by: <b style='text-decoration: underline; color: #0b2e13;'>" + authorisingDeviceNames + "</b><br>";
    bannerHtml += "<span style='font-size: 14px; font-weight: bold;'>Window expires in: <span style='color:red; font-size:18px;'>" + String(remainingTime) + "</span> seconds</span>";
    bannerHtml += "</div>";
  } else {
    bannerHtml += "<div style='margin: 15px auto; width: 95%; max-width: 700px; background-color: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; padding: 10px; text-align: center; border-radius: 5px;'>";
    bannerHtml += "<h3 style='margin: 0;'>🔒 Alexa Disarm Gate: LOCKED</h3>";
    bannerHtml += "<small style='color: #666;'>Bring a verified arrival token into proximity to authorize system overrides.</small>";
    bannerHtml += "</div>";
  }

  html += bannerHtml;

  //Display Alarm set/Unset State

  if (Sec27ASetState == HIGH) {  // High is alarm unset state
    html += "<p>Current Security System Status: <strong> UNSET (disabled/off) </strong></p>";
    html += "<p><a href=\"/SET\"><button class=\"button\">SET Alarm</button></a></p>";

  } else {
    html += "<p>Current Security System Status: <strong> SET (enabled/on) </strong></p>";
    html += "<p><a href=\"UNSET\"><button class=\"button button2\">UnSET Alarm</button></a></p>";
  }

  /* 
  change from sliders to inpt boxes 
  // --- STREAMLINED FILTER CONTROLLER BOX ---
  html += "<div style='text-align: center; margin: 10px auto; padding: 10px; width: 90%; max-width: 380px; border: 1px solid #bbb; border-radius: 6px; font-size: 0.9em; background-color: #f9f9f9;'>";
  html += "  <h5 style='margin: 0 0 8px 0;'>Bluetooth Radio & Filter Settings</h5>";
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

*/

  // --- STREAMLINED FILTER CONTROLLER BOX (CONVERTED TO TEXT ENTRY WITH FREEZE HOOKS) ---
  html += "<div style='text-align: center; margin: 10px auto; padding: 10px; width: 90%; max-width: 380px; border: 1px solid #bbb; border-radius: 6px; font-size: 0.9em; background-color: #f9f9f9;'>";
  html += "  <h5 style='margin: 0 0 8px 0;'>Bluetooth Radio & Filter Settings</h5>";
  html += "  <form action='/setRadioParams' method='GET'>";

  // Input 1: RSSI Sensitivity
  html += "    <div style='margin-bottom: 8px;'>";
  html += "      <label style='display:inline-block; width:140px; text-align:right; margin-right:10px;'>RSSI Gate (dBm):</label>";
  html += "      <input type='number' name='rssi' min='-100' max='-10' step='1' value='" + String(rssiThreshold) + "' style='width: 60px; text-align: center;' "
                                                                                                                   "onfocus=\"sessionStorage.setItem('typing', 'true');\" "
                                                                                                                   "onblur=\"sessionStorage.removeItem('typing');\">";
  html += "    </div>";

  // Input 2: Detection Window Timeout
  html += "    <div style='margin-bottom: 8px;'>";
  html += "      <label style='display:inline-block; width:140px; text-align:right; margin-right:10px;'>Keep-Alive Window:</label>";
  html += "      <input type='number' name='window' min='10' max='300' step='5' value='" + String(presenceWindowSeconds) + "' style='width: 60px; text-align: center;' "
                                                                                                                           "onfocus=\"sessionStorage.setItem('typing', 'true');\" "
                                                                                                                           "onblur=\"sessionStorage.removeItem('typing');\"> s";
  html += "    </div>";

  // Input 3: Scan Slice Duration
  html += "    <div style='margin-bottom: 12px;'>";
  html += "      <label style='display:inline-block; width:140px; text-align:right; margin-right:10px;'>Scan Slice:</label>";
  html += "      <input type='number' name='scantime' min='1' max='10' step='1' value='" + String(scanSliceDuration) + "' style='width: 60px; text-align: center;' "
                                                                                                                       "onfocus=\"sessionStorage.setItem('typing', 'true');\" "
                                                                                                                       "onblur=\"sessionStorage.removeItem('typing');\"> s";
  html += "    </div>";

  html += "    <input type='submit' class='buttonsmall' style='padding: 4px 15px; font-size: 0.85em; cursor: pointer;' value='Apply Changes'>";
  html += "  </form>";
  html += "</div>";

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
  // ======================================================
  // NEW: SETTINGS CONFIGURATION FORM (Adjustable Time Window)
  // ======================================================
  html += "<div style='margin: 20px auto; width: 95%; max-width: 650px; text-align: center; border: 1px dashed #666; padding: 10px;'>";
  html += "<form action='/save-settings' method='GET'>";
  html += "<b>Bluetooth & Ping Device 2FA Authorisation Window: </b>";
  html += "<input type='number' name='window' value='" + String(authTimeWindowSeconds) + "' style='width:60px; text-align:center;'> seconds ";
  html += "<input type='submit' value='Update Window'>";
  html += "</form></div>";

  // ======================================================
  // TABLE 1: ACTIVE BLUETOOTH TOKENS (SCANNER)
  // ======================================================
  html += "<h3>Active Bluetooth Tokens (RSSI > " + String(rssiThreshold) + " dBm)</h3>";
  html += "<table border='1' align='center' style='margin-bottom: 30px; width: 95%; max-width: 700px;'>";  // Fixed width to 700px
  html += "<tr><th>MAC Address</th><th>Device Info</th><th>RSSI</th><th>Last Seen</th><th>Total Duration</th><th>Action</th></tr>";

  int count = 0;
  unsigned long currentMillis = millis();

  for (int i = 0; i < deviceCount; i++) {
    if (currentMillis - discoveredDevices[i].lastSeen < ((unsigned long)presenceWindowSeconds * 1000)) {
      html += "<tr><td><code>" + discoveredDevices[i].macAddress + "</code></td>";

      // NEW LOOKUP: Check if this MAC address has a custom friendly name saved in Table 2
      String activeAlias = "";
      for (int k = 0; k < authDeviceCount; k++) {
        if (authDevices[k].macAddress == discoveredDevices[i].macAddress) {
          activeAlias = authDevices[k].friendlyName;
        }
      }

      html += "<td>";
      // If a friendly name exists, print it as a purple badge above the device type
      if (activeAlias != "") {
        html += "<b style='color:purple;'>[" + activeAlias + "]</b><br>";
      }

      if (discoveredDevices[i].findMyFingerprint != "") {
        html += "<b>" + discoveredDevices[i].deviceType + "</b><br><small style='color:blue;'>Key: " + discoveredDevices[i].findMyFingerprint + "</small></td>";
      } else {
        html += discoveredDevices[i].deviceType + "</td>";
      }

      html += "<td>" + String(discoveredDevices[i].rssi) + " dBm</td>";

      unsigned long lastSeenSec = (currentMillis - discoveredDevices[i].lastSeen) / 1000;
      html += "<td>" + String(lastSeenSec) + "s ago</td>";

      unsigned long totalTimeSec = (currentMillis - discoveredDevices[i].firstSeen) / 1000;
      unsigned long mins = totalTimeSec / 60;
      unsigned long secs = totalTimeSec % 60;

      html += "<td>";
      if (mins > 0) { html += String(mins) + "m "; }
      html += String(secs) + "s in range</td>";

      // ACTION BUTTON: Link to send device data to the /authorise controller url endpoint
      html += "<td><a href='/authorise?mac=" + discoveredDevices[i].macAddress + "&type=" + discoveredDevices[i].deviceType + "'><button style='background-color:#4CAF50; color:white; border:none; padding:4px 8px; cursor:pointer;'>+ Authorise</button></a></td></tr>";

      count++;
    }
  }

  if (count == 0) {
    html += "<tr><td colspan='6' style='color: red; text-align:center;'>No tokens in range.</td></tr>";
  }
  html += "</table>";

  /*
  // ======================================================
  // UPDATED: SETTINGS CONFIGURATION FORM (Triple Value Constraints)
  // ======================================================
  html += "<div style='margin: 20px auto; width: 95%; max-width: 700px; text-align: center; border: 1px dashed #666; padding: 15px; background-color: #fff;'>";
  html += "<form action='/save-settings' method='POST'>";

  html += "<div style='display: inline-block; margin: 5px 15px;'><b>Active Presence Window: </b>";
  html += "<input type='number' name='window' value='" + String(authTimeWindowSeconds) + "' style='width:60px; text-align:center;'> seconds</div>";

  html += "<div style='display: inline-block; margin: 5px 15px;'><b>🔒 Fresh Arrival Trust: </b>";
  html += "<input type='number' name='arrival_limit' value='" + String(maxArrivalAgeSeconds) + "' style='width:60px; text-align:center;'> seconds</div>";

  // NEW INPUT ROW FOR PING REFRESH RATE
  html += "<div style='display: inline-block; margin: 5px 15px;'><b>⚡ Network Ping Interval: </b>";
  html += "<input type='number' name='ping_interval' min='1' max='60' value='" + String(networkPingIntervalSeconds) + "' style='width:60px; text-align:center;'> seconds</div>";

  html += "<div style='margin-top: 15px;'><input type='submit' value='Save All Settings' style='padding: 6px 20px; font-weight: bold; background-color: #333; color: white; border: none; cursor: pointer;'></div>";
  html += "</form></div>";

*/
  /* 
changed to allow easy filling
  // ======================================================
  // UPDATED: SETTINGS CONFIGURATION FORM (Quad Constraints)
  // ======================================================
  html += "<div style='margin: 20px auto; width: 95%; max-width: 700px; text-align: center; border: 1px dashed #666; padding: 15px; background-color: #fff;'>";
  html += "<form action='/save-settings' method='POST'>";
  
  html += "<div style='display: inline-block; margin: 5px 10px;'><b>Active Presence: </b><input type='number' name='window' value='" + String(authTimeWindowSeconds) + "' style='width:50px; text-align:center;'>s</div>";
  html += "<div style='display: inline-block; margin: 5px 10px;'><b>🔒 Fresh Arrival: </b><input type='number' name='arrival_limit' value='" + String(maxArrivalAgeSeconds) + "' style='width:50px; text-align:center;'>s</div>";
  html += "<div style='display: inline-block; margin: 5px 10px;'><b>⚡ Ping Interval: </b><input type='number' name='ping_interval' value='" + String(networkPingIntervalSeconds) + "' style='width:50px; text-align:center;'>s</div>";
  
  // NEW FIELD: ALEXA GATE OPEN WINDOW
  html += "<div style='display: inline-block; margin: 5px 10px;'><b>🎙️ Voice Gate Open: </b><input type='number' name='gate_duration' value='" + String(voiceGateOpenDurationSeconds) + "' style='width:50px; text-align:center;'>s</div>";
  
  html += "<div style='margin-top: 15px;'><input type='submit' value='Save All Settings' style='padding: 6px 20px; font-weight: bold; background-color: #333; color: white; border: none; cursor: pointer;'></div>";
  html += "</form></div>";
  */

  // ======================================================
  // UPDATED: SETTINGS CONFIGURATION FORM (FREEZE-SAFE OVERRIDES)
  // ======================================================
  html += "<div style='margin: 20px auto; width: 95%; max-width: 700px; text-align: center; border: 1px dashed #666; padding: 15px; background-color: #fff;'>";
  html += "<form action='/save-settings' method='POST'>";

  // 1. ACTIVE PRESENCE FIELD
  html += "<div style='display: inline-block; margin: 5px 10px;'><b>Active Presence: </b>"
          "<input type='number' name='window' value='"
          + String(authTimeWindowSeconds) + "' style='width:50px; text-align:center;' "
                                            "onfocus=\"sessionStorage.setItem('typing', 'true');\" "
                                            "onblur=\"sessionStorage.removeItem('typing');\">s</div>";

  // 2. FRESH ARRIVAL FIELD
  html += "<div style='display: inline-block; margin: 5px 10px;'><b>🔒 Fresh Arrival: </b>"
          "<input type='number' name='arrival_limit' value='"
          + String(maxArrivalAgeSeconds) + "' style='width:50px; text-align:center;' "
                                           "onfocus=\"sessionStorage.setItem('typing', 'true');\" "
                                           "onblur=\"sessionStorage.removeItem('typing');\">s</div>";

  // 3. PING INTERVAL FIELD
  html += "<div style='display: inline-block; margin: 5px 10px;'><b>⚡ Ping Interval: </b>"
          "<input type='number' name='ping_interval' value='"
          + String(networkPingIntervalSeconds) + "' style='width:50px; text-align:center;' "
                                                 "onfocus=\"sessionStorage.setItem('typing', 'true');\" "
                                                 "onblur=\"sessionStorage.removeItem('typing');\">s</div>";

  // 4. VOICE GATE OPEN FIELD
  html += "<div style='display: inline-block; margin: 5px 10px;'><b>🎙️ Voice Gate Open: </b>"
          "<input type='number' name='gate_duration' value='"
          + String(voiceGateOpenDurationSeconds) + "' style='width:50px; text-align:center;' "
                                                   "onfocus=\"sessionStorage.setItem('typing', 'true');\" "
                                                   "onblur=\"sessionStorage.removeItem('typing');\">s</div>";

   
  html += "    <input type='submit' class='buttonsmall' style='padding: 4px 15px; font-size: 0.85em; cursor: pointer;' value='Apply Changes'>";
  //html += "<div style='margin-top: 15px;'><input type='submit' value='Save All Settings' style='padding: 6px 20px; font-weight: bold; background-color: #333; color: white; border: none; cursor: pointer;'></div>";
  html += "</form></div>";


  // ======================================================
  // NEW: TABLE 3: AUTHORISED IPHONE NETWORK PINGER DATABASE
  // ======================================================
  IPAddress localIP = WiFi.localIP();
  String subnetPrefix = String(localIP[0]) + "." + String(localIP[1]) + "." + String(localIP[2]) + ".";

  html += "<hr style='width: 95%; max-width: 700px; margin: 20px auto;'>";
  html += "<h3>📱 Authorised Phone Network Pinger (" + String(authIPCount) + "/" + String(MAX_AUTH_IPS) + ")</h3>";

  // Interactive Entry Submission Form Block with Dynamic Auto-Refresh Freeze
  html += "<div style='margin: 10px auto; width: 95%; max-width: 700px; text-align: center; background:#eee; padding:8px;'>";
  html += "<form action='/add-ip' method='GET' style='margin:0;'>";

  html += "Target IP: <b>" + subnetPrefix + "</b>"
                                            "<input type='number' name='quad' min='1' max='254' placeholder='254' style='width:50px;' required "
                                            "onfocus=\"sessionStorage.setItem('typing', 'true');\" "
                                            "onblur=\"sessionStorage.removeItem('typing');\"> ";

  html += "Name: <input type='text' name='name' placeholder=\"Tony's iPhone\" style='width:120px;' required "
          "onfocus=\"sessionStorage.setItem('typing', 'true');\" "
          "onblur=\"sessionStorage.removeItem('typing');\"> ";

  html += "<input type='submit' value='+ Add Phone Key' style='background:#008CBA; color:white; border:none; padding:4px 10px; cursor:pointer;'>";
  html += "</form></div>";

  html += "<table border='1' align='center' style='margin-bottom: 40px; width: 95%; max-width: 700px; background-color: #fafafa;'>";
  html += "<tr style='background-color: #dcdcdc;'><th>Friendly Name</th><th>Target IP Address</th><th>Network Ping Status</th><th>Verification State</th><th>Action</th></tr>";

  if (authIPCount == 0) {
    html += "<tr><td colspan='5' style='color: gray; text-align:center; padding: 10px;'>No verified mobile IPs defined. Use the input form wrapper above.</td></tr>";
  } else {
    for (int i = 0; i < authIPCount; i++) {
      String fullTargetIP = subnetPrefix + String(authIPs[i].lastQuad);
      html += "<tr><td><b>" + authIPs[i].friendlyName + "</b></td>";
      html += "<td><code>" + fullTargetIP + "</code></td>";

      // Ping Connectivity Indicator Check
      String pingIndicator = authIPs[i].isOnline ? "<span style='color:green;'>Connected 📶</span>" : "<span style='color:grey;'>Unreachable 💤</span>";
      html += "<td>" + pingIndicator + "</td>";

      // Calculate Network Arrival Trust Bounds
      String ipVerificationState = "<span style='color:red; font-weight:bold;'>🔴 Expired</span>";
      if (authIPs[i].isOnline) {
        unsigned long totalDurationSeconds = (currentMillis - authIPs[i].firstSeen) / 1000;
        if (totalDurationSeconds <= (unsigned long)maxArrivalAgeSeconds) {
          ipVerificationState = "<span style='color:green; font-weight:bold;'>🟢 Valid (" + String(maxArrivalAgeSeconds - totalDurationSeconds) + "s trust left)</span>";
        } else {
          ipVerificationState = "<span style='color:orange; font-weight:bold;'>🟠 Expired (Static Home)</span>";
        }
      }

      html += "<td>" + ipVerificationState + "</td>";
      html += "<td><a href='/remove-ip?index=" + String(i) + "'><button style='background-color:#f44336; color:white; border:none; padding:4px 8px; cursor:pointer;'>❌ Remove</button></a></td></tr>";
    }
  }
  html += "</table>";

  // ======================================================
  // UPDATED: TABLE 2: NOMINATED AUTHORISED TOKENS (SECURITY DATABASE)
  // ======================================================
  html += "<hr style='width: 95%; max-width: 700px; margin: 20px auto;'>";
  html += "<h3>🔒 Authorised 2FA Security Tokens (" + String(authDeviceCount) + "/" + String(MAX_AUTH_DEVICES) + ")</h3>";
  html += "<table border='1' align='center' style='margin-bottom: 20px; width: 95%; max-width: 700px; background-color: #f9f9f9;'>";
  html += "<tr style='background-color: #e0e0e0;'><th>MAC Address</th><th>Device Specs</th><th>Friendly Identity Name</th><th>Current Proximity Status</th><th>Action</th></tr>";

  if (authDeviceCount == 0) {
    html += "<tr><td colspan='5' style='color: gray; text-align:center; padding: 10px;'>No authorised devices defined. Click '+ Authorise' on the table above to add keys.</td></tr>";
  } else {
    for (int i = 0; i < authDeviceCount; i++) {
      html += "<tr><td><code>" + authDevices[i].macAddress + "</code></td>";
      html += "<td>" + authDevices[i].deviceType + "</td>";

      // 1. INLINE FRIENDLY NAME FORM WITH AUTO-REFRESH FREEZE HOOKS
      html += "<td><form action='/update-bt-name' method='GET' style='margin:0;'>";
      html += "<input type='hidden' name='mac' value='" + authDevices[i].macAddress + "'>";
      html += "<input type='text' name='name' value='" + authDevices[i].friendlyName + "' style='width:110px;' "
                                                                                       "onfocus=\"sessionStorage.setItem('typing', 'true');\" "
                                                                                       "onblur=\"sessionStorage.removeItem('typing');\"> ";
      html += "<input type='submit' value='Set' style='font-size:10px; padding:2px;'>";
      html += "</form></td>";
      /*
      // 2. CALCULATE VALID / EXPIRED STATUS STRATEGY
      String liveStatus = "<span style='color:red; font-weight:bold;'>🔴 Expired (Out of Range)</span>";
      for (int j = 0; j < deviceCount; j++) {
        if (discoveredDevices[j].macAddress == authDevices[i].macAddress) {
          unsigned long lastSeenDelta = (currentMillis - discoveredDevices[j].lastSeen) / 1000;
          unsigned long totalDurationSeconds = (currentMillis - discoveredDevices[j].firstSeen) / 1000;

          bool isCurrentlyPresent = (lastSeenDelta <= (unsigned long)authTimeWindowSeconds);
          bool isFreshArrival = (totalDurationSeconds <= (unsigned long)maxArrivalAgeSeconds);

          if (isCurrentlyPresent && isFreshArrival) {
            unsigned long remainingTrust = maxArrivalAgeSeconds - totalDurationSeconds;
            liveStatus = "<span style='color:green; font-weight:bold;'>🟢 Valid (" + String(remainingTrust) + "s trust left)</span>";
          } else if (isCurrentlyPresent && !isFreshArrival) {
            liveStatus = "<span style='color:orange; font-weight:bold;'>🟠 Expired (Static / Sitting Home)</span>";
          } else {
            liveStatus = "<span style='color:red; font-weight:bold;'>🔴 Expired (Inactive " + String(lastSeenDelta) + "s)</span>";
          }
          break;
        }
      }
*/
      // ======================================================
      // 2. CALCULATE VALID / EXPIRED STATUS STRATEGY (WITH LATCH CLEANUP)
      // ======================================================
      String liveStatus = "<span style='color:red; font-weight:bold;'>🔴 Expired (Out of Range)</span>";
      for (int j = 0; j < deviceCount; j++) {
        if (discoveredDevices[j].macAddress == authDevices[i].macAddress) {
          unsigned long lastSeenDelta = (currentMillis - discoveredDevices[j].lastSeen) / 1000;
          unsigned long totalDurationSeconds = (currentMillis - discoveredDevices[j].firstSeen) / 1000;

          bool isCurrentlyPresent = (lastSeenDelta <= (unsigned long)authTimeWindowSeconds);
          bool isFreshArrival = (totalDurationSeconds <= (unsigned long)maxArrivalAgeSeconds);

          if (isCurrentlyPresent && isFreshArrival) {
            unsigned long remainingTrust = maxArrivalAgeSeconds - totalDurationSeconds;
            liveStatus = "<span style='color:green; font-weight:bold;'>🟢 Valid (" + String(remainingTrust) + "s trust left)</span>";
          } else if (isCurrentlyPresent && !isFreshArrival) {
            liveStatus = "<span style='color:orange; font-weight:bold;'>🟠 Expired (Static / Sitting Home)</span>";
          } else {
            liveStatus = "<span style='color:red; font-weight:bold;'>🔴 Expired (Inactive " + String(lastSeenDelta) + "s)</span>";

            // ⚡ NEW SAFETY RESET: The device is physically inactive/out of range.
            // Release its gate latch so it can trigger the Alexa window again next time you arrive!
            authDevices[i].hasTrippedGate = false;
          }
          break;
        }
      }

      // Fallback Safety Check: If the device wasn't found in the active scan array at all
      if (liveStatus.indexOf("Out of Range") != -1) {
        authDevices[i].hasTrippedGate = false;
      }

      html += "<td>" + liveStatus + "</td>";

      // DE-AUTHORISE ACTION BUTTON
      html += "<td><a href='/deauthorise?mac=" + authDevices[i].macAddress + "'><button style='background-color:#f44336; color:white; border:none; padding:4px 8px; cursor:pointer;'>❌ Revoke</button></a></td></tr>";
    }
  }
  html += "</table>";

  // Old logging section

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
  //server.send(200, "text/html", html);

  // Right before you send the data, lock the gate
  //isUserLoadingWebPage = true;

  server.send(200, "text/html; charset=utf-8", html);

  // Right after the data is safely sent, unlock the gate
  //isUserLoadingWebPage = false;
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
      ProxyRequestText = "Authorised Keys found " + authorisingDeviceNames;
      RotateProxyLogArray();
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
    if (securitySystemDisableAuthorised == true) {
      securitySystemDisableAuthorised = false;

        //Serial.println("XXX Pulsing Relay on ...");
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
      ProxyRequestText = "Authorised Keys found " + authorisingDeviceNames;
      RotateProxyLogArray();
      ProxyRequestText = "UnSet Request Honored ";
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
    } else { // if (securitySystemDisableAuthorised == true)
      Serial.println("27A Security UnSet Request NOT Honored - No Auth keys found");
      ProxyRequestText = "UnSet Request NOT Honored - No Auth keys found";
      RotateProxyLogArray();
    }
  } else { //
      Serial.println("27A Security UnSet Request NOT Honored - Already Set");
      ProxyRequestText = "UnSet Request NOT Honored - Already Set";
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
  WiFi.setSleep(false);
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

void handleRadioParams() {

    Serial.println("is this handleRadioParams function even being used ?? " );
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


/* old scanner
void runNetworkPingScanner() {
  unsigned long currentMillis = millis();
  
       Serial.println("in Ping routine" );
  // Dynamic User-Adjusted Interval Constraint (Default: 2 seconds)
  if (currentMillis - lastPingTime >= ((unsigned long)networkPingIntervalSeconds * 1000)) {
    lastPingTime = currentMillis;
    Serial.println("its time to ping" );
    // Fetch local gateway data structures cleanly
    IPAddress localIP = WiFi.localIP();
    
    for (int i = 0; i < authIPCount; i++) {
      if (authIPs[i].lastQuad == 0) continue; 
      Serial.println(authIPs[i].lastQuad );
      // FIXED: Correctly isolate individual byte quads using array indexes
      IPAddress targetIP(localIP[0], localIP[1], localIP[2], authIPs[i].lastQuad);

       Serial.println(targetIP);

      // Run ESPping check (Sends 1 packet with a 500ms timeout window)
      if (Ping.ping(targetIP, 1)) {
        // iPhone responded!
        Serial.println("phone online" );
        if (!authIPs[i].isOnline || (currentMillis - authIPs[i].lastSeen > 60000)) {
          // Fresh arrival: Reset the countdown window if previously offline
          authIPs[i].firstSeen = currentMillis;
        }
        authIPs[i].lastSeen = currentMillis;
        authIPs[i].isOnline = true;
      } else {
        // iPhone went silent (or went out of range)
        authIPs[i].isOnline = false;
        Serial.println("phone not online" );
      }
    }
  }
}

*/

/* 

2nd attempt
void runNetworkPingScanner() {
  unsigned long currentMillis = millis();
  
  // Dynamic User-Adjusted Interval Constraint (Default: 2 seconds)
  if (currentMillis - lastPingTime >= ((unsigned long)networkPingIntervalSeconds * 1000)) {
    lastPingTime = currentMillis;
    
    // 1. Fetch dynamic local configuration
    IPAddress localIP = WiFi.localIP();
    
    // 2. FIXED: Explicitly convert the first 3 fields into clean, raw numbers
    uint8_t ip0 = localIP[0];
    uint8_t ip1 = localIP[1];
    uint8_t ip2 = localIP[2];
    
    for (int i = 0; i < authIPCount; i++) {
      if (authIPs[i].lastQuad == 0) continue; 
      
      // 3. Assemble target destination using raw numbers safely
      IPAddress targetIP(ip0, ip1, ip2, authIPs[i].lastQuad);
      
      // 4. Debug output verification line
      Serial.print("Issuing core ping request to destination address: ");
      Serial.println(targetIP);
      
      // Run ESPping check (Sends 1 packet with a 500ms timeout window)
      if (Ping.ping(targetIP, 1)) {
        Serial.println(" -> SUCCESS! Target device online.");
        // iPhone responded!
        if (!authIPs[i].isOnline || (currentMillis - authIPs[i].lastSeen > 60000)) {
          // Fresh arrival: Reset the countdown window if previously offline
          authIPs[i].firstSeen = currentMillis;
        }
        authIPs[i].lastSeen = currentMillis;
        authIPs[i].isOnline = true;
      } else {
        Serial.println(" -> FAILED! Host unreachable.");
        // iPhone went silent (or went out of range)
        authIPs[i].isOnline = false;
      }
    }
  }
}

*/
/*
3rd attempt
void runNetworkPingScanner() {
  unsigned long currentMillis = millis();
  
  // Dynamic User-Adjusted Interval Constraint (Default: 2 seconds)
  if (currentMillis - lastPingTime >= ((unsigned long)networkPingIntervalSeconds * 1000)) {
    lastPingTime = currentMillis;
    
    // 1. Fetch live network parameters
    IPAddress localIP = WiFi.localIP();
    
    for (int i = 0; i < authIPCount; i++) {
      if (authIPs[i].lastQuad == 0) continue; 
      
      // 2. FIXED: Instantiate the IPAddress object via explicit bracket constructor formatting
      IPAddress targetIP;
      targetIP[0] = localIP[0];
      targetIP[1] = localIP[1];
      targetIP[2] = localIP[2];
      targetIP[3] = authIPs[i].lastQuad;
      
      // Debug verification printouts
      Serial.print("Issuing core ping request to destination address: ");
      Serial.println(targetIP);
      
      // 3. Execute core network ping via the dvarrel library syntax wrapper
      if (Ping.ping(targetIP, 1)) {
        Serial.println(" -> SUCCESS! Target device online.");
        
        if (!authIPs[i].isOnline || (currentMillis - authIPs[i].lastSeen > 60000)) {
          // Fresh arrival trigger state hook reset
          authIPs[i].firstSeen = currentMillis;
        }
        authIPs[i].lastSeen = currentMillis;
        authIPs[i].isOnline = true;
      } else {
        Serial.println(" -> FAILED! Host unreachable.");
        authIPs[i].isOnline = false;
      }
    }
  }
}
*/
/* 
4th attempt
void runNetworkPingScanner() {
  unsigned long currentMillis = millis();
  
  // Dynamic User-Adjusted Interval Constraint (Default: 2 seconds)
  if (currentMillis - lastPingTime >= ((unsigned long)networkPingIntervalSeconds * 1000)) {
    lastPingTime = currentMillis;
    
    // 1. Fetch active dynamic configuration
    IPAddress localIP = WiFi.localIP();
    
    for (int i = 0; i < authIPCount; i++) {
      if (authIPs[i].lastQuad == 0) continue; 
      
      // 2. FIXED: Construct a raw un-mangled C-String format bypassing the constructor object bugs
      String ipString = String(localIP[0]) + "." + 
                        String(localIP[1]) + "." + 
                        String(localIP[2]) + "." + 
                        String(authIPs[i].lastQuad);
      
      // Convert to a standard character array reference pointer container
      const char* rawTargetHost = ipString.c_str();
      
      // Debug verification logs
      Serial.print("Issuing bypass raw-string ping to destination: ");
      Serial.println(rawTargetHost);
      
      // 3. Execute network call via raw text string pointer override framework
      if (Ping.ping(rawTargetHost, 1)) {
        Serial.println(" -> SUCCESS! Target device online.");
        
        if (!authIPs[i].isOnline || (currentMillis - authIPs[i].lastSeen > 60000)) {
          // Fresh arrival authentication trigger window reset
          authIPs[i].firstSeen = currentMillis;
        }
        authIPs[i].lastSeen = currentMillis;
        authIPs[i].isOnline = true;
      } else {
        Serial.println(" -> FAILED! Host unreachable.");
        authIPs[i].isOnline = false;
      }
    }
  }
}
*/
/* 
5th attempt
void runNetworkPingScanner() {
  unsigned long currentMillis = millis();
  
  // Dynamic User-Adjusted Interval Constraint (Default: 2 seconds)
  if (currentMillis - lastPingTime >= ((unsigned long)networkPingIntervalSeconds * 1000)) {
    lastPingTime = currentMillis;
    
    // 1. Fetch dynamic local configuration
    IPAddress localIP = WiFi.localIP();
    
    // 2. CRITICAL ANTENNA FIX: Temporarily halt the Bluetooth scanning engine
    // This immediately frees up the shared 2.4GHz antenna layer for Wi-Fi traffic.
    if (pBLEScan != nullptr) {
      pBLEScan->stop();
    }
    
    // Allow the network driver stack 50 milliseconds to re-settle
    delay(50); 
    
    for (int i = 0; i < authIPCount; i++) {
      if (authIPs[i].lastQuad == 0) continue; 
      
      // Construct a clean, direct IPAddress structure
      IPAddress targetIP(localIP[0], localIP[1], localIP[2], authIPs[i].lastQuad);
      
      Serial.print("Issuing antenna-isolated ping to: ");
      Serial.println(targetIP);
      
      // Execute network call (Sends 1 packet with a fast response window)
      if (Ping.ping(targetIP, 1)) {
        Serial.println(" -> SUCCESS! Target device online.");
        
        if (!authIPs[i].isOnline || (currentMillis - authIPs[i].lastSeen > 60000)) {
          authIPs[i].firstSeen = currentMillis;
        }
        authIPs[i].lastSeen = currentMillis;
        authIPs[i].isOnline = true;
      } else {
        Serial.println(" -> FAILED! Host unreachable.");
        authIPs[i].isOnline = false;
      }
    }

    // 3. RESUME BLUETOOTH ENGINE: Hand the antenna back over to the BLE loop tracker
    // Replace "3" with your current background Scan Slice/duration variable if it differs
    if (pBLEScan != nullptr) {
      pBLEScan->start(3, false); // Restarts non-blocking scans
    }
  }
}
*/
/*
6th? attempt
void runNetworkPingScanner() {
  unsigned long currentMillis = millis();

  // Strict non-blocking constraint: Only execute if your interval has passed
  if (currentMillis - lastPingTime >= ((unsigned long)networkPingIntervalSeconds * 1000)) {
    lastPingTime = currentMillis;

    IPAddress localIP = WiFi.localIP();
    uint8_t myOwnLastQuad = localIP[3];  // Dynamically grabs the ESP32's last quad (e.g., 20)

    // Temporarily pause BLE scans to clear the shared physical antenna
    if (pBLEScan != nullptr) pBLEScan->stop();
    delay(20);

    for (int i = 0; i < authIPCount; i++) {
      if (authIPs[i].lastQuad == 0) continue;

      // Safety Override: Bypass self-pings entirely
      if (authIPs[i].lastQuad == myOwnLastQuad) {
        authIPs[i].lastSeen = currentMillis;
        authIPs[i].isOnline = true;
        continue;
      }

      // Assemble standard target destination properties
      IPAddress targetIP(localIP[0], localIP[1], localIP[2], authIPs[i].lastQuad);

      Serial.print("Issuing non-blocking ping to: ");
      Serial.println(targetIP);

      // Send 2 packet with a fast response window
      if (Ping.ping(targetIP, 2)) {
        Serial.println(" -> SUCCESS! Target device online.");
        if (!authIPs[i].isOnline || (currentMillis - authIPs[i].lastSeen > 60000)) {
          authIPs[i].firstSeen = currentMillis;
        }
        authIPs[i].lastSeen = currentMillis;
        authIPs[i].isOnline = true;
      } else {
        Serial.println(" -> FAILED! Host unreachable.");
        authIPs[i].isOnline = false;
      }
    }

    // Resume Bluetooth tracking safely
    if (pBLEScan != nullptr) pBLEScan->start(3, false);
  }
}

*/

// --- FreeRTOS Independent Task Engine For Network Pings ---
void networkPingTaskEngine(void* parameter) {
  // Give the ESP32 5 seconds to complete Wi-Fi and startup tasks before beginning
  vTaskDelay(pdMS_TO_TICKS(5000));

  while (true) {
    // 1. Double check connectivity bounds before issuing packets
    if (WiFi.status() == WL_CONNECTED && authIPCount > 0) {
      IPAddress localIP = WiFi.localIP();
      uint8_t myOwnLastQuad = localIP[3];  // Dynamically identify self IP quad

      // 2. Clear the 2.4GHz antenna layer by stopping BLE scans briefly
      if (pBLEScan != nullptr) pBLEScan->stop();
      vTaskDelay(pdMS_TO_TICKS(30));  // Safe task pause

      for (int i = 0; i < authIPCount; i++) {
        if (authIPs[i].lastQuad == 0) continue;

        // Skip over loopback checks to prevent self-recursive calls
        if (authIPs[i].lastQuad == myOwnLastQuad) {
          authIPs[i].lastSeen = millis();
          authIPs[i].isOnline = true;
          continue;
        }

        // Construct target address structure safely
        IPAddress targetIP(localIP[0], localIP[1], localIP[2], authIPs[i].lastQuad);
        /* 
        // Execute network check (Sends 2 packets with an explicit timeout)
        if (Ping.ping(targetIP, 2)) {
          // TRIPPED EDGE DETECTION: If it was previously offline, it has JUST arrived!
          if (!authIPs[i].isOnline) {
            triggerSecurityGate(authIPs[i].friendlyName); // Open the Alexa gate!
            authIPs[i].firstSeen = millis();
          }
          authIPs[i].lastSeen = millis();
          authIPs[i].isOnline = true;
        } else {
          authIPs[i].isOnline = false;
        }
        */
        // Execute network check (Sends 2 packets with an explicit timeout)
        if (Ping.ping(targetIP, 2)) {
          // Only trip the gate if it is newly online AND hasn't already opened the gate this trip
          if (!authIPs[i].isOnline && !authIPs[i].hasTrippedGate) {
            triggerSecurityGate(authIPs[i].friendlyName, "");  // Phones pass names natively
            authIPs[i].hasTrippedGate = true;                  // Lock the latch!
            authIPs[i].firstSeen = millis();
          }
          authIPs[i].lastSeen = millis();
          authIPs[i].isOnline = true;
        } else {
          authIPs[i].isOnline = false;
          // Un-latch the device ONLY if it has been gone / unreachable
          authIPs[i].hasTrippedGate = false;
        }
      }

      // 3. Hand control back over to the Bluetooth scanner engine
      if (pBLEScan != nullptr) pBLEScan->start(3, false);
    }

    // 4. DYNAMIC DELAY CONTROLLER: Pauses the background thread based on user settings
    int delaySeconds = networkPingIntervalSeconds;
    if (delaySeconds < 1) delaySeconds = 1;
    vTaskDelay(pdMS_TO_TICKS(delaySeconds * 1000));
  }
}
/*
void triggerSecurityGate(String newlyArrivedName) {
  unsigned long now = millis();
  
  // If the gate is already open, concatenate the new name safely with " + "
  if (securitySystemDisableAuthorised && (now - gateActivationTime < ((unsigned long)voiceGateOpenDurationSeconds * 1000))) {
    if (authorisingDeviceNames.indexOf(newlyArrivedName) == -1) { // Prevent duplicates
      authorisingDeviceNames += " + " + newlyArrivedName;
    }
  } else {
    // Fresh standalone trigger window opening
    securitySystemDisableAuthorised = true;
    authorisingDeviceNames = newlyArrivedName;
  }
  
  gateActivationTime = now; // Lock in or extend the countdown timer
  Serial.print("🔒 VOICE SECURITY GATE TRIPPED BY: ");
  Serial.println(authorisingDeviceNames);
}
*/

void triggerSecurityGate(String newlyArrivedName, String deviceMac) {
  unsigned long now = millis();
  String cleanName = newlyArrivedName;

  // 1. BULLETPROOF LOOKUP: If the name is blank, unassigned, or a generic placeholder, find it!
  if (cleanName == "" || cleanName == "Authorized Bluetooth Key" || cleanName == "null") {
    if (deviceMac != "") {
      deviceMac.toUpperCase();
      // Search the Bluetooth database for the true friendly name
      for (int k = 0; k < authDeviceCount; k++) {
        if (authDevices[k].macAddress == deviceMac) {
          if (authDevices[k].friendlyName != "") {
            cleanName = authDevices[k].friendlyName;
          }
        }
      }
    }
  }

  // 2. SECONDARY FALLBACK: If it's still generic, use a clean text description
  if (cleanName == "" || cleanName == "null") {
    cleanName = "Unknown Proximity Token";
  }

  // 3. CONCATENATION LOGIC: Build the dynamic event string safely
  unsigned long timeWindowMs = (unsigned long)voiceGateOpenDurationSeconds * 1000;
  if (securitySystemDisableAuthorised && (now - gateActivationTime < timeWindowMs)) {
    // Only append if the name isn't already included in the list
    if (authorisingDeviceNames.indexOf(cleanName) == -1) {
      authorisingDeviceNames += " + " + cleanName;
    }
  } else {
    // Fresh standalone trigger cycle window opening
    securitySystemDisableAuthorised = true;
    authorisingDeviceNames = cleanName;
  }

  gateActivationTime = now;  // Update the clock
  Serial.print("🔒 VOICE SECURITY GATE ACTIVE: ");
  Serial.println(authorisingDeviceNames);
}