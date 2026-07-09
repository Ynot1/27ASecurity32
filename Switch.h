#ifndef SWITCH_H
#define SWITCH_H
 
#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <WiFiUDP.h>
#include "CallbackFunction.h"

 
class Switch {
private:
        WebServer *server = NULL;
        WiFiUDP UDP;
        String serial;
        String persistent_uuid;
        String device_name;
        unsigned int localPort;
        CallbackFunction onCallback;
        CallbackFunction offCallback;
        bool switchStatus;
          
        void startWebServer();
        void handleEventservice();
        void handleUpnpControl();
        void handleRoot();
        void handleSetupXml();
public:
        Switch();
        Switch(String alexaInvokeName, unsigned int port, CallbackFunction onCallback, CallbackFunction offCallback);
        ~Switch();
        String getAlexaInvokeName();
        void serverLoop();
        void respondToSearch(IPAddress& senderIP, unsigned int senderPort);
        void sendRelayState();
};
 
#endif
