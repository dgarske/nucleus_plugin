===========================================================================
Nucleus Samples - Networking (MQTT Client - wolfMQTT)
===========================================================================

Purpose & Goals
---------------

This sample application illustrates the use of Networking Middleware API's
to implement a simple MQTT client on the target.  The demo performs the
following:

    * Connects to iot.eclipse.org using TLS
    * Subscribes to topic and publishes to it.
    * Waits for new publish messages.

What You Will Need
------------------

To run this sample application you will need a Nucleus supported platform
with a BSP that has a Networking device enabled and the MQTT Client 
Nucleus kernel option enabled.

Demo Configuration
------------------

It is recommended to use the available mqtt_client.config file for minimal configuration.

If using Nucleus ReadyStart, open the Nucleus Configuration editor for the build configuration to be worked on: 
    * Select a template to apply by selecting 'Import Configuration' drop down action and clicking 'min_net'
    * Select 'Replace' to overwrite the existing configuration with the selected template

To manually enable SSL Lite in a configuration.
    * Select 'nu' -> 'os' -> 'net' -> 'mqtt' -> 'mqttclient'.

If using Nucleus Source Code, the correct configuration file is selected via the makefile

Rebuild the Nucleus System Project once changes are saved.


How To Run The Application
--------------------------

Load and run the mqtt_client.out file. View the results on the STDIO (serial) port.
