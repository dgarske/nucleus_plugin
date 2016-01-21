===========================================================================
Nucleus Samples - Networking (SSL Lite Client - wolfSSL)
===========================================================================

Purpose & Goals
---------------

This sample application illustrates the use of Networking Middleware API's
to implement a simple TLS client on the target.  The demo performs the
following:

    * Tries to connect to the IP specified in code.
    * Performs TLS handshake.
    * Sends a "Hello World" to the TLS server
    * Checks for echoed response.
    * Closes connection.

What You Will Need
------------------

To run this sample application you will need a Nucleus supported platform
with a BSP that has a Networking device enabled and SSL Lite 
Nucleus kernel option enabled.

Demo Configuration
------------------

It is recommended to use the available ssl_lite.config file for minimal configuration.

If using Nucleus ReadyStart, open the Nucleus Configuration editor for the build configuration to be worked on: 
    * Select a template to apply by selecting 'Import Configuration' drop down action and clicking 'min_net'
    * Select 'Replace' to overwrite the existing configuration with the selected template

To manually enable SSL Lite in a configuration.
    * Select 'nu' -> 'os' -> 'net' -> 'ssl' -> 'lite'.

If using Nucleus Source Code, the correct configuration file is selected via the makefile

Rebuild the Nucleus System Project once changes are saved.

How To Run The Application
--------------------------

Load and run the tls_client.out file. 
Using the Nucleus targets STDIO (serial) port, enter the IP address and port.
Results of the TLS connection and echoed response will be printed to STDOUT.
