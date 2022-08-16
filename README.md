# cinema-nmap-scripts
This project contains a set of nmap scripts for use in scanning a projection network to discover what equipment is on that projection network and if possible, extract information from the equipment such as Vendor, Product, and version information.

As nmap can be intrusive on a network and generate a lot of scanning traffic or overload a TCP-IP stack on some lightweight cinema equipment, the user is expected to utilise the scripts in a less impactful way.  For example, only ports used in fingerprinting a device should be scanned and not the many thousands as is performed in a general nmap scan.  A SYN scan or lightweight open socket scan that does not connect and open ta socket is recommended.

## Precaution
Cinema networks typically have live sessions in play.  A basic nmap SYN scan and targeting only a smaller number of ports should have very little impact on the equipment, users utilising these scripts should still take precautions.  If this was to cause an issue, it is most likely an automation IP-socket-message from one device to another that may be lost.  This is "extremely" unlikely, however, the users of the scripts should be aware of this.

## Status
This should be considered alpha and at an early stage of development.
It would be appreciated if any issues spotted by users be posted to the ISSUES section of the GitHub page for this software.

## Target Equipment
The following is the initial set of equipment that scripts will be created for.

| Vendor           | type                  | Status | info |
| ---------------- | --------------------- | ------ | ---- |
| Christie         | Projectors            | InDev  | Have documentation, all I need is access to some projectors. Help needed |
| Dolby            | Player                | DONE   | IMS1000, IMS2000, IMS3000 (DCP2000 and similar era kit unknown.) Initial beta version done, needs testing by the community. |
| Dolby            | Sound Processor CP750 | DONE   | Dolby CP750 Sound Processor |
| Dolby            | Sound Processor CP850/CP950 | help | Different API from CP750, need access to these units, Any Helpers? |
| Barco / Cinionic | Player                | InDev  | ICMP |
| Barco / Cinionic | Projector             | DONE S1,S2 | Barco Series 1&2 ready for testing, S4 different and I would need direct access to one for implementation |
| GDC              | Player                | DONE   | SX2001A, SX3000, SR1000, SX4000, needs testing |
| Qube             | Player XP-D           | DONE   | XP-D |
| Qube             | Player XP-I           | DONE   | XP-D script may work with XP-I but not expected.  Need access to a XP-I, Any helpers?|
| NEC              | Projectors            | DONE   | Series1 and Series2 projectors, needs testing |
| INTEG            | Automation controller | DONE   | JNIOR 400 |
| RLY8             | Automation controller | DONE   | generic IP based 8 output automation controller with Socket Control|
| KMTronic         | Automation controller | DONE   | generic IP based 8 output automation controller with Web and UDP control |
| Edge             | Automation controller | WAIT   | generic IP based 24 output automation controller |
| QSC-USL          | Sound Processor       | DONE   | JSD100, JSD60, CM8, IRC-28C, LSS-200 |
| QSC              | Sound Processor       |        | Appreciate access to these devices to implement, please contact me |

This will be the initial set of target devices.  Vendors and cinema engineers are welcome to submit scripts to this Repo for addition to the scripts.

## Equipment Classification
As part of the detection of equipment, when creating a nse script to detect certain equipment, those items discovered will need to be classified into certain buckets for easy correlation into tool-chain that may use these scripts.

| Classification | Description |
| --- | --- |
| projector | a DCI certified projector. |
| dci-player | a DCI certified cinema player. |
| e-player | a electronic media player such as a BluRay player, or device that plays domestic video codecs (MP4, MV1, MOV, etc) |
| sound-processor | A typical cinema sound processor device including monitor or amplifiers. |
| automation-io | A device that interfaces automation triggers, IN or OUT. |
| accessability | A device that is connected with accessability features. |
| ip-camera | IP-video cameras for audience monitoring or other. |
| tms-server | a TMS server. |
| network-device | a device used for networking such as a switch, firewall or VPN gateway. |
| pos-device | a Point Of Sale device. |
| quality-assurance | a quality assurance device such as a permanent audio or light meter

Note: Some classifications are for completeness purposes only.  For example, pos-devices, IP-cameras are many and users of these scripts may want to implement their own NSE script for detecting the type of cameras they use.  Other general network switches and devices are not expected to have scripts in this repo but again, users may want to add to the scripts for internal use.

# How to use for wildcard scan of a projection network

Once you have nmap installed and downloaded the Repo from Github, you will have the ```cinema-nmap-scripts``` directory available.  Use the following command to scan a projection network and apply all scripts to the scan:

```sudo nmap -n -sS --open -p 21,22,80,111,1125,1173,5000,8080,10000,10001,43680,43728,49153,7142,9200,49155,61408 --script cinema-nmap-scripts/ <Target Ip range as for example: 10.1.2.1-254 or 10.1.2.0/24>```


## Expected results from all devices detected
To help with programmatically digesting the output from the ```nmap``` scripts typically by using the XML output using the arguments ```-oX```, a number of variables are expected to be present for the output for all scripts.

| Variable Name | Description |
| --- | --- |
| classification | The classification of the device detected as defined in the classification table above |
| vendor | The vendor of the device,  i.e. Dolby, NEC, Barco, INTEG, etc |
| serialNumber | The serial number of the device if available. |
| productName | The product name of the device. i.e. NC2000C, JNIOR400, IMS2000 |
| version | A version string identifying the device to a reasonable level. |

For complex devices that contain numerous version information, please use your judgment of how to best represent the version state of the device.

## Recommended ports to scan

It is recommended to only scan for ports that are used for fingerprinting the known cinema devices in use.  The NSE scripts in the header comments name the ports that should be included in a scan for fingerprinting the devices the script targets.  Otherwise, a list of all ports the script uses is as follows.

```21,22,80,111,1125,1173,5000,8080,10000,10001,43680,43728,49153,7142,9200,49155,61408```

It is recommended that in the ```nmap``` command, the ```-p``` argument should target the ports listed above.

## Example
The following is an example of the initial script created.  This script targets the Dolby Cinema Players,  IMS1000, IMS2000 and is likely to work on DCP2000 and IMS3000 devices

to initiate the script, the user MUST HAVE ROOT ACCESS, as to allow for the low level and less intrusive SYN scan to work.

Make sure nmap is installed. (Google it for your target platform)

Copy the scripts from the Github repository
```
git clone https://github.com/jamiegau/cinema-nmap-scripts.git
```
This will download the latest version of the scripts into a directory called `cinema-nmap-scripts`.

Make sure you have root privileges or utilise the *sudo* command as follows.
```
sudo nmap -sS -n --stats-every 5 -p 21,22,80,111,5000,10000 --script cinema-nmap-scripts/cinema-dolby-player --script-args 'username=manager,password=password,getcerts=true' 10.0.0.1-200
```
Note, the script args are optional and need to be used if the default login credentials have been changed.
 - The `-sS` option indicates a SYN scan.
 - `-n` will disable DSN resolution/lookup.  Likely not required under this use model.
 - `--stats-every 5` will have updates printed to the screen every 5 seconds if the scan is taking a considerable time.
 - `-p 21,22,80,111,5000,10000` indicates to ONLY SCAN the ports listed.  This will stop it from scanning many thousands of ports and only scan the ports needed to fingerprint the cinema devices.  If scanning for many different types of devices at the same time, you must name all the ports these scripts need to fingerprint the device you wish to detect.
 - `--script cinema-nmap-scripts/cinema-dolby-player` tells the nmap scripting engine what script to run.  You can give it wild cards, for example, `cinema-nmap-scripts/`cinema-*` would run all scripts available in the directory starting the 'cinema-'.
 - `--script-args 'username=manager,password=password,getcerts=true'`  Arguments are option.  In this case, you can override the common login credentials if they have been changed.  You can also ask for it to pull out the public certificates for the device as part of the scan. By default, Certs are not included.
 - `10.0.0.1-200` is the address range to scan.  In this case, subnet 10.0.0.x and all devices on ip address 1 to 200 on that subnet.  You can also list multiple numbers of IP addresses or ranges.

### Creating your own scripts

While I will attempt to update these scripts when possible, it would be appreciated if others could contribute to these scripts. Direct access to the equipment is required to implement and test the scripts.

The objective of these scripts is to identify the devices on a projection network without causing any potential side effects.  A projection network is critical infrastructure in that you do not want to cause a session to error. (for example, a session stopped unexpectedly or lights come on/off at the wrong time).  Due to this, it is recommended that the ```portrule``` section of the script is more particular in detecting if a device is exactly what we expect before it starts an intrusive test.  This is done by looking at more than a single port to see if it is open or closed.  I refer to this as a port fingerprint, in that a certain number of ports must be active/inactive allowing the script to have a much better idea if a device is what we expect.

The current scripts in this repo are good examples of how to do this, and also why the examples require numerous ports to be scanned when the scripts are run.  However, the suggested ports to scan are still far fewer than what would be scanned by default.

There are 4 main communication paths for querying a device.
1. Basic Socket command
2. SOAP commands over HTTP
3. Binary socket commands
4. Basic HTTP requests

The current scripts have good examples of each of this type of implementation.  It is suggested you review them to get an idea of how to approach a device you would like to implement.


### Expected output
NOTE, this is the expected output.  The CERTIFICATEs are not shown by default and must be turned on as an argument to the script.

```
PORT      STATE SERVICE          REASON
21/tcp    open  ftp              syn-ack ttl 61
22/tcp    open  ssh              syn-ack ttl 61
80/tcp    open  http             syn-ack ttl 61
| cinema-dolby-player:
|   classification: dci-player
|   vendor: Dolby
|   productName: NP-90MS02
|   serialNumber: 340406
|   version: 2.8.2-0, 4.6.1-0
|   hostname: Marloo-c2-IMS2000-broken
|   screenName: Marloo-C2
|   mainSoftwareVersion: 2.8.30-0
|   mainFirmwareVersion: 4.6.10-0
|   SoftwareInfo:
|
|       version: 7.4
|       vendor: Debian
|       title: Host operating system
|       type: OperatingSystem
|
|       version: 2.8.30
|       vendor: Dolby
|       title: Web interface
|       type: Software
|
|       version: 0.3
|       vendor: Dolby
|       title: Video watermarking
|       type: Library
|
|       version: 4.7
|       vendor: Dolby
|       title: Audio watermarking
|       type: Library
|
|       version: 4.6.10-0
|       vendor: Dolby
|       title: MD firmware
|       type: Firmware
|
|       version: 6.1.135-0
|       vendor: Dolby
|       title: MD software
|       type: Software
|
|       version: Fusion2_3.73.06.63.15
|       vendor: Insyde Corp.
|       title: BIOS
|       type: Software
|
|       version: DOREMI-DC-DCPLAYER-MIB 1.4
|       vendor: Dolby
|       title: SNMP agent
|       type: Library
|
|       version: 1.3.1-0
|       vendor: Dolby
|       title: SOAP agent
|       type: Library
|   HardwareInfo:
|
|       version:
|       status: Normal
|       serial: 00000000
|       model: DDR3 1600 MHz
|       vendor: Micron
|       title: Host memory
|       type: Memory
|
|       version: revC
|       status: Normal
|       serial:
|       model: ims
|       vendor: Dolby
|       title: MD board
|       type: AddOnBoard
|   CertInfo:
|
|       title: jp2k smpte
|       cert: -----BEGIN CERTIFICATE-----
| MIIEpDCCA4ygAwIBAgIIAVMbYJsGvpkwDQYJKoZIhvcNAQELBQAwgYsxITAfBgNV
| BAoTGERDMi5TTVBURS5ET1JFTUlMQUJTLkNPTTEaMBgGA1UECxMRREMuRE9SRU1J
| TEFCUy5DT00xIzAhBgNVBAMTGi5VUzEuRENTLkRPTFBISU4uREMyLlNNUFRFMSUw
| IwYDVQQuExxCbkIwaURKTGd5cWlXVWpuMXVxck95Mi9ERUU9MB4XDTA3MDEwMTAw
| MDAwMFoXDTI1MTIwMTAwMDAwMFowgaAxITAfBgNVBAoTGERDMi5TTVBURS5ET1JF
| TUlMQUJTLkNPTTEaMBgGA1UECxMRREMuRE9SRU1JTEFCUy5DT00xODA2BgNVBAMT
| L0xFIFNQQiBNRCBGTSBTTS5JTVMtMzQwNDA2LkRDLkRPTFBISU4uREMyLlNNUFRF
| MSUwIwYDVQQuExxmYWVOb0NXNXhxZGpvSnd3NW9oYktGakVoWEE9MIIBIjANBgkq
| hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4CvSWvnp7DU+EkpHrbkmRxOERy0ZK8Qv
| Y/90yX6X9eWBoYui8tPEmiN4MO4bfvqK2n3OwoSctslY6sxEnWu4A1dxjGxiQwI4
| RgBYWMsObC70TkkR5ncrqEvA9ygiswK5S9olVO4mG5A1HapjflVPcAipnyKgY+Zs
| bBL68IyZGwCJaMKxuynyhspU/i5XsJ9bMIUNYKVxaOZPR1Mn0NUxrCT+TzBN6TPa
| GVOw+6CBK9N4AG4H8XTmMkDRwmsPljTLiEomobQhIsHsMsVB0BDgJJvrF1kSXNRh
| M/uC0dZWljKLHzQEp87vqOXbksWwnhKdFoym1NMbG73V0ELjYz4G0QIDAQABo4H0
| MIHxMAwGA1UdEwEB/wQCMAAwCwYDVR0PBAQDAgQwMB0GA1UdDgQWBBR9p42gJbnG
| p2OgnDDmiFsoWMSFcDCBtAYDVR0jBIGsMIGpgBQGcHSIMkuDKqJZSOfW6qs7Lb8M
| QaGBjaSBijCBhzEhMB8GA1UEChMYREMyLlNNUFRFLkRPUkVNSUxBQlMuQ09NMRow
| GAYDVQQLExFEQy5ET1JFTUlMQUJTLkNPTTEfMB0GA1UEAxMWLkRDUy5ET0xQSElO
| LkRDMi5TTVBURTElMCMGA1UELhMcaE43dVhTTFlpL0VLdFQwTVlhRFdlRTVqM01v
| PYIBAjANBgkqhkiG9w0BAQsFAAOCAQEAORKoaHo0fOEupEvn1FYkCulPL3lUIZt9
| GawKBVD+TATcTMakH3n9J6YpYiOHY1dB3SRJEh5XHwB/C21ayEpuaZP0AXA4kB6x
| 8krO/t1SUmW4N/h9+uqqleCoNVWaLiKnrHgbM6mejzZOCF2cQFu3Phb+S/0pjHsr
| dOILXzWAifz6IvuZlgv6bUAHAE5V6Lec1DXWkcshXYPABUjMkisff6sARHLKNR0w
| f+gZbwZdw3+2eqRMR/yElcxnvVEPlwu6kpXo7K/M7Pew6XQIExqHxSDjmvooHPIf
| kcpXmjgKACZB1r9IADHpOetROoRUhMj5v7r0D8KGp/xsQHefBCMBvQ==
| -----END CERTIFICATE-----
|
|       title: sms
|       cert: -----BEGIN CERTIFICATE-----
| MIIEmTCCA4GgAwIBAgIIAVMbYAbH+cMwDQYJKoZIhvcNAQELBQAwgYsxITAfBgNV
| BAoTGERDMi5TTVBURS5ET1JFTUlMQUJTLkNPTTEaMBgGA1UECxMRREMuRE9SRU1J
| TEFCUy5DT00xIzAhBgNVBAMTGi5VUzEuU01TLkRPTFBISU4uREMyLlNNUFRFMSUw
| IwYDVQQuExxjb2QrQncvUUJsb1BzZkgxSGtnZXlkRDlsUE09MB4XDTA3MDEwMTAw
| MDAwMFoXDTI1MTIwMTAwMDAwMFowgZUxITAfBgNVBAoTGERDMi5TTVBURS5ET1JF
| TUlMQUJTLkNPTTEaMBgGA1UECxMRREMuRE9SRU1JTEFCUy5DT00xLTArBgNVBAMT
| JFNNUy5JTVMtMzQwNDA2LlNNUy5ET0xQSElOLkRDMi5TTVBURTElMCMGA1UELhMc
| U09aZ1Z6YjZWenJKS2w2QWRnN0ZMdlQ4Rk40PTCCASIwDQYJKoZIhvcNAQEBBQAD
| ggEPADCCAQoCggEBAMNWoSDD619TCJgglB7ehBQcdGavvkUEDuC2ueJhQ0AgbzYZ
| vK8MCUx/hva4Tfjh1yIevIDfin94J8CPhS9M3K0uZIrmYvgY97zyeKa7szUF5JsE
| M25Gl3IoKTIgvc+kMT2QvDSRuF3dHr9p8gI6xfnaRCLBSOOUNfS3yxjfB2tDkysd
| vI+R3fZaavCrLSYspsBi2sQyKwGLAP0uqomTtqMTXfPp4RImYbptxnPjP7eFbhv6
| 9LxIedXmp7/5zCsz0vz7oiqV2+PNPMEuSWKVyqZ/pDiT6GZuFhErq6zMUD2wmBqu
| MAe1LH9H56t8fBJbPicWeXysXK8I9bVIt92i4+ECAwEAAaOB9DCB8TAMBgNVHRMB
| Af8EAjAAMAsGA1UdDwQEAwIEsDAdBgNVHQ4EFgQUSOZgVzb6VzrJKl6Adg7FLvT8
| FN4wgbQGA1UdIwSBrDCBqYAUcod+Bw/QBloPsfH1HkgeydD9lPOhgY2kgYowgYcx
| ITAfBgNVBAoTGERDMi5TTVBURS5ET1JFTUlMQUJTLkNPTTEaMBgGA1UECxMRREMu
| RE9SRU1JTEFCUy5DT00xHzAdBgNVBAMTFi5TTVMuRE9MUEhJTi5EQzIuU01QVEUx
| JTAjBgNVBC4THGdCYW9OTEI5MEdmNEFHaFNDM2xVeFllMUN3Zz2CAQIwDQYJKoZI
| hvcNAQELBQADggEBAEtkgEXfDrTYMlJ+Ogw03WHG/5WdhHDrBXDgCdeQ2HwNK/i6
| f5WQjTPkD0cEMMwySe75AODPgFKfBv0NRij6Id1h/LWcm0H4sxGZczxynvxY4Omw
| 89FD/c25Z7n8eneAmVj+fRnzbpcAinkrktGSNbutIJ2qPskSiXq0AFxWfoinEXP+
| ekUr6dTyTmAjT2a2ye4CUXnLrw3or/FNjtysascWfxEkinP0uNnEu6ZWQTRp+peh
| 2HMdzDmYeCixuV2fkfRPze0o7qnIIQWAZ6Ge6jWZxGC+zVarSgW4B4jrGqfeXcAR
| +8KD1ucn9dBYWONLq+9kBxtvWURY9mM+r4B8jNw=
|_-----END CERTIFICATE-----
111/tcp   open  rpcbind          syn-ack ttl 61
5000/tcp  open  upnp             syn-ack ttl 61
10000/tcp open  snet-sensor-mgmt syn-ack ttl 61
Final times for host: srtt: 3138 rttvar: 1372  to: 100000
```

