# cinema-nmap-scripts
This project contains a set of nmap scripts for use in scanning a projection network to discover what equipment is on that projection network and if possible, extract information from the equipment such as Vendor, Product, and version information.

As nmap can be intrusive on a network and generate a lot of scanning traffic or overload a TCP-IP stack on some light weight cinema equipment, the user is expected to utilise the scripts in a less impactful way.  For example, only ports used in fingerprinting a device should be scaned and not the many thousands as is performed in a general nmap scan.  A SYN scan or light weight open socket scan that does not actually connect and open ta socket is recommended.

## Precaution
Cinema networks typically have live sessions in play.  A basic nmap SYN scan and targeting only a smaller number of ports should have very little inpact on the equipment, users utilising these scripts should still take precautions.  If this was to cause an issue, it is most likely an automation IP-socket-message from one device to another that may be lost.  This is "extremely" unlikely, however the users of the scripts should be aware of this.

## Status
This should be considered alpha and at an early state of development.
It would be appriciated if any issues spotted by users be posted to the ISSUES section of the GitHub page for this software.

## Target Equipment
The following is the initial set of equipment that scripts will be created for.

| Vendor | type | Status | info |
| --- | --- | --- | --- |
| Dolby | Player | DONE | IMS1000, IMS2000, IMS3000 (DCP2000 and similar era kit unknwon.) Initial beta version done, needs testing by the community. |
| Dolby | Sound Processor |   | CP750, CP850, CP950 |
| Barco / Cinionic | Player |   | ICMP |
| GDC | Player |   | SX2001A, SX3000, SR1000, SX4000 |
| Qube | Player |   | XP-D |
| NEC | Projectors |   | Series1 and Series2 projectors |
| INTEG | Automation controler |   | JNIOR 400 |
| RLY8 | Automation controler |   | generic IP based automation controler |
| QSC-USL | Sound Processor |   | JSD80, JSD60 |
| QSC | Sound Processor |   | Other |

This will be the initial set of target devices.  Vendors and cinema engineers are welcome to submit scripts to this Repo for addition to the scripts.

## Example
The following is an example of the initial script created.  This script targets the Dolby Cinema Players,  IMS1000, IMS2000 and is likely to work on DCP2000 and IMS3000 devices

to initiate the script, the user MUST HAVE ROOT ACCESS, as to allow for the low level and less intrusive SYN scan to work.

Make sure nmap is installed. (Google it for your target platform)

Copy the scripts from the Github repository
```
git clone https://github.com/jamiegau/cinema-nmap-scripts.git
```
This will download the latest version of the scripts into a directory called `cinema-nmap-scripts`.

Make sure you are root, or utilise the *sudo* command as follows.
```
sudo nmap -sS -n --stats-every 5 -p 21,22,80,111,5000,10000 --script cinema-nmap-scripts/cinema-doly-player --script-args 'username=manager,password=password,getcerts=true' 10.0.0.1-200
```
Note, the script args are optional and need to be used if the default login credentials have been changed.
 - The `-sS` option indicates a SYN scan.
 - `-n` will disable DSN resolution/lookup.  Likely not required under this use model.
 - `--stats-every 5` will have updates printed to screen every 5 seconds if the scan is taking a considerable time.
 - `-p 21,22,80,111,5000,10000` indicates to ONLY SCAN the ports listed.  This will stop it scanning many thousands of ports and only scan the ports needed to fingerprint the cinema devices.  If scanning for many different types of devices at the same time, you must name all the ports these scripts need to fingerprint a device.
 - `--script cinema-nmap-scripts/cinema-doly-player` tells the nmap scripting engine what script to run.  You can give it wild cards, for example `cinema-nmap-scripts/cinema-*` would run all scripts availabe in the directory starting the 'cinema-'.
 - `--script-args 'username=manager,password=password,getcerts=true'`  Arguments are option.  In this case you can override the common login cridentials if they have been changed.  You can also ask for it to pull out the public certificates for the device as part of the scan. By default Certs are not included.
 - `10.0.0.1-200` is the address range to scan.  In this case, subnet 10.0.0.x and all devices on ip address 1 to 200 on that subnet.  You can also list multiple numbers of IP addresses or ranges.

### Expected output
NOTE, this is the exoected output.  The CERTIFICATEs are not shown by default and must be turned on as a argument to the script.
```
PORT      STATE SERVICE          REASON
21/tcp    open  ftp              syn-ack ttl 61
22/tcp    open  ssh              syn-ack ttl 61
80/tcp    open  http             syn-ack ttl 61
| cinema-dolby-player:
|   hostname: Marloo-c2-IMS2000-broken
|   screenName: Marloo-C2
|   productName: NP-90MS02
|   serialNumber: 340406
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
|       chain: -----BEGIN CERTIFICATE-----
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
| -----BEGIN CERTIFICATE-----
| MIIEhzCCA2+gAwIBAgIBAjANBgkqhkiG9w0BAQsFADCBhzEhMB8GA1UEChMYREMy
| LlNNUFRFLkRPUkVNSUxBQlMuQ09NMRowGAYDVQQLExFEQy5ET1JFTUlMQUJTLkNP
| TTEfMB0GA1UEAxMWLkRDUy5ET0xQSElOLkRDMi5TTVBURTElMCMGA1UELhMcaE43
| dVhTTFlpL0VLdFQwTVlhRFdlRTVqM01vPTAeFw0wNzAxMDEwMDAwMDBaFw0yNTEy
| MzEyMzU5NTlaMIGLMSEwHwYDVQQKExhEQzIuU01QVEUuRE9SRU1JTEFCUy5DT00x
| GjAYBgNVBAsTEURDLkRPUkV
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
|       chain: -----BEGIN CERTIFICATE-----
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
| -----END CERTIFICATE-----
| -----BEGIN CERTIFICATE-----
| MIIEhzCCA2+gAwIBAgIBAjANBgkqhkiG9w0BAQsFADCBhzEhMB8GA1UEChMYREMy
| LlNNUFRFLkRPUkVNSUxBQlMuQ09NMRowGAYDVQQLExFEQy5ET1JFTUlMQUJTLkNP
| TTEfMB0GA1UEAxMWLlNNUy5ET0xQSElOLkRDMi5TTVBURTElMCMGA1UELhMcZ0Jh
| b05MQjkwR2Y0QUdoU0MzbFV4WWUxQ3dnPTAeFw0wNzAxMDEwMDAwMDBaFw0yNTEy
| MzEyMzU5NTlaMIGLMSEwHwYDVQQKExhEQzIuU01QVEUuRE9SRU1JTEFCUy5DT00x
| GjAYBgNVBAsTEURDLkRPUkVNSUxBQlMuQ09NMSM
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

