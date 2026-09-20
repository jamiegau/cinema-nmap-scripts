# cinema-nmap-scripts
This project contains a set of nmap scripts for use in scanning a projection network to discover what equipment is on that projection network and if possible, extract information from the equipment such as Vendor, Product, and version information.

As nmap can be intrusive on a network and generate a lot of scanning traffic or overload a TCP-IP stack on some lightweight cinema equipment, the user is expected to utilise the scripts in a less impactful way.  For example, only ports used in fingerprinting a device should be scanned and not the many thousands as is performed in a general nmap scan.  A SYN scan or lightweight open socket scan that does not connect and open ta socket is recommended.

## Precaution
Cinema networks typically have live sessions in play.  A basic nmap SYN scan and targeting only a smaller number of ports should have very little impact on the equipment, users utilising these scripts should still take precautions.  If this was to cause an issue, it is most likely an automation IP-socket-message from one device to another that may be lost.  This is "extremely" unlikely, however, the users of the scripts should be aware of this.

**CP850-specific warning:** Juan Marin reported that rapid successive TCP
connections locked the CP850 control port until a reboot, although audio playback
continued. The CP850 script uses one connection with pauses between read-only
queries. Do not run it in a tight loop or alongside other scans/pollers targeting
the same processor. Prefer the targeted SYN scan below and avoid broad service
version detection (`-sV`) on a live CP850.

## Dolby CP850

[`cinema-dolby-cp850.nse`](cinema-dolby-cp850.nse) was contributed by
[Juan Marin (@kdmparqueastur-cpu)](https://github.com/kdmparqueastur-cpu) in
[issue #1](https://github.com/jamiegau/cinema-nmap-scripts/issues/1), including
live CP850 verification and the control-port precautions above. Thank you, Juan!

From the repository directory, scan only the required fingerprint ports:

```sh
sudo nmap -n -sS -p 80,111,61408 --script ./cinema-dolby-cp850.nse <target>
```

The fingerprint requires TCP 61408 and HTTP port 80 open, with port 111 not open.
The script queries `sys.macro_preset ?`, `sys.macro_name ?`, `sys.fader ?` and
`sys.mute ?` over one paced connection. It reports the active macro, fader level
and mute status, without changing any settings. No serial number or software
version is reported because those queries were not verified.

The shared ASCII replies do not distinguish CP850 from CP950/CP950A. Without
separate positive model evidence, `productName` is now `CP850/CP950 family`.
When both Dolby scripts are selected, CP950 SOAP discovery runs first. A
confirmed CP950/CP950A is skipped by the CP850 script (no extra control-port
connection); a SOAP-confirmed CP850 retains its exact model name. Juan's
original CP850 hardware test remains valid for the ASCII status queries.

## Recent device additions

| Device family | Discovery available | Validation / limits |
| --- | --- | --- |
| Dolby CP950 / CP950A | Read-only SOAP model, serial and software identity | Documentation-based; offline and real-Nmap local simulator tests, not hardware-tested |
| Dolby CP850 | Paced ASCII macro, fader and mute reads; exact model when separately established | Contributor hardware-tested; shared ASCII-only identity is labelled as a family |
| Barco SP2K / SP4K (Series 4) | HTTP/HTTPS REST model, serial, firmware and family | SP2K-9S hardware-tested; SP4K covered offline only |
| Christie CP2000 / Solaria / CineLife / CineLife+ | Documented read-only cinema identity, plus model/serial where available | Offline and local simulator tests only; hardware verification needed |
| NEC Series 1 / 2 | Existing SNMP discovery hardened against false vendor detection | Now requires an actual NEC model response; regression-tested offline |

The detailed sections below distinguish implemented discovery from hardware-
verified coverage. These additions do not imply control, ingest or TMS support.

## Status
This should be considered alpha and at an early stage of development.
It would be appreciated if any issues spotted by users be posted to the ISSUES section of the GitHub page for this software.

## Target Equipment
The following is the initial set of equipment that scripts will be created for.

| Vendor           | type                  | Status | info |
| ---------------- | --------------------- | ------ | ---- |
| Christie         | Projectors            | Experimental | Documentation-based CP2000/Solaria/CineLife/CineLife+ discovery. Offline and loopback tests only; Christie hardware validation needed. |
| Dolby            | Player                | DONE   | IMS1000, IMS2000, IMS3000 (DCP2000 and similar era kit unknown.) Initial beta version done, needs testing by the community. |
| Dolby            | Sound Processor CP750 | DONE   | Dolby CP750 Sound Processor |
| Dolby            | Sound Processor CP850 | Hardware-tested | Contributed ASCII status reads; exact model requires separate identity. See CP850 precautions above. |
| Dolby            | Sound Processor CP950 / CP950A | Experimental | Dedicated read-only SOAP identity script; documentation-based, simulator-tested, hardware validation needed. |
| Barco / Cinionic | Player                | InDev  | ICMP |
| Barco / Cinionic | Projector             | S1/S2 + S4 | Legacy SNMP support plus read-only SP2K/SP4K REST identification; SP2K-9S hardware-tested. |
| GDC              | Player                | DONE   | SX2001A, SX3000, SR1000, SX4000, needs testing |
| Qube             | Player XP-D           | DONE   | XP-D |
| Qube             | Player XP-I           | DONE   | XP-D script may work with XP-I but not expected.  Need access to a XP-I, Any helpers?|
| NEC              | Projectors            | Hardened | Series 1/2 SNMP; requires positive model evidence to avoid false NEC labels. Hardware testing welcome. |
| INTEG            | Automation controller | DONE   | JNIOR 400 |
| RLY8             | Automation controller | DONE   | generic IP based 8 output automation controller with Socket Control|
| KMTronic         | Automation controller | DONE   | generic IP based 8 output automation controller with Web and UDP control |
| Edge             | Automation controller | WAIT   | generic IP based 24 output automation controller |
| QSC-USL          | Sound Processor       | DONE   | JSD100, JSD60, CM8, IRC-28C, LSS-200 |
| QSC              | Sound Processor       |        | Appreciate access to these devices to implement, please contact me |
| DataSat          | Sound Processor       | DONE   | AP20 Sound processor by DataSat |

This will be the initial set of target devices.  Vendors and cinema engineers are welcome to submit scripts to this Repo for addition to the scripts.

## Equipment Classification
As part of the detection of equipment, when creating a nse script to detect certain equipment, those items discovered will need to be classified into certain buckets for easy correlation into tool-chain that may use these scripts.

| Classification | Description |
| --- | --- |
| projector | a DCI certified projector. |
| dci-player | a DCI certified cinema player. |
| e-player | a electronic media player such as a BluRay player, or device that plays domestic video codecs (MP4, MV1, MOV, etc) |
| sound-processor | A typical cinema sound processor device including monitor or amplifiers. |
| sound-device | An additional IP based device connected to the sound system. i.e. Networked Amps etc. |
| automation-io | A device that interfaces automation triggers, IN or OUT. |
| accessibility | A device that is connected with accessibility features. |
| ip-camera | IP-video cameras for audience monitoring or other. |
| tms-server | a TMS server. |
| network-device | a device used for networking such as a switch, firewall or VPN gateway. |
| pos-device | a Point Of Sale device. |
| quality-assurance | a quality assurance device such as a permanent audio or light meter

Note: Some classifications are for completeness purposes only.  For example, pos-devices, IP-cameras are many and users of these scripts may want to implement their own NSE script for detecting the type of cameras they use.  Other general network switches and devices are not expected to have scripts in this repo but again, users may want to add to the scripts for internal use.

# How to use for wildcard scan of a projection network

Once you have nmap installed and downloaded the Repo from Github, you will have the ```cinema-nmap-scripts``` directory available.  Use the following command to scan a projection network and apply all scripts to the scan:

```sudo nmap -n -sS --open -p 21,22,23,80,443,111,1125,1173,2000,4241,4242,5000,5900,8080,7142,9090,9200,10000,10001,14500,43680,43728,49153,49155,61408 --script cinema-nmap-scripts/ <Target Ip range as for example: 10.1.2.1-254 or 10.1.2.0/24>```


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

```21,22,23,80,443,111,1125,1173,2000,4241,4242,5000,5900,8080,7142,9090,9200,10000,10001,14500,43680,43728,49153,49155,61408```

It is recommended that in the ```nmap``` command, the ```-p``` argument should target the ports listed above.

## Development validation

Run `./test.sh` before committing changes. The test asks nmap to load and compile every cinema NSE script without scanning a network. If `luac` is installed, it also performs a Lua syntax check on each script. If Lua 5.3 or later is installed, it runs offline CP850 and projector tests covering identity replies, fingerprints, HTTPS upgrades, malformed responses, legacy fallback and socket cleanup. No live cinema equipment is contacted by these tests.

Run `./test.sh --loopback` to additionally exercise real Nmap against local
Christie TCP and Dolby SOAP simulators (Python 3 required). These bind only
OS-assigned localhost ports and do not contact cinema equipment. CP950 candidate
selection and CP850/CP950 duplicate-suppression checks are included offline.

### Dolby CP950 / CP950A (experimental)

`cinema-dolby-cp950.nse` identifies the exact model through the Dolby
SystemManagement compatibility SOAP service, normally on TCP 9090:

```sh
sudo nmap -n -sS -p9090,61408 --script ./cinema-dolby-cp950.nse PROCESSOR_IP
```

The script sends only `getDeviceInfo`, followed by `getSerialNumber` and
`getSystemVersions` if needed. Output uses `classification=sound-processor`,
`vendor=Dolby`, `productName=CP950` or `CP950A`, plus `serialNumber` and `version`
when returned with recognised identity labels. Board/Atmos certificate serials
are not substituted for the chassis serial. No default login, SOAP setter,
reboot, macro, fader, mute or ASCII control-port command is sent.

It requires positive model evidence, refuses redirects, limits each HTTP
request to 2.5 seconds and 32 KiB, and rejects invalid/faulted XML. Authentication
requirements, blocked SOAP access or unrecognised identity labels can prevent
exact identification. Missing optional fields are omitted, not guessed.

If an older Catcher scan includes only TCP 61408, that open port selects a
candidate for a SOAP query to 9090; it does not open an ASCII connection. If
both ports are scanned, the script runs once on 9090. An explicitly closed or
filtered 9090 is not retried via 61408. For an alternative SOAP port, scan it
and set `--script-args cinema-dolby-cp950.soap-port=PORT`.

Source: **Dolby Cinema Processor CP950 and Dolby Atmos Cinema Processor CP950A
Manual**, Issue 13, part 8800298, 15 August 2024: pp. 163-165 describe the SOAP
API and CP850-compatible interface; pp. 166-168 describe the shared ASCII
commands and SNMP identity support. [Official manual](https://professional.dolby.com/siteassets/products/cp950a/dolby_cp950-cp950a_manual_issue_13.pdf).
Request names, namespaces, reply structure and endpoint come from Dolby's
`SystemManagement.wsdl` / `SystemManagement.xsd` v1.0/v1.1 definitions already
present in Catcher's `SmsTools/Dolby/wsdl/cp`. No proprietary MIB OIDs have been
invented; the manual refers to a separate downloadable MIB, not included here.

**Not hardware-tested.** The WSDL defines key/value replies but not all model
and version key spellings. Recognised labels are deliberately conservative;
fixtures are synthetic, not captured from a CP950. Hardware feedback is needed
to confirm field naming and firmware-specific behaviour. `CP850/CP950 family`
in results means the ASCII protocol was recognised but the exact model was not.

### Christie cinema projectors (experimental)

`cinema-christie-projector.nse` uses serial-over-Ethernet on TCP 5000, already
included in Catcher's scan ports:

```sh
sudo nmap -n -sS -p5000 --script ./cinema-christie-projector.nse PROJECTOR_IP
```

For an explicitly configured alternative port, include it in `-p` and set
`--script-args cinema-christie-projector.port=PORT`; the script never searches
other ports automatically.

The initial `PNG?` reply must contain a documented cinema projector type:
41/42 (CP2000-ZX/M), 46 (Solaria/Series 2), 60 (CineLife/Series 3), or 71
(CineLife+/Series 4). Internal controller/board types and unknown types are
rejected. Open port 5000 alone does not identify Christie.

One connection is used, with a 2.5-second connection/query timeout and bounded
reply size. Only `PNG?` and selected `SST` group reads are sent. There are no
logins, default passwords, configuration writes, power or playback commands.
Disabled/restricted remote access can prevent or limit discovery; the script
does not change access settings. Avoid repeated scans during performances.

Output provides `classification=dci-projector`, `vendor=Christie`, `family`,
and `version` (the primary CPU's PNG version, not an IMB or whole-package build).
For type 46, model/serial enrichment reads `SST+CONF?` and, if needed,
`SST+SERI?`. For types 60/71 it reads the documented `SST+SERI?` and
`SST+SYST?` groups. Only recognised model labels and explicitly labelled
projector chassis serials are accepted. Exact model and serial fields are
omitted when unavailable; a component/IMB serial is never substituted.
Types 41/42 get basic PNG identification only.

**No Christie projector has been hardware-tested for this implementation.**
The manuals establish the command families and reply format, but do not list
all CineLife status-item labels or guarantee where an exact model is returned.
Consequently modern model/serial enrichment is best-effort and needs field
verification. The status labels/indices in the tests are synthetic examples,
not evidence of a particular firmware's output. Unknown labels are deliberately
ignored. Please report redacted discovery XML and identity-group replies when
hardware becomes available.

Primary documentation consulted:

- [Solaria API Guide, 020-100966-01](https://www.christiedigital.com/globalassets/resources/public/020-100966-01-christie-lit-man-appl-solaria-api.pdf), PNG pp. 34-35 and SST p. 43: legacy device codes, configuration/serial groups, legacy status severity.
- [CineLife 2.2.0 Serial Commands, 020-102714-01](https://www.christiedigital.com/globalassets/resources/public/020-102714-01-christie-lit-tech-ref-cinelife-v2.2.0.pdf), PNG p. 26, SST pp. 29-30: type 60, status reply fields and read-only groups.
- [CineLife+ Serial Commands](https://www.christiedigital.com/globalassets/resources/public/020-103075-12-Christie-LIT-TECH-REF-CineLifePlus-API.pdf), pp. 7-10, 32-33 and 36-37: TCP 5000, framing, type 71, status groups and severity. The downloaded document identifies itself as 020-103075-11, January 2026, despite the URL's `-12` suffix.
- [Christie Cinema technical-support FAQ](https://www.christiedigital.com/help-center/technical-support/cinema-tech-support-faq/): Series 2 serial-over-Ethernet port 5000.

`./test.sh` includes mocked Christie tests. For a real Nmap socket/XML check
against a **local synthetic fixture only**, run
`python3 tests/christie-loopback.py`; it binds an OS-assigned localhost port.

Catcher pins this repository to a commit in its backend Dockerfile. Update
`CINEMA_NMAP_SCRIPTS_REF` to a validated revision and rebuild the backend image
to include these changes. Afterwards run **Single Scan and Update** to replace
an existing cached discovery record.

### Barco Series 4 / SP projectors

`cinema-barco-projector.nse` uses the Series 4 REST API's read-only
`/rest/system/modelname`, `serialnumber`, `firmwareversion` and `familyname`
properties. It requires a valid SP2K/SP4K model response before identifying a
device as Barco; open ports alone are not proof of a vendor.

```sh
sudo nmap -n -sS -p80,443 --script ./cinema-barco-projector.nse PROJECTOR_IP
```

HTTP redirects to HTTPS are supported only on the same target IP and the same
identity path. An existing Catcher scan that includes port 80 but not 443 still
works with the projector's HTTP-to-HTTPS redirect. For HTTPS-only installations,
include port 443. Only one result is emitted when both ports are scanned.

No authentication or default-password guessing is performed unless credentials
are supplied using `cinema-barco-projector.username` and
`cinema-barco-projector.password`. Prefer a protected `--script-args-file` when
credentials are required. No power, lens, shutter, macro or configuration
commands are sent. The tested SP2K-9S permits these identity reads without a login.

Output uses the established fields `classification=dci-projector`, `vendor=Barco`,
`productName`, `serialNumber` and `version`. Catcher maps `version` to its Software
column. Missing optional fields are omitted, not fabricated. SP4K uses the same
documented API and is covered offline; it has not yet been hardware-tested here.
Series 1/2 retain their legacy port fingerprint and SNMP path. The NEC script
now requires a model returned by NEC's private MIB before emitting an NEC label.

The script changes must be included in the Catcher backend image (or installed
in its configured scripts directory), then run **Single Scan and Update** for an
existing unclassified or incorrectly classified device. Merely updating the
scripts does not rewrite cached discovery records.

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
