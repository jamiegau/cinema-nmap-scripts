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
- Dolby Cinema Players - `DONE` - Initial beta version done, needs testing by the community.
- Barco/Cineionic Cinema Players
- GDC Cinema Players - if licensing allows
- Qube Cinema Players
- NEC projectors
- Barco/Cinionic Projectors
- INTEG Jnior automation controllers
- RLY8 automation controllers
- QSC JSD60 and JSD80 cinema sound processors
- More to come, please submit your own.....

This will be the initial set of target devices.  Vendors are welcome to submit scripts to this Repo for addition to the scripts.

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


