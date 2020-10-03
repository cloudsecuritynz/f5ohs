
### What is F5OHS?
F5 Operation Health Snapshot is a (PIP installable) python package which uses the 
F5 iControl REST API to gather point-in-time F5 device (appliance or VE) operational status for 20+ configuration objects and key device metrics (full list below.) The output is two formatted text strings, either written to a file or returning the formatted strings for the calling python script to use, e.g. to be sent in the body of an email set to run daily with cron/task scheduler.
 

F5OHS is very simple to use, requiring only device IP, username and password (or API token,) to pull the data from almost any current F5 device (appliance/VE) running __*versions 12.1.5 and up*__. Optional parameters allow you to tailor the output to your requirements. 
F5OHS will use the API to automatically verify what F5 modules are enabled and test only configured and enabled objects from those modules. Disabled objects are ignored. You dont need to provide any other details, if a module/object is not provisioned and enabled then the script will ignore it. 

### What checks are performed?
1. Device Uptime in days, hours and minutes
1. Device Status,i.e. is the device online/offline and active/standby
1. Device NTP synchronisation: in ms
1. Device Memory usage %
1. Device CPU usage % (average across all CPUs)
1. Device Disk Mount usage %
1. Device Disk Inode usage %
1. Appliance Fans, up or down
1. Appliance PSUs, up or down
1. Appliance Chassis temerature in degrees C
1. Network Trunks, up or down 
1. Network Interfaces, up or down
1. SSL/TLS Certificates due to expire with X (default 31) days (F5 default and bundle certs igrored)
1. LTM Virtual Servers status/availability
1. APM Connectivity: total number of current user connections (not including duplicates caused by using DTLS)
1. GTM/DNS number of Data Centre objects and their current status/availability
1. GTM/DNS number of Server objects and their current status/availability
1. GTM/DNS number of DC Links and their current status/availability
1. GTM/DNS number of WideIPs and their current status/availability
1. GTM/DNS BIND availability, whether BIND responds to DNS requests for wideIP A records (other types of wideIP signored)
1. GTM/DNS External DNS Servers (in Listener LB pools) availability and response to DNS requests

### What can F5OHS be used for?
F5OHS offers Ops teams and other IT teams the ability get a quick grasp of the operational health of their F5 devices. The metrics provided give a quick point-in-time overview of device health and allow support teams to quickly identify and correct smaller issues before they become larger issues and impact the working of the device. F5OHS was born out of the need for the authors' customers to perform manual daily operational checks as part of the requirements for external auditors. F5OHS drastically reduces the time needed to perform these checks by providing a text snapshot which takes seconds to review, rather than many minutes to login to F5 devices manually and perform the checks. 

### F5OHS example and explanation
Output is usually two (python strings) - **Summary** and **Detailed**. Is it possible to output only one of those, as required.

Output for both Summary and Detailed is intuitive and starts with a timestamp, the device hostname, platform (appliance/VE,) BIGIP version and, optionally, the serial number. All automatically pulled using the API. 

The **Summary** provides a quick overview of the F5 device status that can reviewed in seconds. Please see the example here:

![summary](/images/f5ohs_summary.png "Summary Output")

**Summary** output (see above) presents a concise summarisation of the **Detailed** output data for each metric (F5 configuration object/appliance parameter.) 
Numerical values are added, indicating percentage UP/DOWN, temperature, milliseconds etc, or an OK or DOWN, eg for Fans and PSUs, to each line (metric) in the **Summary**.
Furthermore, the F5 objects listed here show the number of objects UP/Available as a proportion of the total, where *total **=** objects Available **+** objects Offline*:
* NET Trunks, 
* LTM VIPs, 
* GTM wideIP, 
* GTM Data Centers, 
* GTM Servers, 
* GTM Links all, 
* GTM BIND, 
* GTM External DNS servers

These above listed objects are only counted in the relevant **Summary** line if they are enabled and have monitoring configured. Objects with Disabled and Unknown status' are not counted.    

#### Summary Thresholds
Most metrics are analysed against thresholds and a warning of **'!!!!'** (configurable) appended to that line in the summary output if the threshold is reached. 
For example:
```
LTM * VIPs: 16/20 UP 	!!!!
```
From the above, there are 20 VIPs total which have status Available **OR** Offline. Of those 20, 16 are Available/Up.

The below thresholds are configurable:
* memory usage (%)
* cpu usage (%)
* disk/inode usage (%)
* ssl cert expiry threshold (days)


**Detailed** output provides more details for each metric, listing each configured object/metric and its status. Ops engineers can use the **Detailed** output to get further information on any issues highlighted in the **Summary**.

[Detailed example](/images/f5ohs_detailed.png "Detailed Output")



### What F5 models/BIGIP software versions does F5OHS work on?
F5OHS has been tested on i4000,i5000 and i10000 appliances and various VE editions.
F5OHS should work on any version 12.1.5 or higher. It has been tested on LTS versions:
* 12.1.5
* 13.1.3
* 14.1.2
* 15.1.0

### What is F5OHS not?
F5OHS is not a replacement for any real-time operational monitoring tools. Organisations should, ideally, be monitoring the device with SNMP (and augmenting with sflow) and sending all logs to a SIEM. 

### Does it work with partitions?
In general, APM and GTM dont play nice with partitions, so partitions shouldnt be a big part of the checking.
Its been tested to work with partitions for LTM VIPs and GTM wideIPs. 
 

### How to use F5OHS
#### Authentication options:
* Basic and Token authentication can be used. If using basic, access to bash via API will require an admin account be used. [An overview of iControl permissions is here.](https://support.f5.com/csp/article/K84925527)

* More fine grained API Token control is detailed [here by Satoshi Toyosawa on DevCentral](https://devcentral.f5.com/s/articles/icontrol-rest-fine-grained-role-based-access-control-30773)


### Future updates
* run from cli
* function to get API Token (run from from cli) and automatically run f5snapshot() 
