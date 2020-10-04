import json, datetime, re, time, ssl, base64, urllib.request, urllib.parse, urllib.error


def f5snapshot(host, username="", password="", token="", summary_only=False,
                detailed_only=False, serial=True, filePath="", alert_message="\t!!!!",
                memory_alert=90, cpu_alert=80, disk_usage=95, ssl_expire_days=31,
                fqdns=['google.com', 'cnn.com', 'f5.com']):
    """Queries F5 device API to get current status for various configuration objects
    and collects those status responses into two strings (summary and detailed)
    to be returned to the calling python script OR (optionally) saved to a text file

    Note:
        Only Requires modules found in python standard library
        Works in python environment 3.6+ due to use of f-strings

    Args:
        host (string): the F5 device IP being queried
        username (str, optional): the account name used to acces the F5 API. Defaults
            to empty string.
        password (str, optional): the account password used to acces the F5 API.
            Defaults to empty string.
        token (str, optional): the auth token used to acces the F5 API. Defaults to
            empty string.
        summary_only (bool, optional): return only the summary status string.
            Defaults False.
        detailed_only (bool, optional): return only the detailed status string.
            Defaults False.
        serial (bool, optional): include F5 device serial number in return string.
            Defaults True.
        filePath (str, optional): drive path location to write to text file the
            summary and/or detailed strings. If filePath is empty string, return
            summary/detailed Strings to calling python script - ie no file
            written. Defaults to empty string.
        alert_message (str, optional): substring used in return string to highlight
            where config object status response not expected or where config object
            status response above threshold. Default is "\t!!!!".
        memory_alert (int, optional): percentage memory usage threshold, above which
            alert raised in return string. Default is 90.
        cpu_alert (int, optional): percentage cpu usage threshold, above which
            alert raised in return string. Default is 80.
        disk_usage (int, optional): percentage disk usage (disk and inode)
            threshold, above which alert raised in return string. Default is 95.
        ssl_expire_days (int, optional): number of days until SSL/TLS cert expiry
            threshold, below which alert raised in return string. Default is 31.
        fqdns (list, optional): list of fqdns used to test BIND and/or external
            DNS server responses. Default is ['google.com', 'cnn.com', 'f5.com'].

    Returns:
        summary (string): only summary string output returned if ONLY summary_only=True
        detailed (string): only detailed string output returned if ONLY detailed_only=True

        Otherwise, if both summary_only and detailed_only are equal to True/False, both summary
        and detailed strings returned.

        If filePath contains a path, then the above outcome will also be saved to a txt file
        at the specified (filePath) location

    Raises:
        IOError: ERROR writing to file

    Examples:
        Return summary and detailed output strings using admin username and password:
            >>>summaryString, detailedString = f5ohs.f5snapshot("10.10.10.10",
                                            username="admin", password="aP@ssw0rd")

        Return summary and detailed strings using API token:
            >>>summaryString, detailedString = f5ohs.f5snapshot("10.10.10.10",
                                            token="alphanumericAPITokengoeshere")

        Return only summary string using admin username and password:
            >>>summaryString = f5ohs.f5snapshot("10.10.10.10", username="admin",
                            password="aP@ssw0rd", summary_only=True)

        Return only detailed string using API token:
            >>>detailedString = f5ohs.f5snapshot("10.10.10.10",
                             token="alphanumericAPITokengoeshere", detailed_only=True)

        Return only detailed string using admin username and password and output to
        file. NOTE - if writing to a file on a Windows system, either use double
        backslash (e.g. "C:\\f5snapshot\\F5devicename_date.txt") or prefix the quoted
        filename with r to denote a raw string in python
        (e.g. filePath=r"C:\f5snapshot\F5devicename_date.txt"):
            >>>f5ohs.f5snapshot("10.10.10.10", username="admin",
                             password="aP@ssw0rd", detailed_only=True,
                             filePath=r"C:\f5snapshot\F5devicename_date.txt")

        Return summary and detailed strings using API token and non-default alert message:
            >>>summaryString, detailedString = f5ohs.f5snapshot("10.10.10.10",
                                            token="alphanumericAPITokengoeshere",
                                            alert_message="*ALARM*")

        Return summary and detailed strings using API token WITHOUT including
        the F5 device serial number:
            >>>summaryString, detailedString = f5ohs.f5snapshot("10.10.10.10",
                                            token="alphanumericAPITokengoeshere",
                                            serial=False)

        Return only summary string using admin username and password and non-default
        memory and disk alert thresholds:
            >>>summaryString = f5ohs.f5snapshot("10.10.10.10", username="admin",
                            password="aP@ssw0rd", memory_alert=70, disk_usage=80)

        Return only detailed string using admin username and password and non-default
        SSL/TLS expiry thresholds:
            >>>detailedString = f5ohs.f5snapshot("10.10.10.10", username="admin",
                             password="aP@ssw0rd", ssl_expire_days=62)

        Return summary and detailed output strings using admin username and
        password and non-default fqdns:
            >>>summaryString, detailedString = f5ohs.f5snapshot("10.10.10.10",
                                            username="admin", password="aP@ssw0rd",
                                            fqdns=['example1.com','example2.com'])

    """

    def __f5_api_request_post(path, payload):
        """Makes API POST call to defined F5 device and returns string response

        Args:
            path (str): path used to make API call request
            payload (dict): payload used for API POST call request

        Note:
            uses args host/username/password/token from parent function f5snapshot()

        Returns:
            status (string): contains API response payload if response HTTP status
                in range 200-230; else contains error string

        Raises:
            urllib.error.HTTPError: HTTP Error in API call
            urllib.error.URLError: URL Error in API call
        """
        conSsl = ssl.create_default_context()  #create SSL context
        conSsl.check_hostname = False #ignore hostname issues
        conSsl = ssl._create_unverified_context()
        status = ""
        params = json.dumps(payload).encode('utf8')
        req = urllib.request.Request("https://"+host+path, data = params, \
        headers = {'content-type': 'application/json'})
        #check if API token provided and use that for auth, else use un/pwd
        if token:
            req.add_header('X-F5-Auth-Token', token)
        else:
            credentials = (f'{username}:{password}')
            encoded_credentials = base64.b64encode(credentials.encode('ascii'))
            req.add_header('Authorization', f' Basic {encoded_credentials.decode("ascii")}')
        try:
            resp = urllib.request.urlopen(req, context=conSsl)
        except urllib.error.HTTPError as e:
            status = f'ERROR POST request {path} failed: {e.reason}'
        except urllib.error.URLError as e:
            status = f'ERROR POST request {path} failed: {e.reason}'
        else:
            statusCode = resp.getcode()
            status = resp.read().decode('utf-8') if statusCode in range(200,230) \
            else "ERROR - status code:"+str(resp.getcode())
        return status

    def __f5_api_request_get(path):
        """Makes API GET call to defined F5 device and returns string response

        Args:
            path (str): path used to make API call request

        Note:
            uses args host/username/password/token from parent function f5snapshot()

        Returns:
            status (string): contains API response payload if response HTTP status
                in range 200-230; else contains error string

        Raises:
            urllib.error.HTTPError: HTTP Error in API call
            urllib.error.URLError: URL Error in API call
        """
        conSsl = ssl.create_default_context()  #create SSL context
        conSsl.check_hostname = False #ignore hostname issues
        conSsl = ssl._create_unverified_context()
        status = ""
        req = urllib.request.Request("https://"+host+path, headers = {'content-type': 'application/json'})
        #check if API token provided and use that for auth, else use un/pwd
        if token:
            req.add_header('X-F5-Auth-Token', token)
        else:
            credentials = (f'{username}:{password}')
            encoded_credentials = base64.b64encode(credentials.encode('ascii'))
            req.add_header('Authorization', f' Basic {encoded_credentials.decode("ascii")}')
        try:
            resp = urllib.request.urlopen(req, context=conSsl)
        except urllib.error.HTTPError as e:
            status = f'ERROR GET request {path} failed: {e.reason}'
        except urllib.error.URLError as e:
            status = f'ERROR GET request {path} failed: {e.reason}'
        else:
            statusCode = resp.getcode()
            status = resp.read().decode('utf-8') if statusCode in range(200,230) \
            else "ERROR - status code:"+str(resp.getcode())
        return status

    def __get_filesystem_usage(filesystem):
        """Parses response payload of '/mgmt/tm/util/bash/ df' API call and returns
        string containing all filesystems and their current % in use

        Args:
            filesystem (str): defining whether disk or inode output of
                                linux 'df' requested

        Note:
            uses arg disk_usage from parent function f5snapshot()

        Returns:
            output (str): listing in rows the filestore and in-use %
            full (list): list of filestore names with usage above disk_usage %
        """
        output = ""
        filesystemInteresting, full = [], []
        filesystemRows = 0
        for line in filesystem:
            #remove substrings of multiple whistpaces and replace with single whitespace
            disk = " ".join(line.split())
            #remove the first row of output which is column headings
            if not disk.startswith('Filesystem'):
                #v13 Bigip adds \n to end of long filesystem names (first column) for df command;
                #command. So a single entry will be spread across 2 lines. Find those and concatenate
                #with the rest of the entry (ie add to subsequent list position)
                if disk.strip().count(" ") == 0:
                    if disk != "":
                        disk = disk+" "+filesystem[filesystemRows+1]
                        disk = " ".join(disk.split())
                        filesystemInteresting.append(disk)
                #if no \n at end of filesystem (first column) value in df output
                elif disk.strip().count(" ") == 5:
                    filesystemInteresting.append(disk)
            filesystemRows += 1
        #loop through and save mount name and usage %
        for line in filesystemInteresting:
            mount = line.split(" ")[5]
            #dont allow RO filesystems to be part of the result
            if mount != "/usr" and mount.startswith("/var/apm/mount/") == False:
                inUse = int(line.split(" ")[4][:-1])
                output += f"\n{inUse}%\t{mount}"
                #create list of any mounts above 'full' threshold
                if inUse > disk_usage:
                    full.append(mount)
        return output, full

    def __get_provisioned(name):
        """Verifies if F5 module is provisioned on the F5 host/appliance and returns
        boolean value to confirm

        Args:
            name (str): name of module (eg LTM, GTM, ASM, APM, AFM)

        Returns:
            Bool: True if module provisioned, False if not or API error
        """
        pathProvisioned = "/mgmt/tm/sys/provision"
        responseProvisioned = __f5_api_request_get(pathProvisioned)
        if responseProvisioned.startswith('ERROR'):
            return False
        else:
            for module in json.loads(responseProvisioned)["items"]:
                if module["name"].lower() == name.lower() and module["level"].lower() != "none":
                    return True
            return False

    #get date for timestamp at head of output string/file
    now = datetime.datetime.now()
    currentDate = f' Status at: {now.strftime("%Y-%m-%d %H:%M:%S")}'
    #dashed lines for formatting result string which forms body of email
    dashedLine = "\n-------------------------------"
    doubleDashedLine = "\n========================================================"
    summaryLine = "\n******************************************************"
    #detailed string is formatted text containing F5 check details
    #summary string is formatted text summarizing the F5 check details
    detailed = f'{doubleDashedLine}\nDetailed{currentDate}'
    summary = f'{summaryLine}\nSummary{currentDate}'
    message = output = ""
    #varible for Virtual Edition F5; default = hardware appliance
    ve = False


    #GET hostname of the device from api call
    pathHostname = "/mgmt/tm/cm/device/?$select=hostname"
    responseHostname = __f5_api_request_get(pathHostname)
    if responseHostname.startswith('ERROR'):
        detailed += f'\n{host} {responseHostname}'
        summary += f'\n{host} {responseHostname}'
    else:
        hostname = json.loads(responseHostname)["items"][0]["hostname"]
        detailed += f"\n{hostname.split('.')[0].upper()}"
        summary += f"\n{hostname.split('.')[0].upper()}"


    #GET device type (VM/Hardware) and BigIP software version from api call
    pathDeviceType = "/mgmt/tm/cm/device/?$select=marketingName"
    responseDeviceType = __f5_api_request_get(pathDeviceType)
    if responseDeviceType.startswith('ERROR'):
        detailed += f'\n{host} {responseDeviceType}'
        summary += f'\n{host} {responseDeviceType}'
    else:
        deviceType = json.loads(responseDeviceType)["items"][0]["marketingName"].split(' ')
        deviceBigipVersion = json.loads(responseDeviceType)["selfLink"].split("=")[-1]
        if deviceType[1] == 'Virtual':
            deviceType = 'VE'
            ve = True
        else:
            deviceType = deviceType[1]
        detailed += f" | {deviceType} | version {deviceBigipVersion}"
        summary += f" | {deviceType} | v{deviceBigipVersion}"

    if serial:
        #GET chassis serial number
        pathSerial = "/mgmt/tm/sys/hardware"
        responseSerial = __f5_api_request_get(pathSerial)
        if responseSerial.startswith('ERROR'):
            detailed += f'\n{responseSerial}'
            summary += f'\n{responseSerial}'
        else:
            responseSerialDict = json.loads(responseSerial)
            serialF5 = responseSerialDict["entries"]["https://localhost/mgmt/tm/sys/hardware/system-info"] \
            ["nestedStats"]["entries"]["https://localhost/mgmt/tm/sys/hardware/system-info/0"] \
            ["nestedStats"]["entries"]["bigipChassisSerialNum"]["description"]
            detailed += f" | {serialF5[:-2]}"
            summary += f" | {serialF5[:-2]}"


    #close the header sections
    summary += summaryLine
    detailed += doubleDashedLine

    #POST to get F5 device uptime
    pathUptime = "/mgmt/tm/util/bash/"
    payloadUptime = {"command":"run", "utilCmdArgs":" -c uptime"}
    uptime, hrs = "", ""
    responseDeviceUptime = __f5_api_request_post(pathUptime, payloadUptime)
    if responseDeviceUptime.startswith('ERROR'):
        detailed += f'\n{responseDeviceUptime}'
        summary += f'\n{responseDeviceUptime}'
    else:
        responseUptimeDict = json.loads(responseDeviceUptime)
        timeframe = responseUptimeDict["commandResult"].split()[3].lower()
        timeN = responseUptimeDict["commandResult"].split()[2]
        #if uptime more than 1 day
        if timeframe == 'days,':
            uptime += f"{timeN} days"
            hrs = responseUptimeDict["commandResult"].split()[4]#[0:5]
        #if uptime in minutes
        elif timeframe == 'min,':
            uptime += f"{timeN} mins"
        #if uptime in hours
        else:
            hrs = timeN
        #remove leading comma after hrs
        if len(hrs) > 2:
            if hrs[-1] == ',':
                hrs = hrs[:-1]
            uptime += f" {hrs} Hrs"
        detailed += f'\n*UPTIME*{dashedLine}\n{uptime}'
        #detailed += f'{uptime}'
        summary += f'\nSYS * Uptime: {uptime}'

    #check if F5 unit online/healthy/active
    pathHealth = "/mgmt/tm/cm/failover-status"
    responseHealth = __f5_api_request_get(pathHealth)
    if responseHealth.startswith('ERROR'):
        detailed += f"\n{responseHealth}"
        summary += f"\n{responseHealth}"
    else:
        responseHealthDict = (json.loads(responseHealth))["entries"] \
        ["https://localhost/mgmt/tm/cm/failover-status/0"] \
        ["nestedStats"]["entries"]
        color = responseHealthDict["color"]["description"]
        status = responseHealthDict["status"]["description"]
        overview = responseHealthDict["summary"]["description"]
        detailed += f"{dashedLine}\n*STATUS*{dashedLine}\n{color.upper()}, {status}, {overview}"
        summary += f"\nSYS * Status: {color.upper()}, {status}"

    #check NTP sync status
    ntpStatResult, ntpServers = [], []
    pathSysNtpServers = "/mgmt/tm/sys/ntp/"
    responseSysNtpServers = __f5_api_request_get(pathSysNtpServers)
    if responseSysNtpServers.startswith('ERROR'):
        detailed += f"\n{responseSysNtpServers}"
        summary += f"\n{responseSysNtpServers}"
    else:
        responseSysNtpServersDict = json.loads(responseSysNtpServers)
        #if servers key exists [if no NTP servers configured, this will not exist]
        if "servers" in responseSysNtpServersDict.keys():
            ntpServers = responseSysNtpServersDict["servers"]
            pathNtpStat = "/mgmt/tm/util/bash/"
            payloadNtpStat = {"command":"run", "utilCmdArgs":"-c 'ntpstat'"}
            detailed += f'{dashedLine}\n*NTP SYNCHRONIZATION*{dashedLine}\n'
            #run bash API call to get ntpstat output to verify sync status
            responseNtpStat = __f5_api_request_post(pathNtpStat, payloadNtpStat)
            if not responseNtpStat.startswith('ERROR'):
                responseNtpStatList = json.loads(responseNtpStat)["commandResult"].split('\n')
                #alternate responses - 'unsynchronised' or 'syncronised to local net'
                if responseNtpStatList[0].startswith("synchronised to NTP server"):
                    detailed += (
                        f'NTP Server {responseNtpStatList[0].split(" ")[4][1:-2]}: '
                        f'synchronised within {responseNtpStatList[1].split(" ")[-2]} ms'
                    )
                    summary += f'\nSYS * NTP: Synchronised within {responseNtpStatList[1].split(" ")[-2]} ms'
                else:
                    detailed += f'NTP Sync error: {responseNtpStatList[0]}'
                    summary += f"\nSYS * NTP: SYNC ERROR {alert_message}"
            else:
                detailed += f"\nError getting NTP Synch status"
                summary += f"\nERROR GETTING NTP SYNC Status"

    #check F5 memory status - current % usage
    pathMemTotal = "/mgmt/tm/sys/host-info?$select=memoryTotal"
    pathMemUsed = "/mgmt/tm/sys/host-info?$select=memoryUsed"
    responseMemTotal = __f5_api_request_get(pathMemTotal)
    responseMemUsed = __f5_api_request_get(pathMemUsed)
    if responseMemUsed.startswith('ERROR') or responseMemTotal.startswith('ERROR'):
        detailed += f"\n{responseMemTotal} \n{responseMemUsed}"
        summary += f"\n{responseMemTotal} \n{responseMemUsed}"
    else:
        responseMemTotalStr = (json.loads(responseMemTotal))["entries"] \
        ["https://localhost/mgmt/tm/sys/host-info/0"]["nestedStats"]["entries"] \
        ["memoryTotal"]["value"]
        responseMemUsedStr = (json.loads(responseMemUsed))["entries"] \
        ["https://localhost/mgmt/tm/sys/host-info/0"]["nestedStats"]["entries"] \
        ["memoryUsed"]["value"]
        memUsage = round((int(responseMemUsedStr))/(0.01*(int(responseMemTotalStr))))
        detailed += f"{dashedLine}\n*CPU/MEMORY USAGE*{dashedLine}\nCurrent Memory Usage: {memUsage}%"
        message = alert_message if memUsage > memory_alert else ""
        summary += f"\nSYS * Memory Usage: average {memUsage}% {message}"


    #check F5 CPU status - last 5 mins usage
    pathCpu = "/mgmt/tm/sys/cpu/stats"
    cpu =  {}
    responseCpu = __f5_api_request_get(pathCpu)
    if responseCpu.startswith('ERROR'):
        detailed += f"\n{responseCpu}"
        summary += f"\n{responseCpu}"
    else:
        responseCpuDict = (json.loads(responseCpu))["entries"] \
        ["https://localhost/mgmt/tm/sys/cpu/0/stats"] \
        ["nestedStats"]["entries"]["https://localhost/mgmt/tm/sys/cpu/0/cpuInfo/stats"] \
        ["nestedStats"]["entries"]
        numCpus = len(responseCpuDict)
        #loop through CPUs and add 5min avg to result string
        cpuAverage = 0
        for c in range(0, numCpus):
            cpu[c] = responseCpuDict["https://localhost/mgmt/tm/sys/cpu/0/cpuInfo/"+str(c)+"/stats"] \
            ["nestedStats"]["entries"]["fiveMinAvgIdle"]["value"]
            detailed += f"\nCPU-{str(c)} (5 Min Avg) {str(100-(cpu[c]))}%"
            cpuAverage += (100-cpu[c])
        message = alert_message if (cpuAverage/numCpus) > cpu_alert else ""
        summary += f"\nSYS * CPU Usage: average {round(cpuAverage/numCpus)}% {message}"

    #check filesystem disk usage % as per checks defined in K14403
    pathDfSpace = "/mgmt/tm/util/bash/"
    payloadDfSpace = {"command":"run", "utilCmdArgs":" -c df -h"}
    responseDfSpace = __f5_api_request_post(pathDfSpace, payloadDfSpace)
    fullDisk = []
    if responseDfSpace.startswith('ERROR'):
        detailed += f'\n{responseDfSpace}'
        summary += f'\n{responseDfSpace}'
    else:
        disk = json.loads(responseDfSpace)["commandResult"].split("\n")
        resultDisk, fullDisk = __get_filesystem_usage(disk)
        detailed += f'{dashedLine}\n*FILESYSTEM DISK USAGE*{dashedLine}{resultDisk}'
        #if any mounts/Inodes above full threshold, add to summary
        if fullDisk:
            summary += f'\nSYS * Disk Mount Usage: above {disk_usage}% {alert_message}'
        else:
            summary += f'\nSYS * Disk Mount Usage: OK'

    #check filesystem inode usage % as per checks defined in K14404
    pathDfSpace = "/mgmt/tm/util/bash/"
    payloadDfInode = {"command":"run", "utilCmdArgs":" -c df -i"}
    responseDfInode = __f5_api_request_post(pathDfSpace, payloadDfInode)
    fullInode = []
    if responseDfInode.startswith('ERROR'):
        detailed += f'\n{responseDfInode}'
        summary += f'\n{responseDfInode}'
    else:
        inode = json.loads(responseDfInode)["commandResult"].split("\n")
        resultInode, fullInode = __get_filesystem_usage(inode)
        detailed += f'{dashedLine}\n*FILESYSTEM INODE USAGE*{dashedLine}{resultInode}'
        #if any inodes above disk_usage threshold, add to summary
        if fullInode:
            summary += f'\nSYS * Disk Inode Usage: above {disk_usage}% FULL {alert_message} '
        else:
            summary += f'\nSYS * Disk Inode Usage: OK'

    #Check F5 hardware: Fans, PSU and Temp status
    pathHardware = "/mgmt/tm/sys/hardware/stats"
    tempHiLimit, tempCurrent = "", ""
    fans, psu = {}, {}
    responseHardware = __f5_api_request_get(pathHardware)
    if responseHardware.startswith('ERROR'):
        detailed += f"\n{responseHardware}"
        summary += f"\n{responseHardware}"
    else:
        #dont check for hardware on VE
        if ve == False:
            responseFansDict = (json.loads(responseHardware))["entries"] \
            ["https://localhost/mgmt/tm/sys/hardware/chassis-fan-status-index/stats"] \
            ["nestedStats"]["entries"]
            numFans = len(responseFansDict)
            #loop through fans and add status to Fan dict
            for f in range(1, numFans+1):
                fans[f] = responseFansDict["https://localhost/mgmt/tm/sys/hardware/chassis-fan-status-index/"+str(f)+"/stats"] \
                ["nestedStats"]["entries"]["status"]["description"]
            responsePsuDict = (json.loads(responseHardware))["entries"] \
            ["https://localhost/mgmt/tm/sys/hardware/chassis-power-supply-status-index/stats"] \
            ["nestedStats"]["entries"]
            numPsu = len(responsePsuDict)
            #loop through PSU's and add status to PSU dict
            for p in range(1, numPsu+1):
                psu[p] = responsePsuDict["https://localhost/mgmt/tm/sys/hardware/chassis-power-supply-status-index/"+str(p)+"/stats"] \
                ["nestedStats"]["entries"]["status"]["description"]
            responseTempDict = (json.loads(responseHardware))["entries"] \
            ["https://localhost/mgmt/tm/sys/hardware/chassis-temperature-status-index/stats"] \
            ["nestedStats"]["entries"]["https://localhost/mgmt/tm/sys/hardware/chassis-temperature-status-index/1/stats"] \
            ["nestedStats"]["entries"]
            tempHiLimit = responseTempDict["hiLimit"]["value"]
            tempCurrent = responseTempDict["temperature"]["value"]
            #add values to result string
            fanSummary, psuSummary = 0, 0
            detailed += dashedLine+"\n*HARDWARE STATUS*"+dashedLine
            for i in range(1, len(fans)+1):
                detailed += f"\nFan{str(i)} {fans[i].upper()}"
                if fans[i].upper() == 'UP':
                    fanSummary += 1
            for j in range(1, len(psu)+1):
                detailed += f"\nPSU{str(j)} {psu[j].upper()}"
                if psu[j].upper() == 'UP':
                    psuSummary += 1
            detailed += "\nChassis Temp Max"+" "+str(tempHiLimit)+"C"
            detailed += "\nChassis Temp Current"+" "+str(tempCurrent)+"C"
            if (fanSummary == len(fans)) and (psuSummary == len(psu)):
                summary += f"\nSYS * Fans/PSUs: OK"
            elif (fanSummary < len(fans)) and (psuSummary == len(psu)):
                summary += f"\nSYS * {len(fans)-fanSummary} Fans DOWN {alert_message}\nSYS * PSUs OK"
            elif (fanSummary == len(fans)) and (psuSummary < len(psu)):
                summary += f"\nSYS * Fans OK\nSYS * {len(psu)-psuSummary} PSUs DOWN {alert_message}"
            else:
                summary += f"\nSYS * {len(fans)-fanSummary} DOWN and {len(psu)-psuSummary} PSUs DOWN {alert_message}"
            message = alert_message if tempCurrent > 65 else ""
            summary += f"\nSYS * Chassis Temp: {tempCurrent}C {message}"


    #check F5 trunks status
    pathTrunk = "/mgmt/tm/net/trunk/stats"
    responseTrunk = __f5_api_request_get(pathTrunk)
    if responseTrunk.startswith('ERROR'):
        detailed += f"\n{responseTrunk}"
        summary += f"\n{responseTrunk}"
    else:
        responseTrunkDict = json.loads(responseTrunk)
        if "entries" in responseTrunkDict.keys():
            trunkStatus = {}
            for k,v in responseTrunkDict["entries"].items():
                trunkStatus[v["nestedStats"]["entries"]["tmName"]["description"]] = \
                v["nestedStats"]["entries"]["status"]["description"]
            #loop through interfaces and add those with status 'up' to result string
            trunkDown = 0
            detailed += f'{dashedLine}\n*TRUNK STATUS*{dashedLine}'
            for k,v in trunkStatus.items():
                if v == "up":
                    detailed += f"\nTrunk {k} UP"
                else:
                    trunkDown += 1
                    detailed += f"\nTrunk {k} DOWN"
            message = "" if trunkDown == 0 else alert_message
            summary += f"\nNET * Trunks: {len(trunkStatus)-trunkDown}/{len(trunkStatus)} UP {message}"


    #check F5 interfaces status
    pathInt = "/mgmt/tm/net/interface/"
    pathIntStats = "/mgmt/tm/net/interface/stats"
    responseInt = __f5_api_request_get(pathInt)
    responseIntStats = __f5_api_request_get(pathIntStats)
    if responseInt.startswith('ERROR'):
        detailed += f"\n{responseInt}"
        summary += f"\n{responseInt}"
    else:
        responseIntList = json.loads(responseInt)['items']
        ints = []
        #loop through interfaces and add name of enabled interfaces to list
        for intf in responseIntList:
            if "enabled" in intf:
                ints.append(intf["name"])
        detailed += f'{dashedLine}\n*INTERFACE STATUS*{dashedLine}'
        #get interfaces stats for each enabled interface
        if responseIntStats.startswith('ERROR'):
            detailed += f"\n{responseIntStats}"
            summary += f"\n{responseIntStats}"
        else:
            responseIntStatsDict = json.loads(responseIntStats)['entries']
            interfaces, intUp, intDown = 0, 0, 0
            #loop through interfaces and add those with status 'up' to result string
            for k,v in responseIntStatsDict.items():
                name  = v["nestedStats"]["entries"]["tmName"]["description"]
                if name in ints:
                    intStatus = v["nestedStats"]["entries"]["status"]["description"]
                    if intStatus == "up" and name != "mgmt":
                        detailed += f"\nInterface {name} UP"
                        intUp += 1
                    elif intStatus == "down" and name != "mgmt":
                        intDown += 1
                    interfaces += 1
            message = alert_message if intDown > 0 else ""
            summary += f"\nNET * Interfaces: {interfaces-intDown}/{interfaces} UP {message}"

    #check SSL Cert Expiry status - expiring within 31 days
    pathSslStatus = "/mgmt/tm/sys/file/ssl-cert"
    responseSslStatus = __f5_api_request_get(pathSslStatus)
    if responseSslStatus.startswith('ERROR'):
        detailed += f"\n{responseSslStatus}"
        summary += f"\n{responseSslStatus}"
    else:
        responseSslStatusDict = json.loads(responseSslStatus)
        detailed += dashedLine+"\n*SSL CERT EXPIRY*"+dashedLine
        certs = {}
        expiring = []
        for c in responseSslStatusDict["items"]:
            if c["isBundle"] == "false":
                certs[c["name"]] = {c["expirationDate"] : c["expirationString"]}
        for k,v in certs.items():
            for epochTime, date in v.items():
                #if current time to expiry of cert (in seconds) is less than the defined
                #threshold limit ssl_expire_days (to get seconds, multiply by 86400)
                #log expiry message. Default 31 days (= 2678400 seconds)
                if (epochTime - time.time()) < (ssl_expire_days*86400):
                    expiring.append(f'{k} expiring on {date}')
        if not expiring:
            summary += f'\nSSL * Certs Expiring < {ssl_expire_days} days: NONE'
            detailed += '\nNONE'
        else:
            for cert in range(len(expiring)):
                detailed += f'\n{expiring[cert]}'
            summary += f'\nSSL * {len(expiring)} certs expiring within {ssl_expire_days} days {alert_message}'

    #if LTM module Provisioned
    if __get_provisioned('ltm'):
        #check LTM VIP status
        pathLtmVipStatus = "/mgmt/tm/ltm/virtual/stats"
        responseLtmVipStatus = __f5_api_request_get(pathLtmVipStatus)
        if responseLtmVipStatus.startswith('ERROR'):
            detailed += f"\n{responseLtmVipStatus}"
            summary += f"\n{responseLtmVipStatus}"
        else:
            responseLtmVipStatusDict = json.loads(responseLtmVipStatus)
            if 'entries' in responseLtmVipStatusDict.keys():
                detailed += dashedLine+"\n*LTM VIP AVAILABILITY STATUS*"+dashedLine
                vipsDown, vipsTotalEnabledMonitored = 0, 0
                for k,v in responseLtmVipStatusDict["entries"].items():
                    #get name of VIP and parse into linux path structure
                    detailed += f"\n{k.split('/')[-2].replace('~', '/')} "
                    #get enabled/disabled status
                    enabledState = v["nestedStats"]["entries"]["status.enabledState"]["description"].upper()
                    availableState = v["nestedStats"]["entries"]["status.availabilityState"]["description"]
                    statusReason = v["nestedStats"]["entries"]["status.statusReason"]["description"]
                    if enabledState == 'DISABLED':
                        detailed += f"Status: DISABLED"
                    else:
                        detailed += f'Status: {availableState.upper()}'
                        vipsTotalEnabledMonitored += 1
                        if availableState.lower() != 'available':
                            #specify reason for VIP status for those VIPs with no monitoring configured
                            if v["nestedStats"]["entries"]["status.statusReason"]["description"].endswith('not available yet'):
                                detailed += f", reason: No Monitoring Configured"
                                vipsTotalEnabledMonitored -= 1
                            else:
                                #specify reason for those VIPs with monitoring enabled but failed - only these increment vipsDown
                                detailed += f", reason: {statusReason}"
                                vipsDown += 1
                message = alert_message if vipsDown > 0 else ""
                summary += (
                    f'\nLTM * VIPs: {vipsTotalEnabledMonitored-vipsDown}'
                    f'/{vipsTotalEnabledMonitored} UP {message}'
                )

        #find LTM VIPs with connectivity profiles
        pathLtmVipConn = "/mgmt/tm/ltm/virtual/?expandSubcollections=true"
        responseLtmVipConn = __f5_api_request_get(pathLtmVipConn)
        connectivity = {}
        if responseLtmVipConn.startswith('ERROR'):
            detailed += f"\n{responseLtmVipConn}"
            summary += f"\n{responseLtmVipConn}"
        else:
            responseLtmVipConnDict = json.loads(responseLtmVipConn)
            if 'items' in responseLtmVipConnDict.keys():
                #loop through all enabled VIPs to find ones with Connectivity profiles attached
                #and add name of VIP and connectivity profile name to dict connectivity{}
                for vip in responseLtmVipConnDict["items"]:
                    #disabled vips use 'disabled: True.' Surely a disabled vip would be 'enabled:False,' F5?
                    if "enabled" in vip:
                        if vip["enabled"] == True:
                            vipDetails = [vip["destination"].split(":")[0],]
                            for profile in vip["profilesReference"]["items"]:
                                if "nameReference" in profile.keys():
                                    if profile["nameReference"]["link"].split('/')[7] == "connectivity":
                                        connProfile = profile["nameReference"]["link"].split('/')[8].split('?')[0]
                                        #only store conn profile once (eg same conn profile on 443 and DTLS VIPs)
                                        #so that user counts arent doubled for same APM policy
                                        if connProfile in connectivity.keys():
                                            connectivity[connProfile].append(vip["name"])
                                        else:
                                            connectivity[connProfile] = [vip["name"],]

    #if APM module Provisioned
    if __get_provisioned('apm'):
        #check number of current APM users if connectivity profiles found
        if len(connectivity) > 0:
            detailed += dashedLine+"\n*APM CONNECTIVITY*"+dashedLine
            pathConn = "/mgmt/tm/apm/profile/connectivity/stats/"
            responseConn = __f5_api_request_get(pathConn)
            if responseConn.startswith('ERROR'):
                detailed += f"\n{responseConn}"
                summary += f"\n{responseConn}"
            else:
                responseConnDict = json.loads(responseConn)
                totalConns = 0
                #loop through all connectivity profiles
                for conn, stats in responseConnDict["entries"].items():
                    #if connectivity profile in dict connectivity{} (from above,) then check stats
                    if conn.split('/')[8] in connectivity.keys():
                        for connect, vips in connectivity.items():
                            currentConns = stats["nestedStats"]["entries"]["curConns"]["value"]
                            #totalConns will only increment if multiple conn profiles in connectivity{}
                            totalConns += currentConns
                            for vip in vips:
                                #conn profile on multiple VIPs will show same number of users
                                detailed += f"\nAPM VIP {vip} has {str(currentConns)} current connections "
                summary += f"\nAPM * Connectivity: {totalConns} total current user connections"

    #if GTM/DNS module Provisioned
    if __get_provisioned('gtm'):
        #check GTM DCs status
        pathGtmDcStatus = "/mgmt/tm/gtm/datacenter/stats?$select=status.availabilityState"
        responseGtmDcStatus = __f5_api_request_get(pathGtmDcStatus)
        if responseGtmDcStatus.startswith('ERROR'):
            detailed += f"\n{responseGtmDcStatus}"
            summary += f"\n{responseGtmDcStatus}"
        else:
            responseGtmDcStatusDict = json.loads(responseGtmDcStatus)
            if "entries" in responseGtmDcStatusDict:
                detailed += dashedLine+"\n*GTM DC STATUS*"+dashedLine
                dcUnavailable = 0
                dcs = json.loads(responseGtmDcStatus)["entries"].items()
                for dc, status in dcs:
                    availability = status["nestedStats"]["entries"]["status.availabilityState"]["description"].lower()
                    dcName = dc.split("/")[-2].replace("~", "/")
                    detailed += f"\nGTM DC {dcName} {availability.upper()}"
                    if availability != "available":
                        dcUnavailable += 1
                message = alert_message if dcUnavailable else ""
                summary += f'\nGTM * DCs: {len(dcs)-dcUnavailable}/{len(dcs)} UP {message}'

        #check GTM Servers object status
        servers = {}
        pathGtmServers = "/mgmt/tm/gtm/server/stats"
        responseGtmServers = __f5_api_request_get(pathGtmServers)
        if responseGtmServers.startswith('ERROR'):
            detailed += f"\n{responseGtmServers}"
            summary += f"\n{responseGtmServers}"
        else:
            if "entries" in json.loads(responseGtmServers):
                detailed += dashedLine+"\n*GTM SERVER STATUS*"+dashedLine
                serversDown = 0
                responseGtmServersDict = json.loads(responseGtmServers)["entries"]
                for k,v in responseGtmServersDict.items():
                    if v["nestedStats"]["entries"]["status.enabledState"]["description"].lower() == "enabled":
                        server = re.search(r'(~([\w]+)/)', k)
                        servers[server.group(2)] = v["nestedStats"]["entries"]["status.availabilityState"]["description"]
                for k,v in servers.items():
                    detailed += f" \nGTM server *{str(k)}* {str(v).upper()}"
                    if v.upper() != "AVAILABLE":
                        serversDown += 1
                message = alert_message if serversDown else ""
                summary += f"\nGTM * Servers: {len(servers)-serversDown}/{len(servers)} UP {message}"

        #Check GTM Link monitor status
        pathGtmLink = "/mgmt/tm/gtm/link"
        pathGtmLinkStats = "/mgmt/tm/gtm/link/stats"
        responseGtmLink = __f5_api_request_get(pathGtmLink)
        responseGtmLinkStats = __f5_api_request_get(pathGtmLinkStats)
        links, linksDc = [], []
        if responseGtmLink.startswith('ERROR'):
            detailed += f"\n{responseGtmLink}"
            summary += f"\n{responseGtmLink}"
        else:
            responseGtmLinkDict = json.loads(responseGtmLink)
            #look in Links config to get name, DC and enbaled state
            if 'items' in responseGtmLinkDict.keys():
                linkDc = ""
                for link in responseGtmLinkDict["items"]:
                    linkName = link["fullPath"]
                    linkDc = link["datacenter"].split('/')[2]
                    if link["enabled"] == True:
                        links.append(linkName)
                #if enabled links configured, get availability status
                if links:
                    if responseGtmLinkStats.startswith('ERROR'):
                        detailed += f"\n{responseGtmLinkStats}"
                        summary += f"\n{responseGtmLinkStats}"
                    else:
                        responseGtmLinkStatsDict = json.loads(responseGtmLinkStats)["entries"]
                        totalLinks, linksDown = 0, 0
                        linkName, linkAvailability = "", ""
                        detailed += dashedLine+"\n*GTM LINK STATUS*"+dashedLine
                        for key, value in responseGtmLinkStatsDict.items():
                            if value["nestedStats"]["entries"]["linkName"]["description"] in links:
                                if value["nestedStats"]["entries"]["status.enabledState"]["description"].lower() == "enabled":
                                    totalLinks += 1
                                    linkName = value["nestedStats"]["entries"]["linkName"]["description"].split('/')[2]
                                    linkAvailability = value["nestedStats"]["entries"]["status.availabilityState"]["description"]
                                    if linkAvailability.lower() != 'available':
                                        linksDown += 1
                                else:
                                    linkAvailability = "DISABLED"
                                detailed += f'\nLink {linkName} in DC {linkDc} {linkAvailability.upper()}'
                        message  = alert_message if linksDown else ""
                        summary += f'\nGTM * Links: {totalLinks - linksDown}/{totalLinks} UP {message}'

        #check GTM WideIP status
        records = ['a', 'aaaa', 'cname', 'mx', 'naptr', 'srv']
        wideipsDown, wideipsDisabled = 0, 0
        wideipsTotal, wideipsA = [], []
        wip = True
        for record in records:
            pathGtmWipStatus = "/mgmt/tm/gtm/wideip/"+record+"/stats"
            responseGtmWipStatus = __f5_api_request_get(pathGtmWipStatus)
            if responseGtmWipStatus.startswith('ERROR'):
                detailed += f"\n{responseGtmWipStatus}"
                summary += f"\n{responseGtmWipStatus}"
            else:
                responseGtmWipStatusDict = json.loads(responseGtmWipStatus)
                if "entries" in responseGtmWipStatusDict:
                    #only print header once
                    if wip:
                        detailed += dashedLine+"\n*GTM WIDEIP AVAILABILITY STATUS*"+dashedLine
                        wip = False
                    for k,v in responseGtmWipStatusDict["entries"].items():
                        #store wideip as fqdn
                        wideip = k.split('~')[-1].split(":")[0]
                        #store wideip as /partition/fqdn
                        wideipPartition = k.split('/')[-2].replace('~', '/')
                        #v15 doesnt append record type to end of record in 'entries' link; append here
                        if wideipPartition.count(':') == 0:
                            wideipPartition += ":"+record.upper()
                        #if A record, store wideip name in list wideipsA for use in BIND checks later
                        if record == 'a':
                            #only store wideips from partition /Common
                            partition = k.split('~')[-2].lower()
                            if partition == 'common':
                                #v15 appends /stats to the returned wideip string. remove it if present
                                if wideip.endswith('/stats'):
                                    wideipsA.append(wideip.split('/')[0])
                                else:
                                    wideipsA.append(wideip)
                        #store all wideip names in list to check wideip availability and add wideip status to result
                        wideipsTotal.append(wideip)
                        available = v["nestedStats"]["entries"]["status.availabilityState"]["description"].lower()
                        enabled = v["nestedStats"]["entries"]["status.enabledState"]["description"].lower()
                        detailed += "\n"+wideipPartition+" "+"  "+available.upper()
                        #if disabled, dont alert in summary
                        if enabled == 'disabled':
                            wideipsDisabled += 1
                        #wideip states, assuming enabled, are: unknown [ie no monitoring], offline, available
                        elif available != 'available' and enabled == 'enabled':
                            wideipsDown += 1
                            detailed += f' ({v["nestedStats"]["entries"]["status.statusReason"]["description"]})'
        #if there are wideips, add amount that are down to summary ignoring disabled wideips
        if wideipsTotal:
            message  = {alert_message} if wideipsDown > 0 else ""
        summary += (
            f'\nGTM * WideIPs: {len(wideipsTotal)-(wideipsDown+wideipsDisabled)}'
            f'/{len(wideipsTotal)-wideipsDisabled} UP {message}'
        )

        #check DNS resolution of BIND and external DNS pools
        pathListener = "/mgmt/tm/gtm/listener/?expandSubcollections=true"
        responseListener = __f5_api_request_get(pathListener)
        if responseListener.startswith('ERROR'):
            detailed += f"\n{responseListener}"
            summary += f"\n{responseListener}"
        else:
            responseListenerDict = json.loads(responseListener)
            #if listeners configured, continue testing DNS request/response
            if "items" in responseListenerDict:
                if responseListenerDict["items"]:
                    gtmPool = ""
                    listeners = {}
                    #get all enabled listeners and thei profiles and store in listeners{}
                    for listener in responseListenerDict["items"]:
                        #verify listener enabled
                        if "enabled" in listener.keys():
                            profiles = []
                            #get profiles
                            for pros in listener["profilesReference"]["items"]:
                                profiles.append(pros["name"])
                            #get LB Pool name
                            if "pool" in listener.keys():
                                profiles.append("pool___"+listener["pool"])
                            #check no duplicate (tcp/udp) listeners and listener enabled; add to dict
                            if listener["address"] not in listeners:
                                listeners["listener__"+listener["address"]] = profiles
                    #get listener profiles and establish which is DNS profile
                    pathListenerProfiles = "/mgmt/tm/ltm/profile/dns"
                    responseListenerProfiles = __f5_api_request_get(pathListenerProfiles)
                    if responseListenerProfiles.startswith('ERROR'):
                        detailed += f"\n{responseListenerProfiles}"
                        summary += f"\n{responseListenerProfiles}"
                    else:
                        responseListenerProfilesDict = json.loads(responseListenerProfiles)["items"]
                        for dnsProfile in responseListenerProfilesDict:
                            #find which of the attched profiles is the DNS profile
                            for listener, profile in listeners.items():
                                gtmPool = ""
                                #if 'profile' is pool, save value to be added to listeners{} below
                                for items in profile:
                                    if items.startswith("pool___"):
                                        gtmPool = items#.split("___")[1]
                                #if profile is DNS profile; if BIND enabled and if pool, replace existing
                                #listeners{} value with list containing 'BIND' and/or pool name strings
                                if dnsProfile["name"] in profile:
                                    if dnsProfile["unhandledQueryAction"] == "allow":
                                        if dnsProfile["useLocalBind"] == "yes":
                                            if gtmPool:
                                                listeners[listener] = ["BIND", gtmPool]
                                            else:
                                                listeners[listener] = ["BIND",]
                                        elif gtmPool:
                                            listeners[listener] = [gtmPool,]
                                            gtmPool = ""
                        #if listener has BIND enabled, query BIND (local loopback) for wideip response
                        #elif listener has LB Pool enabled, get pool members and query URLs using API util dig call
                        detailed += f'{dashedLine}\n*GTM DNS RESOLUTION*{dashedLine}\n'
                        repeatBind = False#use this bool to verify if BIND (/Common) wideips already checked
                        repeatPool = []#use this list to store names of LB Pools that have already been checked
                        #externalDnsUp, externalDnsDown, externalDnsDownReason, externalPoolName = [], [], [], []
                        totalExternalDns, totalExternalDnsUp = [], []
                        totalLookups, totalSuccess = 0, 0
                        for listener, options in listeners.items():
                            for option in options:
                                pathDig = "/mgmt/tm/util/dig"
                                #If listener has BIND enabled, query wideip URLs using API util dig call
                                #based on assumption that a BIND record automatically created when wideip created
                                if option == "BIND" and wideipsA:
                                    if repeatBind == False:#if BIND checks have not been performed yet
                                        repeatBind = True#only check BIND once
                                        success = 0#use this variable as counter of succesful dig calls
                                        for fqdn in wideipsA:
                                            payload = {"command":"run", "utilCmdArgs":"@127.0.0.1 +short "+fqdn}
                                            responseLookupBind = __f5_api_request_post(pathDig, payload)
                                            if responseLookupBind.startswith('ERROR'):
                                                detailed += f"\n{responseLookupBind} {fqdn}"
                                                summary += f"\n{responseLookupBind} {fqdn}"
                                                break
                                            else:
                                                responseLookupBindDict = json.loads(responseLookupBind)
                                                if "commandResult" in responseLookupBindDict.keys():
                                                    resultDns = responseLookupBindDict["commandResult"].split("\\")[0]
                                                    #when dig returns multiple IPs for query it appends '\r\n' after each IP
                                                    if '\n' in resultDns:
                                                        #only return first IP
                                                        resultDns = resultDns.split()[0]
                                                    success += 1
                                                    detailed += f"BIND Response for {fqdn} is {resultDns}\n"
                                                else:
                                                    detailed += f"BIND Request for {fqdn} FAILED\n"
                                        message = alert_message if success == 0 else ""
                                        summary += f"\nGTM * BIND: {success}/{len(wideipsA)} request success {message}"

                                #If listener has LB Pool enabled, get pool members and query URLs using API util dig call
                                elif option.startswith("pool___"):
                                    #get pool members, verify in /Common partition and do DNS lookup against them using API util dig call
                                    poolFullPath = option.split("___")[1].replace('/','~')
                                    poolPartition = poolFullPath.split('~')[1].lower()
                                    poolName = poolFullPath.split('~')[-1].lower()
                                    if repeatPool.count(poolFullPath) == 0:#if this LB Pool checks have not been done yet
                                        repeatPool.append(poolFullPath)
                                        if poolPartition == "common":
                                            pathPool = "/mgmt/tm/ltm/pool/"+poolFullPath+"/members"
                                            responseDnsPool = __f5_api_request_get(pathPool)
                                            if responseDnsPool.startswith('ERROR'):
                                                detailed += f"\n{responseDnsPool} {pathPool}"
                                                summary += f"\n{responseDnsPool} {pathPool}"
                                                break
                                            else:
                                                responseDnsPoolDict = json.loads(responseDnsPool)
                                                externalDnsUp, externalDnsDown, externalDnsDownReason = [], [], []
                                                #loop through all GTM LB Pool members and get IPs of those that are up
                                                for IP in responseDnsPoolDict["items"]:
                                                    #add server IP to totalExternalDns[] if not duplicate
                                                    if totalExternalDns.count(IP["address"]) == 0:
                                                        totalExternalDns.append(IP["address"])
                                                    if IP["state"] == 'up':
                                                        #add server IP to totalExternalDnsUp[] if not duplicate
                                                        if totalExternalDnsUp.count(IP["address"]) == 0:
                                                            totalExternalDnsUp.append(IP["address"])
                                                        externalDnsUp.append(IP["address"])
                                                    else:
                                                        externalDnsDown.append(IP["address"])
                                                        externalDnsDownReason.append(IP["state"])
                                                #loop through all up extenal DNS servers and send DNS requests
                                                for server in externalDnsUp:
                                                    for fqdn in fqdns:
                                                        payload = {"command":"run", "utilCmdArgs":"@"+server+" +short "+fqdn}
                                                        responseLookupBind = __f5_api_request_post(pathDig, payload)
                                                        if responseLookupBind.startswith('ERROR') is False:
                                                            responseLookupBindDict = json.loads(responseLookupBind)
                                                            totalLookups += 1
                                                            if "commandResult" in responseLookupBindDict.keys():
                                                                resultDns = responseLookupBindDict["commandResult"].split("\\")[0]
                                                                #when dig returns multiple IPs for query it appends '\r\n' after each IP
                                                                if '\n' in resultDns:
                                                                    #only return first IP
                                                                    resultDns = resultDns.split()[0]
                                                                #if request string doesnt comply with DNS request rules (ie starting with @)
                                                                if resultDns.startswith('/usr/bin/dig'):
                                                                    detailed += f"[Pool: {poolName}] External DNS Server {server} Request for {fqdn} FAILED\n"
                                                                else:
                                                                    totalSuccess += 1
                                                                    detailed += f"[Pool: {poolName}] External DNS {server} Response for {fqdn} is {resultDns}\n"
                                                            else:
                                                                detailed += f"[Pool: {poolName}] External DNS Server {server} Request for {fqdn} FAILED\n"
                                                        else:
                                                            detailed += f"\nError getting GTM external DNS server {server} dig response"
                                                            summary += f"\nERROR GETTING GTM EXTERNAL DNS DIG RESPONSE"
                                                            break
                                                for server in range(len(externalDnsDown)):
                                                    detailed += (
                                                        f'[Pool: {poolName}] External DNS Server {externalDnsDown[server]} health'
                                                        f' monitoring {externalDnsDownReason[server].upper()} - no DNS requests sent\n'
                                                    )
                        if responseDnsPool.startswith('ERROR') is False:
                            message = alert_message if (len(totalExternalDnsUp) < (len(totalExternalDns)) or totalSuccess < totalLookups) else ""
                            summary += (
                                f"\nGTM * External DNS Servers: {len(totalExternalDnsUp)}/{len(totalExternalDns)}"
                                f" servers UP ({totalSuccess}/{totalLookups} request success) {message}"
                            )


    #if output to file (defined by non-empty filePath attribute) requested
    if filePath:
        try:
            #if only the summary output requested
            if summary_only and detailed_only == False:
                output = summary
            #if only the detailed output requested
            elif detailed_only and summary_only == False:
                output = detailed
            #if no request for only one of summary/detailed
            elif (summary_only and detailed_only) or output == "":
                output = summary+detailed
            #open RW file in specified location and write output string
            with open(filePath, 'w') as file:
                file.write(output)
        except IOError as e:
            #if IOError, append error string to output string
            summary += f"\n**********\nERROR writing to file {e}"
            detailed += f"\n**********\nERROR writing to file {e}"
    #else return string/s with relevant summary/detailed values
    else:
        #if only the summary output requested, return summary string
        if summary_only and detailed_only == False:
            return summary
        #if only the detailed output requested, return detailed string
        elif detailed_only and summary_only == False:
            return detailed
        #else return both summary & detailed as strings
        else:
            return summary, detailed

