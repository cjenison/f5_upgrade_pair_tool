#!/usr/bin/python

# f5_upgrade_pair_tool.py
# Author: Chad Jenison (c.jenison at f5.com)
# Version 1.0
#
# Script that uses F5 BIG-IP iControl REST API to upgrade a BIG-IP HA Pair in a
# sensible manner so as to minimize service disruption and to abort and try to roll back if needed
# Operator will be prompted to confirm failover, failback, etc

import argparse
import sys
import requests
import json
import getpass

def removeMember(memberUrlToDelete, memberName, poolName):
    if args.noprompt:
        req = bip.delete('%s/ltm/pool/%s' % (url_base, memberUrlToDelete))
    else:
        queryString = ('Remove Pool Member: %s from Pool: %s?' % (memberName, poolName))
       	if query_yes_no(queryString, default="no"):
            req = bip.delete('%s/ltm/pool/%s' % (url_base, memberUrlToDelete))
            print ('Deleted Member: %s from pool: %s' % (memberName, poolName))
        else:
            print('Skipping Member: %s from Pool: %s' % (memberName, poolName))

def removeVirtual(virtualUrlToDelete, virtualName):
    if args.noprompt:
        req = bip.delete('%s/ltm/virtual/%s' % (url_base, virtualUrlToDelete))
    else:
        queryString = ('Remove Virtual Server: %s?' % (virtualName))
        if query_yes_no(queryString, default="no"):
            req = bip.delete('%s/ltm/virtual/%s' % (url_base, virtualUrlToDelete))
            print ('Deleted Virtual Server: %s' % (virtualName))
        else:
            print('Skipping Virtual Server: %s' % (virtualName))

def getManagementIp():
    managementIpAPI = bip.get('%s/sys/management-ip' % (url_base)).json()
    managementIpAndMask = managementIpAPI['items'][0]['name']
    discoveredManagementIp = managementIpAndMask[0:managementIpAndMask.find('/')]
    return discoveredManagementIp

# Taken from http://code.activestate.com/recipes/577058/
def query_yes_no(question, default="no"):
    valid = {"yes": True, "y": True, "ye": True, "no": False, "n": False}
    if default == None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)
    while 1:
        sys.stdout.write(question + prompt)
        choice = raw_input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid.keys():
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' (or 'y' or 'n').\n")

#Setup command line arguments using Python argparse
parser = argparse.ArgumentParser(description='A tool to identify and remove orphaned or unused pool members from F5 BIG-IP Systems running TMOS 11.5 and higher', epilog='Use this tool with caution')
mode = parser.add_mutually_exclusive_group(required=True)
mode.add_argument('--scan', action='store_true', help='scan for unused pool members and output to file')
mode.add_argument('--remove', action='store_true', help='remove unused pool members based on input file')
mode.add_argument('--scanandremove', action='store_true', help='scan for unused pool members and immediately remove')
parser.add_argument('--bigip', help='IP or hostname of BIG-IP Management or Self IP', required=True)
parser.add_argument('--user', help='username to use for authentication', required=True)
parser.add_argument('--file', help='filename in cwd CSV formatted; file is output filename if scanning; file is input filename if removing', default='bigip_config_cleaner.csv')
#Pool Member Selection Criteria
poolmemberselector = parser.add_argument_group(title='Criteria for Selecting Pool Members')
poolmemberselector.add_argument('--disabled0TotalConns', action='store_true', help='select pool member for removal if it is disabled AND has 0 Total Conns')
poolmemberselector.add_argument('--enabled0TotalConns', action='store_true', help='select pool member for removal if it is enabled AND has 0 Total Conns')
poolmemberselector.add_argument('--offline0TotalConns', action='store_true', help='select pool member for removal if it is offline (due to health monitors) AND has 0 Total Conns')
poolmemberselector.add_argument('--offline0CurrentConns', action='store_true', help='select pool member for removal if it is offline (due to health monitors) AND has 0 Current Conns')
#Virtual Server Selection Criteria
virtualselector = parser.add_argument_group(title='Criteria for Selecting Unused Virtual Servers')
virtualselector.add_argument('--vs0TotalConns', action='store_true', help='select virtual server for removal if it has 0 Total Conns; indepenent of status')
virtualselector.add_argument('--vsDisabled0TotalConns', action='store_true', help='select virtual server for removal if it disabled AND has 0 Total Conns')
virtualselector.add_argument('--vsEnabled0TotalConns', action='store_true', help='select virtual server for removal if it is enabled AND has 0 Total Conns')
virtualselector.add_argument('--vsOffline0TotalConns', action='store_true', help='select virtual server for removal if it is unavailable AND has 0 Total Conns')
virtualselector.add_argument('--vsAvailable0TotalConns', action='store_true', help='select virtual server for removal if it is available AND has 0 Total Conns')
#Safety Checks
safety = parser.add_argument_group(title='Options for disabling Safety Checks')
safety.add_argument('--noprompt', action='store_true', help='do not prompt to confirm removal of each node')
safety.add_argument('--nosanity', action='store_true', help='do not check device for inactivity (0 total connections) or standby/offline status for traffic groups')
safety.add_argument('--ignoreIpMismatch', action='store_true', help='Used in conjunction with --remove option; do not prompt on mismatch between management IP of CSV file and target BIG-IP')

args = parser.parse_args()

# Double Confirm that they don't want prompting for deletion of each node; exit if they don't confirm
if args.noprompt:
    noPromptConfirm = query_yes_no('Deleting pool members without prompting is very risky; are you sure?', default="no")
    if not noPromptConfirm:
        exit()

user = args.user
passwd = getpass.getpass("Password for " + user + ":")
bip = requests.session()
bip.auth = (user, passwd)
bip.verify = False
requests.packages.urllib3.disable_warnings()
url_base = ('https://%s/mgmt/tm' % (args.bigip))


if args.scan or args.scanandremove:
    # Try to determine whether the BIG-IP is inactive for any Traffic Groups
    # First need to determine Management IP of device and based on that; device name
    #managementIpAPI = bip.get('%s/sys/management-ip' % (url_base)).json()
    #managementIpAndMask = managementIpAPI['items'][0]['name']
    #managementIp = managementIpAndMask[0:managementIpAndMask.find('/')]
    managementIp = getManagementIp()
    if not args.nosanity:
        devices = bip.get('%s/cm/device' % (url_base)).json()
        for device in devices['items']:
            if device['managementIp'] == managementIp:
                deviceFullPath = device['fullPath']
        # we have device name in deviceFullPath variable ; now check that it isn't Standby or Offline for any traffic groups
        trafficGroupStats = bip.get('%s/cm/traffic-group/stats' % (url_base)).json()
        for trafficGroup in trafficGroupStats['entries']:
            # print trafficGroupStats['entries'][trafficGroup]['nestedStats']['entries']['failoverState']['description']
            if trafficGroupStats['entries'][trafficGroup]['nestedStats']['entries']['deviceName']['description'] == deviceFullPath:
                trafficGroupFullPath = trafficGroupStats['entries'][trafficGroup]['nestedStats']['entries']['trafficGroup']['description']
                if trafficGroupStats['entries'][trafficGroup]['nestedStats']['entries']['failoverState']['description'] == "standby":
                    print ('This device is standby for traffic group %s' % (trafficGroupFullPath))
                    print ('Use option --nosanity to ignore this check')
                    exit()
                elif trafficGroupStats['entries'][trafficGroup]['nestedStats']['entries']['failoverState']['description'] == "offline":
                    print ('This device is offline for traffic group %s' % (trafficGroupFullPath))
                    print ('Use option --nosanity to ignore this check')
                    exit()
        # TODO: Validate Config Sync State is in Sync
        # Check if Config Sync State is In Sync (for sync-failover device group if one exists)
        # deviceGroups = bip.get('%s/cm/device-group/' % (url_base)).json()
        # for deviceGroup in deviceGroups['items']:
        #    if deviceGroup['type'] == 'sync-failover':
	#	syncFailoverDeviceGroupFullPath = deviceGroup['fullPath']
	#	syncFailoverDeviceGroupName = deviceGroup['name']
        #        syncFailoverStatus
        # Check for 0 Total Connections and Exit if True - Device Is Idle
        virtualStats = bip.get('%s/ltm/virtual/stats' % (url_base)).json()
        vsTotConns = 0
        for virtual in virtualStats['entries']:
            vsTotConns += virtualStats['entries'][virtual]['nestedStats']['entries']['clientside.curConns']['value']
        print ('Total VS Connections: %s' % (vsTotConns))
        if vsTotConns == 0:
            print ('Total Virtual Server Connections is 0; box appears to be inactive')
            print ('Use option --nosanity to ignore this check')
            exit()
    # open file for output if applicable
    if args.scan:
       fileOut = open('%s' % (args.file), 'w')
       fileOut.write('##ManagementIP##,%s\n' % (managementIp))
    # look for stale/unused virtual servers
    if (args.vs0TotalConns or args.vsDisabled0TotalConns or args.vsEnabled0TotalConns or args.vsOffline0TotalConns or args.vsAvailable0TotalConns):
       virtuals = bip.get('%s/ltm/virtual' % (url_base)).json()
       for virtual in virtuals['items']:
           virtualUrl = virtual['fullPath'].replace("/", "~", 2)
           virtualStats = bip.get('%s/ltm/virtual/%s/stats' % (url_base, virtualUrl)).json()
           if (args.vs0TotalConns and virtualStats['entries']['clientside.totConns']['value'] == 0) or (args.vsDisabled0TotalConns and virtualStats['entries']['clientside.totConns']['value'] == 0 and virtualStats['entries']['status.enabledState']['description'] == 'disabled') or (args.vsEnabled0TotalConns and  virtualStats['entries']['clientside.totConns']['value'] == 0 and virtualStats['entries']['status.enabledState']['description'] == 'enabled') or (args.vsOffline0TotalConns and virtualStats['entries']['clientside.totConns']['value'] == 0 and virtualStats['entries']['status.availabilityState']['description'] == 'offline') or (args.vsAvailable0TotalConns and virtualStats['entries']['clientside.totConns']['value'] == 0 and virtualStats['entries']['status.availabilityState']['description'] == 'available'):
               #We have a stale Virtual Server
               print ('Stale Virtual Server: %s' % (virtual['fullPath']))
               if args.scan:
                   fileOut.write('VirtualServerFullPath,%s,VirtualName,%s,CurrentConns,%s,TotalConns,%s,EnabledState,%s,AvailabilityState,%s\n' % (virtualUrl, virtual['name'], virtualStats['entries']['clientside.curConns']['value'], virtualStats['entries']['clientside.totConns']['value'], virtualStats['entries']['status.enabledState']['description'], virtualStats['entries']['status.availabilityState']['description']))
               else:
                   removeVirtual(virtualUrl, virtual['name'])
    if (args.offline0CurrentConns or args.offline0TotalConns or args.disabled0TotalConns or args.enabled0TotalConns):
        # Get list of pools and then walk pools and members to identify candidates for removal
        pools = bip.get('%s/ltm/pool' % (url_base)).json()
        for pool in pools['items']:
            poolUrl = pool['fullPath'].replace("/", "~", 2)
            members = bip.get('%s/ltm/pool/%s/members' % (url_base, poolUrl)).json()
            #print ('Pool: %s' % (pool['name']))
            #print ('poolUrl: %s' % (poolUrl))
            #print pool['name']
            #print pool['fullPath']
            #print members
            for member in members['items']:
                name = member['name']
                memberFullPath = member['fullPath'].replace("/", "~", 2)
                memberFullPathUrlFragment = memberFullPath.replace("%", "%25", 1)
                memberUrl = ('%s/members/%s' % (poolUrl, memberFullPathUrlFragment))
                memberStats = bip.get('%s/ltm/pool/%s/stats' % (url_base, memberUrl)).json()
                if (args.offline0CurrentConns and memberStats['entries']['serverside.curConns']['value'] == 0 and memberStats['entries']['status.availabilityState']['description'] == 'offline') or (args.offline0TotalConns and memberStats['entries']['serverside.totConns']['value'] == 0 and memberStats['entries']['status.availabilityState']['description'] == 'offline') or (args.disabled0TotalConns and memberStats['entries']['status.enabledState']['description'] == 'disabled' and memberStats['entries']['serverside.totConns']['value'] == 0) or (args.enabled0TotalConns and memberStats['entries']['status.enabledState']['description'] == 'enabled' and memberStats['entries']['serverside.totConns']['value'] == 0):
                    if args.scan:
                        fileOut.write('PoolFullPath,%s,MemberFullPath,%s,CurrentConns,%s,TotalConns,%s,EnabledState,%s,AvailabilityState,%s\n' % (poolUrl, memberUrl, memberStats['entries']['serverside.curConns']['value'], memberStats['entries']['serverside.totConns']['value'], memberStats['entries']['status.enabledState']['description'], memberStats['entries']['status.availabilityState']['description']))
                    else:
                        removeMember(memberUrl, name, pool['name'])

if args.remove:
    fileIn = open('%s' % (args.file), 'r')
    for line in fileIn:
        #Deal with each line of file
        #treat first line of file specially, it contains management IP of device that was scanned to produce CSV file
	if line.startswith('##ManagementIP##'):
	    fileManagementIp = line.split(',')[1].strip()
            # obtain management IP from Device
            managementIp = getManagementIp()
            if fileManagementIp != managementIp and not ignoreIpMismatch:
                queryString = ('Input File obtained from device with management IP: %s, but target device has management IP: %s ; Do you want to proceed?' % (fileManagementIp, managementIp))
                if not query_yes_no(queryString, default="no"):
                    print 'Exiting Due to Mismatch of IPs'
        elif line.startswith('PoolFullPath'):
            # Deal with Pool member line in CSV format (URI Formatted "fullPath" is the critical info we need)
            poolPath = line.split(',')[1]
            memberPath = line.split(',')[3]
            removeMember (memberPath, memberPath, poolPath)
        elif line.startswith('VirtualServerFullPath'):
            virtualPath = line.split(',')[1]
            virtualName = line.split(',')[3]
            removeVirtual(virtualPath, virtualName)




if args.scan:
    print ('Output written to file: %s' % (args.file))
    fileOut.close()
if args.remove:
    fileIn.close()
