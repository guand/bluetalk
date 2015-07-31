import time
import bluetooth
import json

def run():
	list_values = 'list/list.json'
	while True:
		temp_list = []
		for addr, name in bluetooth.discover_devices (duration = 5, lookup_names = True):
			temp_list.append((addr, name))

		with open(list_values, 'wb') as outfile:
			json.dump(temp_list, outfile)
		time.sleep(15)

run()