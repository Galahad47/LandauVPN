import requests

proxy = requests.get("https://sockslist.us/Json").json()

for i in proxy:
    print(i['ip'],i['port'])
