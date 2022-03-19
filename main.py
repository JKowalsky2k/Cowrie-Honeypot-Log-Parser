from glob import glob
from collections import Counter
from pprint import pprint
import termplotlib as tpl
import re
import subprocess as sp 

def info(text):
    text = "[i] "+text 
    print("\n"+str(text))
    print("-"*len(text))

def error(text):
    text = "[!] "+text 
    print("\n"+str(text), end="\n")

class Statistics:
    def __init__(self, data):
        self.data = data
        self.credentials = []
        self.credentialsParse()
        self.country_names = []

    def credentialsParse(self):
        for _, user in self.data.items():
            for line in user.activity:
                if "login attempt" in line:
                    login, passwd = line.split()[-2].split("'")[1], line.split()[-2].split("'")[-2] 
                    self.credentials.append((login, passwd))

    def getCountryNames(self):
        cache = {}
        all_ip = len([user.ip for _, user in self.data.items()])
        for _, session in self.data.items():
            print("Cached IPs: {} of {}".format(len(cache.items()), all_ip), end="\r")
            if session.ip in cache.keys():    
                self.country_names.append(cache[session.ip])
            else:
                xml_stream = sp.Popen(['geoiplookup', '{}'.format(session.ip)], stdout=sp.PIPE, stderr=sp.PIPE)
                stdout, _ = xml_stream.communicate()
                ip_country_name = stdout.decode("UTF-8").split(":")[-1].split(",", maxsplit=1)[-1].strip()
                cache[session.ip] = ip_country_name
                self.country_names.append(cache[session.ip])
        #print(f'{len(cache.items()) = }')

    def portRanking(self):
        return list(Counter([user.port for _, user in self.data.items()]).items())

    def ipRanking(self):
        return list(Counter([user.ip for _, user in self.data.items()]).items())

    def passwordRanking(self):
        return list(Counter([creds[1] for creds in self.credentials]).items()) 

    def loginRanking(self):
        return list(Counter([creds[0] for creds in self.credentials]).items()) 

    def credentialsRanking(self):
        return list(Counter(self.credentials).items())

    def countryRanking(self):
        return list(Counter(self.country_names).items())

    def display(self, type: str, top=10):
        if type == "port":
            info("Port Ranking")
            fig = tpl.figure()
            ranking = sorted(self.portRanking(), key=lambda port: port[1], reverse=True)[:top]
            labels, data = [port[0] for port in ranking], [port[1] for port in ranking]
            fig.barh(data, labels, force_ascii=True)
            fig.show()
        elif type == "ip":
            info("IPs Ranking")
            fig = tpl.figure()
            ranking = sorted(self.ipRanking(), key=lambda ip: ip[1], reverse=True)[:top]
            labels, data = [ip[0] for ip in ranking], [ip[1] for ip in ranking]
            fig.barh(data, labels, force_ascii=True)
            fig.show()
        elif type == "passwd":
            info("Passwords Ranking")
            fig = tpl.figure()
            ranking = sorted(self.passwordRanking(), key=lambda creds: creds[1], reverse=True)[:top]
            labels, data = [creds[0] for creds in ranking], [creds[1] for creds in ranking]
            fig.barh(data, labels, force_ascii=True)
            fig.show()
        elif type == "login":
            info("Logins Ranking")
            fig = tpl.figure()
            ranking = sorted(self.loginRanking(), key=lambda creds: creds[1], reverse=True)[:top]
            labels, data = [creds[0] for creds in ranking], [creds[1] for creds in ranking]
            fig.barh(data, labels, force_ascii=True)
            fig.show()       
        elif type == "creds":
            info("Creds Ranking")
            fig = tpl.figure()
            ranking = sorted(self.credentialsRanking(), key=lambda creds: creds[1], reverse=True)[:top]
            labels, data = [creds[0] for creds in ranking], [creds[1] for creds in ranking]
            fig.barh(data, labels, force_ascii=True)
            fig.show()
        elif type == "geoip":
            info("Country Name Ranking")
            fig = tpl.figure()
            self.getCountryNames()
            ranking = sorted(self.countryRanking(), key=lambda country: country[1], reverse=True)[:top]
            #pprint(self.country_names)
            labels, data = [country[0] for country in ranking], [country[1] for country in ranking]
            fig.barh(data, labels, force_ascii=True)
            fig.show()
        else:
            error("Not supported type! ({})".format(type))

class NewSession:
    def __init__(self, id, ip, port, start_time, activity):
        self.ip = ip
        self.port = port
        self.start_time = start_time
        self.activity = activity

    def display(self):
        print(f'{self.ip = }', f'{self.port = }', f'{self.start_time = }')
        for line in self.activity:
            print(line, end="")

sessions = {}
for file in glob("./logs/*.log"):
    print(f'{file = }')
    with open(file) as current_file:
        ip = port = start_time = 0
        activity = []
        for line_num, line in enumerate(current_file.readlines()):
            if "New connection:" in line:
                ip = line.strip().split()[4].split(":")[0]
                port = line.strip().split()[4].split(":")[1]
                start_time = line.strip().split()[0].split(".")[0]

            activity.append(line)

            if "Connection lost" in line and "info" not in line:
                user = NewSession(line_num, ip, port, start_time, activity)
                sessions[str(line_num)+str(start_time)] = user
                activity = []

'''
for id, session in sessions.items():
    print()
    print(id, end=": ")
    session.display()
'''

stats = Statistics(sessions)
stats.display("port")
stats.display("ip")
stats.display("creds")
stats.display("passwd")
stats.display("login")
stats.display("geoip")

print("All sessions:", len(sessions))