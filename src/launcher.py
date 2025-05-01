import getpass
import json
import requests
import settings
import subprocess

def main(start, end):
    NAME = 'OSniffy'
    TYPE = 'mysql'
    MYSQL_HOST = settings.MYSQL_HOST
    DB_NAME = settings.DB_NAME
    DB_USER = settings.MYSQL_USER_GRAFANA
    DB_PASSWORD = settings.MYSQL_PASS_GRAFANA
    GRAFANA_API_KEY = settings.GRAFANA_API_KEY

    SERVER = settings.GRAFANA_HOST
    PORT = settings.GRAFANA_PORT
    PATH = "api/datasources"

    url = "http://{SERVER}:{PORT}/{PATH}".format(SERVER=SERVER, PORT=PORT, PATH=PATH)

    headers = {
        "Authorization": "Bearer {API_KEY}".format(API_KEY=GRAFANA_API_KEY),
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    body = {
        'name': NAME,
        'type': TYPE,
        'access': MYSQL_HOST,
        'user': DB_USER,
        'password': DB_PASSWORD,
        'database': DB_NAME
    }

    response = requests.post(url=url, headers=headers, data=json.dumps(body))

    if (response.status_code == 409):
        print("Database already exists in Grafana")
    else:
        print("Database added to Grafana")

    PATH = "api/dashboards/db"

    FILE = "../TFG.json"

    file = open(FILE)
    dashboard = json.load(file)
    file.close()

    body = {
        "dashboard": dashboard,
        "overwrite": True
    }

    url = "http://{SERVER}:{PORT}/{PATH}".format(SERVER=SERVER, PORT=PORT, PATH=PATH)

    response = requests.post(url=url, headers=headers, data=json.dumps(body))

    print("Dashboard added to Grafana")

    if (settings.os.getenv("USER") == "root"):
        if end == "now-5m":
            args = ["runuser", "-u", "{USER}".format(USER=settings.USER), "sensible-browser", "http://localhost:3000/d/zyHdgQcMk/tfg?refresh=5s&from={START}&to={END}".format(START=start, END=end)]
        else:
            args = ["runuser", "-u", "{USER}".format(USER=settings.USER), "sensible-browser", "http://localhost:3000/d/zyHdgQcMk/tfg?from={START}&to={END}".format(START=start, END=end)]
        subprocess.Popen(args)
    else:
        if end == "now-5m":
            subprocess.run(["sensible-browser", "http://localhost:3000/d/zyHdgQcMk/tfg?refresh=5s&from={START}&to={END}".format(START=start, END=end)])
        else:
            subprocess.run(["sensible-browser", "http://localhost:3000/d/zyHdgQcMk/tfg?from={START}&to={END}".format(START=start, END=end)])