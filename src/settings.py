import binascii
from dotenv import load_dotenv
import frames
import os
import parser
import socket
import struct

load_dotenv()

MYSQL_HOST = os.getenv("MYSQL_HOST")
DB_NAME = os.getenv("DB_NAME")
TABLE_NAME = os.getenv("TABLE_NAME")

MYSQL_USER = os.getenv("MYSQL_USER")
MYSQL_PASS = os.getenv("MYSQL_PASS")

MYSQL_USER_GRAFANA = os.getenv("MYSQL_USER_GRAFANA")
MYSQL_PASS_GRAFANA = os.getenv("MYSQL_PASS_GRAFANA")

GRAFANA_HOST = os.getenv("GRAFANA_HOST")
GRAFANA_PORT = os.getenv("GRAFANA_PORT")
GRAFANA_API_KEY = os.getenv("GRAFANA_API_KEY")

USER = os.getenv("CLIENT")