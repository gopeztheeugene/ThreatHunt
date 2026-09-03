import requests
import json
import auth
import rules
import time
import csv
import logs
import tkinter as tk
from tkinter import messagebox
from datetime import datetime, timedelta
import os

#Load output directories
target_dir = os.path.join(os.path.expanduser("~/Documents"), "ThreatHuntOutputDev")
target_dir_fortiedr = os.path.join(target_dir, "FortiEDR")
target_dir_sentinelone = os.path.join(target_dir, "SentinelOne")
os.makedirs(target_dir, exist_ok=True)
os.makedirs(target_dir_fortiedr, exist_ok=True)
os.makedirs(target_dir_sentinelone, exist_ok=True)

#initialize logging function
logger= logs.setup_logging(log_file="logs.log", path=target_dir)

#SentinelOne Rule Names 
rule_name = ['Unusual RDP or Auth Probes', 'Syskey Access','SAM Database Dump','Rundll LSASS Dump', 'Recon CMDs', 'Mesh Service', 'Taskmgr Lsass Dump', 'Wmiexec', 'Smbexec', 'Atexec','Perflogs Staging','Allow RDP', 'Allow Restricted Admin (Allows PTH)', 'Allow RDP 2', 'RDP Port Query', 'Certutil Usage', 'Net Share Scan', 'Share Audit', 'Suspicious Pushd Usage', 'ClickFix Delivery']

#Event Message box setup
root = tk.Tk()
root.withdraw()
root.grab_set()
root.attributes("-topmost", True)

#SentinelOne Urls
url_us = "https://xdr.us1.sentinelone.net/api/query"
url_eu = "https://xdr.eu1.sentinelone.net/api/query"
url_ca = "https://xdr.ca1.sentinelone.net/api/query"

#FortiEDR Events to CSV
def write_csv_fortiedr(data):
    file_path = os.path.join(target_dir_fortiedr, "fortiedr_output.csv")
    with open(file_path, 'a', newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=data[0].keys())
        if os.path.getsize(file_path) == 0: writer.writeheader()        
        writer.writerows(data) 

#SentinelOne Events to CSV
def write_csv_sentinelone(data, index):
  file_path = os.path.join(target_dir_sentinelone, f"{rule_name[index]}.csv")
  rows = data if isinstance(data, list) else [data]
  all_keys = set()
  for row in rows:all_keys.update(row.keys())
  fieldnames = sorted(all_keys) 
  with open(file_path, 'a', newline="", encoding="utf-8") as f:
      writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
      if os.path.getsize(file_path) == 0: writer.writeheader()
      if isinstance(data, dict):writer.writerow(data)       # one row
      elif isinstance(data, list):writer.writerows(data)

#Converts UTC to EST 
def utc_to_est(start_utc, end_utc):
    fmt = "%Y-%m-%d %H:%M:%S"
    start_est = datetime.strptime(start_utc, fmt) + timedelta(hours=4)
    end_est   = datetime.strptime(end_utc, fmt) + timedelta(hours=4)
    return start_est, end_est

def fortiedr_api(urls,param):
  all_data=[]
  for index, url in enumerate(urls):
    console_results=requests.get(url,auth=(auth.fortiedr_auth[index]["user"],auth.fortiedr_auth[index]["pass"]), params=param)
    if console_results.json(): all_data=all_data+console_results.json()
  return all_data


def fortiedr(start, end):
  params = rules.parameters_fortiedr(start, end)
  for index, rule in enumerate(params):
    all_data=fortiedr_api(auth.fortiedr_urls,rule)
    if all_data:
      logger.warning(f"FortiEDR Event found: {rule["process"]}")
      messagebox.showwarning("Alert", f"FortiEDR Event found: {rule["process"]}")
      write_csv_fortiedr(all_data)
    else:
      logger.info(f"No events found for {rule["process"]}")
  return 

def sentinelone_api(param):
  all_events= []
  all_statuses = []
  for index_2,url in enumerate(auth.sentinelone_urls):
    result = requests.request("POST", url, headers=auth.headers[index_2], data=json.dumps(param))
    response = result.text
    data = json.loads(response)
    events = data["matches"]
    all_events = all_events + events
    all_statuses.append(data["status"])
  return(all_events, all_statuses)

def sentinelone(start, end):
  start_est, end_est = utc_to_est(start, end)
  parameters= rules.sentinelone_parameters(start_est, end_est)
  for index_1,rule in enumerate(parameters):
    allevents, allstatuses = sentinelone_api(rule)
    if allevents:
      logger.warning(f"SentinelOne Event found: {rule_name[index_1]}")
      messagebox.showwarning("Alert", f"SentinelOne Event found: {rule_name[index_1]}")
      for event in allevents:
        att=event["attributes"]
        write_csv_sentinelone(att, index_1)
    if not allevents:
      logger.info(f"No events found for {rule_name[index_1]}, Api results (US, EU and CA repectively): {allstatuses[0]} {allstatuses[1]} {allstatuses[2]}")
  return

def next_run(end_utc):
    next_run = datetime.strptime(end_utc, "%Y-%m-%d %H:%M:%S") + timedelta(hours=1)
    logger.info(f"Next run time is approximately:{next_run}")
    sleep_seconds = (next_run - datetime.now()).total_seconds()
    time.sleep(sleep_seconds)

#Main Script
while True:
    start_utc, end_utc = rules.get_timestamp()
    fortiedr(start_utc, end_utc)
    logger.info(f"FortiEDR APIs Finished")
    sentinelone(start_utc, end_utc)
    logger.info(f"SentinelOne APIs Finished")
    next_run(end_utc)
