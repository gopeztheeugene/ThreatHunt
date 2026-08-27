import requests
import json
import auth
import rules
import time
import csv
import tkinter as tk
from tkinter import messagebox
from datetime import datetime, timedelta
import os

#Load output directories
target_dir = os.path.join(os.path.expanduser("~/Documents"), "ThreatHuntOutput")
target_dir_fortiedr = os.path.join(target_dir, "FortiEDR")
target_dir_sentinelone = os.path.join(target_dir, "SentinelOne")
os.makedirs(target_dir, exist_ok=True)
os.makedirs(target_dir_fortiedr, exist_ok=True)
os.makedirs(target_dir_sentinelone, exist_ok=True)

#SentinelOne Rule Names 
rule_name = ['Unusual RDP or Auth Probes', 'Syskey Access','SAM Database Dump','Rundll LSASS Dump', 'Recon CMDs', 'Mesh Service', 'Taskmgr Lsass Dump', 'Wmiexec', 'Smbexec', 'Atexec','Perflogs Staging','Allow RDP', 'Allow Restricted Admin (Allows PTH)', 'Allow RDP 2', 'RDP Port Query', 'Certutil Usage', 'Net Share Scan', 'Share Audit', 'Suspicious Pushd Usage', 'ClickFix Delivery']


#Event Message box setup
root = tk.Tk()
root.withdraw()
root.grab_set()
root.attributes("-topmost", True)

#API URLs
thrive1_url = "https://thrive.console.ensilo.com/management-rest/events/list-events"
thrive2_url = "https://thrive2.console.ensilo.com/management-rest/events/list-events"
thrive3_url = "https://thrive3.console.ensilo.com/management-rest/events/list-events"
thrive4_url = "https://thrive4.fortiedr.com/management-rest/events/list-events"
thrive5_url = "https://thrive5.fortiedr.com/management-rest/events/list-events"
thrive6_url = "https://thrive6.fortiedr.com/management-rest/events/list-events"
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

#Main Script
while True:
    #function call will return start and end time, make sure to change this when sentinelone script is onboarded
    start_utc, end_utc = rules.get_timestamp()
    print(f"Threat hunt coverage: {start_utc} - {end_utc}")

    #FortiEDR APIs
    params = rules.parameters(start_utc, end_utc)
    for index, rule in enumerate(params):
        console1_results = requests.get(thrive1_url ,auth=(auth.thrive1_user, auth.thrive1_pass), params=rule)
        data1=console1_results.json()
      
        console2_results = requests.get(thrive2_url ,auth=(auth.thrive2_user, auth.thrive2_pass,), params=rule)
        data2=console2_results.json()
        
        console3_results = requests.get(thrive3_url ,auth=(auth.thrive3_user, auth.thrive3_pass), params=rule)
        data3=console3_results.json()

        console4_results = requests.get(thrive4_url ,auth=(auth.thrive4_user, auth.thrive4_pass), params=rule)
        data4=console4_results.json()

        console5_results = requests.get(thrive5_url ,auth=(auth.thrive5_user, auth.thrive5_pass), params=rule)
        data5=console5_results.json()
        
        console6_results = requests.get(thrive6_url ,auth=(auth.thrive6_user, auth.thrive6_pass), params=rule)
        data6=console6_results.json()

        all_data = data1 + data2+  data3 + data4 + data5 + data6
        if all_data:
                messagebox.showwarning("Alert", f"FortiEDR Event found: {rule["process"]}")
                write_csv_fortiedr(all_data)
        else:
            print(f"No events found for {rule["process"]}")

    #SentinelOne APIs
    start_est, end_est = utc_to_est(start_utc, end_utc)
    parameters= rules.sentinelone_parameters(start_est, end_est)
    for index,rule in enumerate(parameters):
        result_us = requests.request("POST", url_us, headers=auth.headers_us_s1, data=json.dumps(rule))
        response_us= result_us.text
        data_us=json.loads(response_us)
        events_us=data_us["matches"]
        status_us= data_us["status"]
        
        result_eu = requests.request("POST", url_eu, headers=auth.headers_eu_s1, data=json.dumps(rule))
        response_eu= result_eu.text
        data_eu=json.loads(response_eu)
        events_eu=data_eu["matches"]
        status_eu= data_eu["status"]

        result_ca = requests.request("POST", url_ca, headers=auth.headers_ca_s1, data=json.dumps(rule))
        response_ca= result_ca.text
        data_ca=json.loads(response_ca)
        events_ca=data_ca["matches"]
        status_ca= data_ca["status"]

        all_events = events_us + events_eu + events_ca
        
        if all_events:
            messagebox.showwarning("Alert", f"SentinelOne Event found: {rule_name[index]}")
            for event in all_events:
                att=event["attributes"]
                write_csv_sentinelone(att, index)
        if not all_events:
            print(f"No events found for {rule_name[index]}, Api results (US, EU and CA repectively): {status_us} {status_eu} {status_ca}")
    
    
    now = datetime.now()
    one_hour_later = now + timedelta(hours=1)
    print("Next run is approx:", one_hour_later)
    time.sleep(3000)