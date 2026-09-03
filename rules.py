import time
from datetime import datetime, timedelta
import logs
import os

logger= logs.setup_logging(log_file="logs.log", path=os.path.join(os.path.expanduser("~/Documents"), "ThreatHuntOutput"))

def get_timestamp():
    end_time = datetime.now()
    end_str = end_time.strftime("%Y-%m-%d %H:%M:%S")
    last_run = os.path.join(os.path.expanduser("~/Documents"), "ThreatHuntOutput", "last_run.txt")
    with open(last_run, "r", encoding="utf-8") as f:
        line = f.readline().strip()
        last_run_time = datetime.strptime(line, "%Y-%m-%d %H:%M:%S.%f")
    with open(last_run, "w", encoding="utf-8") as f: f.write(f"{end_time}")
    start_str = last_run_time.strftime("%Y-%m-%d %H:%M:%S")
    logger.info(f"Threat hunt coverage: {start_str} - {end_str}")
    return start_str, end_str

def parameters_fortiedr(start, end):
    payload = [
                {
                    "rule": "Access to Critical System Information",
                    "process": "rundll32.exe",
                    "lastSeenFrom": start,
                    "lastSeenTo": end
                },
            
                {
                    "rule": "Access to Critical System Information",
                    "process": "taskmgr.exe",
                    "lastSeenFrom": start,
                    "lastSeenTo": end
                },
                {
                    "rule": "Access to Critical System Information",
                    "process": "svchost.exe",
                    "lastSeenFrom": start,
                    "lastSeenTo": end
                },
                {
                    "process": "Suspicious Files Created in Perflogs",
                    "lastSeenFrom": start,
                    "lastSeenTo": end
                },
                {
                    "process": "Explorer Privilege Escalation",
                    "lastSeenFrom": start,
                    "lastSeenTo": end
                },
                {
                    "process": "Task Manager LSASS Dump",
                    "lastSeenFrom": start,
                    "lastSeenTo": end
                },
                {
                    "process": "Net Share Scan",
                    "lastSeenFrom": start,
                    "lastSeenTo": end
                },
                {
                    "process": "SAM Database Dump",
                    "lastSeenFrom": start,
                    "lastSeenTo": end
                },
                {
                    "process": "Share Audit",
                    "lastSeenFrom": start,
                    "lastSeenTo": end
                },
                {
                    "process": "Certutil Usage",
                    "lastSeenFrom": start,
                    "lastSeenTo": end
                },
                {
                    "process": "Suspicious Pushd Usage",
                    "lastSeenFrom": start,
                    "lastSeenTo": end
                }
                    ]
    return payload

def sentinelone_parameters(start, end): 
    payload= [
            {
                "queryType": "log",
                "startTime": str(start),
                "endTime": str(end),
                "filter":  "(dst.port.number = \"3389\" or dst.port.number = \"636\" or dst.port.number =\"88\") and (src.process.image.path contains \"programdata\" or (src.process.image.path contains \"temp\"and src.process.image.path !contains \"pendingdelete\") or src.process.image.path contains \"tmp\" or src.process.image.path contains \"public\" or src.process.image.path contains \"Appdata\") and dst.ip.address != \"127.0.0.1\" and event.network.direction =\"OUTGOING\" AND !(src.process.user contains \"CO-SK\" and src.process.name contains:anycase \"motty.exe\" ) AND !(src.process.image.path contains \"C:\\Auvik\" and src.process.name contains:anycase \"AuvikService\" ) AND !(src.process.cmdline contains \"jwaller\" and src.process.name = \"RDCMan.exe\" ) AND !(src.process.cmdline contains \"jworthy\" and src.process.name = \"RDCMan.exe\" ) AND !(src.process.user contains \"PLegislador\" and src.process.name = \"MobaRTE.exe\" )",
                "columns" : "site.name, event.time, endpoint.name,event.type, src.process.name,src.process.cmdline, src.process.parent.name, src.process.user, src.process.startTime, dst.ip.address, dst.port.number,src.process.image.path, src.ip.address, src.process.image.sha1"
            },
            {
                "queryType": "log",
                "startTime": str(start),
                "endTime": str(end),
                "filter":  "indicator.name= \"AccessSyskey\" and indicator.metadata contains:anycase \"SYSTEM\"",
                "columns" : "site.name, event.time, event.type, endpoint.name,src.process.name,src.process.cmdline, src.process.parent.name, indicator.metadata, indicator.name, src.process.user, src.process.startTime"
            },
            {
                "queryType": "log",
                "startTime": str(start),
                "endTime": str(end),
                "filter":  "(tgt.process.name = \"reg.exe\" and tgt.process.cmdline contains \"save\" and (tgt.process.cmdline contains \"SAM\" or tgt.process.cmdline contains \"SYSTEM\") and src.process.parent.name != \"ir_agent.exe\" and !(tgt.process.cmdline contains:anycase \"HKLM\\SOFTWARE\") and !(tgt.process.cmdline contains:anycase \"SavedDriverParameters\") and !(tgt.process.cmdline contains \"screensave\") and !(tgt.process.cmdline contains \"rapid7\")) or (src.process.name = \"reg.exe\" and event.type contains \"File\" and src.process.cmdline contains \"save\" and (src.process.cmdline contains \"SAM\" or src.process.cmdline contains \"SYSTEM\"))",
                "columns" : "site.name, event.time, endpoint.name,event.type, src.process.name,src.process.cmdline, src.process.parent.name, src.process.user, src.process.image.path, src.process.startTime, tgt.process.name, tgt.process.cmdline, tgt.process.startTime"
            },
            {
                "queryType": "log",
                "startTime": str(start),
                "endTime": str(end),
                "filter":  "src.process.name contains:anycase \"rundll32.exe\" and src.process.cmdline contains:anycase \"comsvcs.dll\"",
                "columns" : "site.name, event.time, endpoint.name,event.type, src.process.name,src.process.cmdline, src.process.parent.name, src.process.user, src.process.image.path, src.process.startTime, tgt.file.path, tgt.file.name, tgt.file.size"
            },
            {
                "queryType": "log",
                "startTime": str(start),
                "endTime": str(end),
                "filter":  "(src.process.name = \"cmd.exe\" or src.process.name =\"powershell.exe\") and ((tgt.process.cmdline contains \"domain computers\" or tgt.process.cmdline contains \"/dclist\" or tgt.process.cmdline contains \"/domain_trusts\" or tgt.process.cmdline contains \"Get-ADComputer\" or tgt.process.cmdline contains \"“Domain admins”\"  or tgt.process.cmdline contains \"/Q /c esentutl.exe\") or (tgt.process.name = \"wevtutil.exe\" and tgt.process.cmdline contains \"cl\" and tgt.process.name \"Security\"))",
                "columns" : "site.name, event.time, endpoint.name,event.type, src.process.name,src.process.cmdline, src.process.parent.name, src.process.user, src.process.image.path, src.process.startTime, tgt.process.name, tgt.process.cmdline, tgt.process.startTime"
            },
            {
                "queryType": "log",
                "startTime": str(start),
                "endTime": str(end),
                "filter":  "src.process.cmdline contains \"--meshServiceName=\" and site.name != \"BergmeyerAssociates\"",
                "columns" : "site.name, event.time, endpoint.name,event.type, src.process.name,src.process.cmdline, src.process.parent.name, src.process.user, src.process.image.path, src.process.startTime, tgt.process.name, tgt.process.cmdline"
            },
            {
                "queryType": "log",
                "startTime": str(start),
                "endTime": str(end),
                "filter":  "src.process.name contains:anycase \"taskmgr\" and tgt.file.name contains:anycase \"lsass\" and tgt.file.name contains:anycase \"dmp\"",
                "columns" : "site.name, event.time, endpoint.name,event.type, src.process.name,src.process.cmdline, src.process.parent.name, src.process.user, src.process.image.path, src.process.startTime, tgt.file.path, tgt.file.name, tgt.file.size"
            },
            {
                "queryType": "log",
                "startTime": str(start),
                "endTime": str(end),
                "filter":  "osSrc.process.name contains:anycase \"wmiprvse.exe\" and tgt.process.name = \"cmd.exe\" and tgt.process.cmdline contains \"cmd.exe /Q /c\" and tgt.process.cmdline contains \"2>&1\"",
                "columns" : "site.name, event.time, endpoint.name,event.type, src.process.name,src.process.cmdline, src.process.parent.name, src.process.user, src.process.image.path, src.process.startTime, tgt.process.name, tgt.process.cmdline, tgt.process.startTime, osSrc.process.name, osSrc.process.startTime " 
            },
            {
                "queryType": "log",
                "startTime": str(start),
                "endTime": str(end),
                "filter":  "osSrc.process.name = \"services.exe\" and tgt.process.name = \"cmd.exe\" and tgt.process.cmdline contains \"cmd.exe /Q /c\" and tgt.process.cmdline contains \"echo\"",
                "columns" : "site.name, event.time, endpoint.name,event.type, src.process.name,src.process.cmdline, src.process.parent.name, src.process.user, src.process.image.path, src.process.startTime, tgt.process.name, tgt.process.cmdline, tgt.process.startTime, osSrc.process.name"
            },
            {
                "queryType": "log",
                "startTime": str(start),
                "endTime": str(end),
                "filter":  "src.process.name contains \"cmd.exe\" and src.process.cmdline contains:anycase \"C\" and src.process.cmdline contains:anycase \"WINDOWS\" and src.process.cmdline contains:anycase \"temp\" and src.process.parent.cmdline contains \"Schedule\" and src.process.cmdline contains \"2>&1\" and !(src.process.cmdline contains:anycase \"fortiedr\") and src.process.parent.name=\"svchost.exe\" and !(src.process.cmdline contains \"\\\\\") or indicator.name  = \"ScheduledTaskCmdCommandExecutedRemotely\"",
                "columns" : "site.name, event.time, endpoint.name,event.type, src.process.name,src.process.cmdline, src.process.parent.name, src.process.user, src.process.image.path, src.process.startTime, tgt.process.name, tgt.process.cmdline, tgt.process.startTime, src.process.parent.cmdline"
            },
            {
                "queryType": "log",
                "startTime": str(start),
                "endTime": str(end),
                "filter":  "tgt.file.path contains \"perflogs\" and (tgt.file.extension contains \"exe\" or tgt.file.extension contains \"bat\" or tgt.file.extension contains \"jar\" or tgt.file.extension contains \"py\" or tgt.file.extension contains \"dll\" or tgt.file.extension contains \"ps1\") and event.type = \"File Creation\"",
                "columns" : "site.name, event.time, endpoint.name,event.type, src.process.name,src.process.cmdline, src.process.parent.name, src.process.user, src.process.image.path, src.process.startTime, tgt.file.path, tgt.file.name, tgt.file.size, tgt.file.type, tgt.file.extension"
            },
            {
                "queryType": "log",
                "startTime": str(start),
                "endTime": str(end),
                "filter":  "tgt.process.name contains \"netsh.exe\" and tgt.process.cmdline contains \"3389\" and tgt.process.cmdline contains \"allow\"",
                "columns" : "site.name, event.time, endpoint.name,event.type, src.process.name,src.process.cmdline, src.process.parent.name, src.process.user, src.process.image.path, src.process.startTime, tgt.process.name, tgt.process.cmdline, tgt.process.startTime, src.process.parent.cmdline"
            },
            {
                "queryType": "log",
                "startTime": str(start),
                "endTime": str(end),
                "filter":  "tgt.process.name contains:anycase \"reg.exe\" and tgt.process.cmdline contains:anycase \"DisableRestrictedAdmin\" and tgt.process.cmdline contains \"0\"",
                "columns" : "site.name, event.time, endpoint.name,event.type, src.process.name,src.process.cmdline, src.process.parent.name, src.process.user, src.process.image.path, src.process.startTime, tgt.process.name, tgt.process.cmdline, tgt.process.startTime, src.process.parent.cmdline, osSrc.process.name, osSrc.process.startTime "
            },
            {
                "queryType": "log",
                "startTime": str(start),
                "endTime": str(end),
                "filter":  "tgt.process.name contains:anycase \"reg.exe\" and tgt.process.cmdline contains:anycase \"fDenyTSConnections\" and tgt.process.cmdline contains \"0\"",
                "columns" : "site.name, event.time, endpoint.name,event.type, src.process.name,src.process.cmdline, src.process.parent.name, src.process.user, src.process.image.path, src.process.startTime, tgt.process.name, tgt.process.cmdline, tgt.process.startTime, src.process.parent.cmdline, osSrc.process.name, osSrc.process.startTime "
            },
            {
                "queryType": "log",
                "startTime": str(start),
                "endTime": str(end),
                "filter":  "tgt.process.name contains:anycase \"reg.exe\" and tgt.process.cmdline contains:anycase \"query\" and tgt.process.cmdline contains:anycase \"Terminal Server\" and tgt.process.cmdline contains:anycase \"PortNumber\"",
                "columns" : "site.name, event.time, endpoint.name,event.type, src.process.name,src.process.cmdline, src.process.parent.name, src.process.user, src.process.image.path, src.process.startTime, tgt.process.name, tgt.process.cmdline, tgt.process.startTime, src.process.parent.cmdline, osSrc.process.name, osSrc.process.startTime "
            },
            {
                "queryType": "log",
                "startTime": str(start),
                "endTime": str(end),
                "filter":  "src.process.name = \"certutil.exe\" and src.process.cmdline contains \"urlcache\"",
                "columns" : "site.name, event.time, endpoint.name,event.type, src.process.name,src.process.cmdline, src.process.parent.name, src.process.user, src.process.image.path, src.process.startTime, tgt.file.name, tgt.file.path, tgt.file.sha1"
            },
            {
                "queryType": "log",
                "startTime": str(start),
                "endTime": str(end),
                "filter":  "tgt.file.name = \"delete.me\"",
                "columns" : "site.name, event.time, endpoint.name,event.type, src.process.name,src.process.cmdline, src.process.parent.name, src.process.user, src.process.image.path, src.process.startTime, tgt.file.name, tgt.file.path, tgt.file.sha1"
            },
            {
                "queryType": "log",
                "startTime": str(start),
                "endTime": str(end),
                "filter":  "tgt.file.name contains \"shareaudit\"",
                "columns" : "site.name, event.time, endpoint.name,event.type, src.process.name,src.process.cmdline, src.process.parent.name, src.process.user, src.process.image.path, src.process.startTime, tgt.file.name, tgt.file.path, tgt.file.sha1"
            },
            {
                "queryType": "log",
                "startTime": str(start),
                "endTime": str(end),
                "filter":  "(src.process.name = \"cmd.exe\" or src.process.name =\"powershell.exe\") and src.process.cmdline contains \"pushd\" and (tgt.process.name = \"msiexec.exe\" or tgt.process.name = \"rundll32.exe\" or tgt.process.name = \"mshta.exe\")",
                "columns" : "site.name, event.time, endpoint.name,event.type, src.process.name,src.process.cmdline, src.process.parent.name, src.process.user, src.process.image.path, src.process.startTime, tgt.process.name, tgt.process.cmdline, tgt.process.startTime, src.process.parent.cmdline"
            },
            {
                "queryType": "log",
                "startTime": str(start),
                "endTime": str(end),
                "filter":  "((src.process.name = \"cmd.exe\" or src.process.name contains \"powershell\") and tgt.process.name = \"finger.exe\") or (indicator.name =\"ClipboardPhishingFromBrowserToRunWindow\" and !(src.process.cmdline contains \"printui.dll\") and !(src.process.name contains \"Onenote\" or src.process.name contains \"olk.exe\" or src.process.name contains \"excel.exe\" or src.process.name contains \"OneDrive\" or src.process.name contains \"outlook\" or src.process.name contains \"acrobat.exe\")) or ((src.process.name = \"cmd.exe\" or src.process.name contains \"powershell\") and tgt.process.name = \"where.exe\" and (tgt.process.cmdline contains \"cm?\" or tgt.process.cmdline contains \"cu?\"))",
                "columns" : "site.name, event.time, endpoint.name,event.type, src.process.name,src.process.cmdline, src.process.parent.name, src.process.user, src.process.image.path, src.process.startTime, tgt.process.name, tgt.process.cmdline, tgt.process.startTime, src.process.parent.cmdline, indicator.name, indicator.metadata"
            }
        ]
    return payload