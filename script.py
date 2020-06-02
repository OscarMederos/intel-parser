#!/usr/bin/env python
from config import *
import datetime
import smtplib
import pycurl
import socket
import pickle
import time
from time import gmtime
from datetime import datetime
from datetime import timedelta
from email.mime.text import MIMEText
from StringIO import StringIO

debugLevel = 0

############
## FUNCTIONS

def writeToLocalLog( msg ):
	if debugLevel > 0:
		logFile = "/opt/log/debugLog"
	else:
		logFile = "/opt/log/sentinelLog"
	timeStamp = str(datetime.now())
	logTime = datetime.now().strftime("%Y%m%d")
	f = open(logFile + logTime, "a")
	f.write(timeStamp + " " + msg + "\n")
	f.close()

def logError( msg ):
    timeStamp = str(datetime.now())
    logTime = datetime.now().strftime("%Y%m%d")
    f = open("/opt/log/sentinelErrorLog" + logTime, "a")
    f.write(timeStamp + " " + msg + "\n")
    f.close()

def sendSyslog( msg ):
    try:
        logTime = time.strftime("%Y-%m-%di %H:%M:%S", gmtime())
        syslogMessage ="event_time=" + logTime + " host_name=" + host_name + " service=sentinel alert=" + msg
        ls = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ls.sendto(syslogMessage, (syslog_server, 514))
        ls.close()
        return True
    except Exception,e:
        if debugLevel == 1:
            writeToLocalLog(str(e))
        errorMessage = "Sentinel failed to send syslog to " + syslog_server + "from " + host_name + "\n" + str(e)
        logError(errorMessage)
        sendEmail("Error", errorMessage, alert_email)
    return False

def sendEmail( subject, msg, recipients ):
    msg = MIMEText(msg)
    msg['Subject'] = "Sentinel Alert: " + subject
    msg['From'] = 'sentinel@chewy.com'
    msg['To'] = recipients
    recipient = recipients.split(", ")
    success = 0
    loggedError = False
    while success == 0:
        try:
            server = smtplib.SMTP(smtp_server)
            server.set_debuglevel(0)
            server.sendmail(recipients, recipient, msg.as_string())
            server.quit()
        except Exception,e:
            if not loggedError:
                errorMessage = "Sentinel failed to send email to " + smtp_server + "from " + host_name + "\n" + str(e)
                logError(errorMessage)
            if debugLevel == 1: writeToLocalLog("eMail dispatch failed. Sleeping five seconds...")
            time.sleep(5)
        else:
            if loggedError:
                errorMessage = "Sentinel email error cleared"
                logError(errorMessage)
            success = 1
    return True

###############
## MAIN PROCESS
host_name = socket.gethostname()

try:
    state = pickle.load(open("/opt/sentinel/state-threatmanager.p","rb"))
except:
    state = {}

lastBlockrev = state.get("blockrev",0)

while True:
    try:
        buffer = StringIO()
        c = pycurl.Curl()
        c.setopt(c.URL, 'https://rules.emergingthreats.net/blockrules/blockrev')
        c.setopt(c.WRITEDATA, buffer)
        c.perform()
        c.close()
        body = buffer.getvalue()
        currentBlockrev = int(body.strip())
    except:
        sendEmail("Threat Intel Version Check Failed", "Failed to download https://rules.emergingthreats.net/blockrules/blockrev", "jason.rowe@chewy.com, secops@chewy.com")
        currentBlockrev = 0

    if lastBlockrev < currentBlockrev:
        try:
            ## DOWNLOAD NEW BLOCKLIST
            buffer = StringIO()
            c = pycurl.Curl()
            c.setopt(c.URL, 'https://rules.emergingthreats.net/blockrules/emerging-botcc.rules')
            c.setopt(c.WRITEDATA, buffer)
            c.perform()
            c.close()
            body = buffer.getvalue()
            f = open("/opt/sentinel/threatIntel/emerging-botcc.rules", "w")
            f.write(body)
            f.close()
            state["blockrev"] = currentBlockrev
            pickle.dump(state,open("/opt/sentinel/state-threatmanager.p","wb"))
        except:
            sendEmail("Threat Intel Download Failed", "Failed to download https://rules.emergingthreats.net/blockrules/emerging-botcc.rules", "jason.rowe@chewy.com, secops@chewy.com")
    
    time.sleep(3600)
