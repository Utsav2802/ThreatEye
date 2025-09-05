CONTENTS

Chapters	Particulars	Page No.
1	Introduction
1.1.	Objective of the New System
1.2.	Problem Definition
1.3.	Core Components
1.4.	Project Profile
1.5.	Assumptions and Constraints
1.6.	Advantages and Limitations of the Proposed System	


2	Requirement Determination & Analysis
2.1.	Requirement Determination
2.2.	Targeted Users
2.3.	Details of tools and techniques used / implemented
2.4.	Advantages and Limitations of the used security tools	


3	System Design
3.1	Flow chart
3.2	Workflow
3.3	Use case	


4	Development
4.1 Script details / Source code
4.2. Screen Shots / UI Design of simulation (if applicable)
4.3. Test reports 
	


5	Proposed Enhancements	     
6	Conclusion	
7	Bibliography











	















                     
                 

Chapter-1
Introduction











1.1	Objective

To create an EDR (Endpoint Detection and Response) system that is script-based, lightweight, and continuously monitors system processes. It can identify suspicious and take necessary measures, such as logging, alerting, or quarantining the threat, without the need for any AI or third-party antivirus software.


1.2	Definition of the Problem

In many systems, particularly Linux or development environments without antivirus software, threats such as backdoors, command-line payloads, or illegal scripts could exist undetected. Manual monitoring takes a lot of time and is not always accurate.

The lack of a lightweight, automated, real-time solution for tracking and reacting to questionable system activity is the issue.

Goal: Developing a script-driven technology that automatically recognizes dangerous behaviour and reacts immediately. 


1.3	Core Components

Component	Description
Process Scanner	Scans all active processes and collects metadata
Threat Matcher	Compares process behaviour against a list of suspicious keywords, hashes
Logger	Logs alerts in a SQLite database and .txt file
Response Module	Tries to quarantine harmful files/processes by killing or moving them
Telegram Alert Bot	Sends instant alert messages to a pre-configured Telegram chat
Dashboard (Streamlit)	Displays threats in a live, filterable table with summaries

Table 1.1 - Core Components









1.4	Project Profile


Project Name	-	ThreatEye

Languages Used	-	Python, Shell Scripting
Database	-	SQLite – a local, lightweight database for storing alerts
Tools Used	-	psutil (process scanning), Streamlit (dashboard), Telegram API (alerts)
Platform	-	Compatible with Linux and Windows systems
Scope	-	Monitor and respond to suspicious processes in real-time without using AI or external antivirus solutions

Table 1.2- Description and attribute
 
1.5	Project Profile

Python and shell scripting are used in the development of the Script-Based Endpoint Threat Detection System project. With a concentration on real-time system process monitoring to identify any threats, it is made to operate on both the Windows operating systems. The Telegram API is used to send quick notifications, a Streamlit is used to show alerts on a live dashboard, and the psutil library is utilized for scanning current processes. For convenience and documentation, every detected warning is kept in a small SQLite database. The project is a simple but efficient solution for basic endpoint threat detection because it doesn't depend on artificial intelligence or third-party antivirus software.

1.6	Premises and Limitations

Premises: 
-	Python will be installed on Windows OS or Linux for the system to function.
-	The user can read process information via basic permissions.
-	Telegram alerts can be accessed via the internet.

Limitations: 
-	Quarantine activities require root or administrative permissions.
-	Can only identify dangers using pre-established rules, hashes, and keywords.
-	Makes no use of behavioural AI models or polymorphic malware detection. 
-	When developer systems purposefully employ tools like Powershell or Netcat, it may result in false positives.








1.7	Advantages and Limitations of the Proposed System

Advantages:
•	Lightweight and fast – runs on minimal resources.
•	No need for internet except for Telegram alerts.
•	Fully customizable via configuration files.
•	Works on systems without traditional antivirus tools.

Limitations:
•	No AI or advanced machine learning – purely rule-based.
•	Can miss new or unknown types of attacks not listed in rules.
•	Needs regular updating of threat keywords, hashes, and indicators.




















































                               Chapter- 2
Requirement Determination 
& Analysis





















 2.1 Requirement Determination

-To build a functional and efficient endpoint threat detection system, the following requirements were identified:

Functional Requirements:
•	Scan all running processes on the system
•	Detect suspicious processes based on keywords, hashes, or patterns
•	Log alerts into a database and text file
•	Send real-time notifications via Telegram
•	Display threat data on a live dashboard

Non-Functional Requirements:
•	Must run with low CPU/memory usage
•	Should work without an internet connection (except for Telegram)
•	Easy to configure using .cfg or .ini files
•	Should work cross-platform (Linux/Windows)


2.2 Targeted Users

This project is targeted at:
•	System Administrators – to monitor unauthorized activities on servers/workstations.
•	Cybersecurity Learners – to understand how basic EDR systems work.
•	Educational Institutions – as a demo tool for cybersecurity labs or courses.
•	Developers – who want a lightweight threat monitor without antivirus.



2.3 Details of Tools and Techniques Used / Implemented

Tool/Library	Purpose
psutil	Process scanning: retrieves running process details
sqlite3	Stores alerts in a local database
logging	Logs threat info to a readable .txt file
requests	Sends Telegram alerts via Bot API
Streamlit	Creates a live web dashboard with filters and graphs
Shell scripting	Automates script execution or integrates with OS tasks

Table 2.1- Tools/Libraries








 2.4 Advantages and Limitations of the Used Security Tools

 Advantages:
•	Open-source and easy to integrate.
•	Lightweight and does not slow down the system.
•	Highly customizable with config files.
•	No dependency on commercial antivirus or cloud services.
•	Works offline (except Telegram alerts).

Limitations:
•	Does not use AI or machine learning to detect unknown threats.
•	May generate false positives for legitimate admin tools.
•	Quarantine may fail without admin/root access.
•	No file scanning or behavioural analysis beyond rule-based checks.












































                                  Chapter-3
System Design


























3.1 Flowchart



Script-Based Endpoint Threat Detection System
│
├── Start
│   └── Read Process Info
│       └── Match with Keywords / Hashes / IPs?
│           ├── Yes
│           │   ├── Log Alert
│           │   ├── Quarantine Threat
│           │   ├── Send Telegram Alert
│           │   └── Continue Monitoring → Repeat
│           └── No
│               └── Continue Monitoring → Repeat

Fig 3.1- flowchart
             

Fig 3.2 System Workflow









Explanation of System Workflow-

Step1- Launch the application
After starting, the EDR script enters a loop of continuous monitoring.

Step 2- Read Process info
It gathers information about all active processes, including the process name, PID, path, and user.

Step 3- Match with Threat Indicators
Every process is examined in relation to:-
-suspicious keywords (such as netcat and powershell)
-Malicious hashes
-IPs that are blocked or display unusual behavior

Step 4 - IF Threat is Discovered:- 
-Capture the alert in the database and the log file.
-Try to stop and isolate the process.
-Send a detailed Telegram alert.

Step 5- If No Threat is Found-  
In the background, the system keeps checking for new threats.

 

Fig3.3:- EDR System Functions and User Roles


This diagram is a Use Case Diagram that shows how the Security Analyst interacts with the EDR System.
•	The EDR System automatically does tasks like:
o	Scans processes
o	Detects suspicious activity
o	Logs threats
o	Sends Telegram alerts
o	Quarantines malicious files
•	The Security Analyst (user) can:
o	View live alerts on the dashboard
o	Filter/search alerts by PID, username, or keyword
o	Review threat logs for investigation
o	Configure detection rules (keywords, hashes, IPs)















































                             Chapter 4
Development













4.1 Script details / Source code

A ) main_monitor.py
 
Fig :- 4.1 


Fig :- 4.2 

 
Fig :- 4.3

 
Fig :- 4.4



B) dashboard.py
 
Fig :- 4.5

 
Fig :- 4.6

 
Fig :- 4.7 

C) threats.json
 
Fig :- 4.8 

1.	Threat Detection Script

-	Scripts in Python and Shell were created to use psutil to continuously monitor processes that were operating. Each operation is compared to a list of suspicious phrases, hashes, or IP addresses by the system. When a match is discovered, the system proceeds on to quarantine, alert, and logging procedures.

2.	Telegram Alert Integration
-	 The security team gets immediate Telegram warnings when threats are detected. Process name, PID, cause, username, and action taken (Alert-Only or Quarantined) are all included in the alerts.

-	A quarantined process represents a program that has been stopped and its executable moved to a secure place, whereas an alert-only process is one that has been logged but not stopped.

 
                      Fig 4.9:- Telegram Alert – Alert-Only Notification

         
               Fig4.10: - Telegram Alert – Quarantined Process Notification

3.	Threat Logging

•	Each of the detection event is documented in a text log file called threat_log.txt, which also includes: -
- The detection timestamp
- Details of the process (name, PID, user)
- Action conducted (Quarantined or Alert-Only)

•	Auditing, investigating incidents, and monitoring recurring threats over time all rely on this logging system.


 

Figure 4.11: Threat log entries showing suspicious PowerShell executions and corresponding quarantine actions.

4. Real-Time Dashboard

Developed an interactive dashboard with Streamlit for monitoring threats in real time.

Key features:
-	The latest detections are displayed in a live alert feed that automatically refreshes.
-	To make searching simpler, you can filter options by username, PID, or reason keyword.
-	Threat Summary showing quarantined counts, unique processes, and total notifications.
-	The display is always updated since data is received directly from the SQLite database.

 
Figure 4.12: Real-time threat monitoring dashboard with live alerts, filters, and summary statistics.


5.	Testing

•	Used a variety of suspicious commands, process names, and malicious activity simulators to carry out several test cases.

•	Verified that the system: - 
- Precisely detects dangers
- Carries out measures of quarantine without compromising valid processes.
- Instantly sends Telegram alerts
- Immediately updates the dashboard and logs
- Verified that there are no system crashes during the detection, quarantine, and alert procedures.



















Chapter-5
                          Proposed Enhancements















Proposed Enhancements

Future enhancements could make the existing system more effective, user-friendly and capable of handling today's security concerns, even if it now monitors procedures and identifies dangers using pre-established rules.

1. Advanced Techniques for Detection
- Using behavioural patterns rather than merely keywords or hashes, integrate machine learning models to identify unknown threats.
- Real-time anomaly detection can be used to identify odd process activity.

2. Integration of Threat Intelligence
- To automatically update harmful IPs, domains, and file hashes, connect to online threat intelligence feeds (such as VirusTotal and AbuseIPDB)
- Allow the rules/configuration file to be updated automatically.

3. Improved Ability to Respond
- Isolate the affected endpoints from the network.
- Provide the option to restore or roll back quarantined files in the situation that they get recognized as false positives.
- Process sandboxing should be included for secured examination prior to termination.

4. Improved Visualization and Dashboard
- Include real-time charts displaying the CPU and memory utilization of suspicious processes.
- Permit reports to be generated in Excel and PDF formats for compliance and audits.
- Allow SOC teams role-based access control including multi-user login.

5. Cross-Platform Optimization
- Make a small, portable agent that works with Windows, Linux, and macOS.
- Along with Telegram alerts, include support for push notifications on smartphones.

6. Automatic Reporting of Incidents
- When a danger is recognized, we immediately generate incident tickets.

- Collaborate with SIEM applications for centralized logging, like Splunk, ELK, or Wazuh.















                                    Chapter-6 
Conclusion


















Conclusion

Without the need for complex antivirus software or artificial intelligence (AI)-based engines, the Script-Based Endpoint Threat Detection System effectively demonstrates how lightweight Python and Shell scripting may be used to monitor, identify, and react to suspicious activity on an endpoint.

Running processes are continuously scanned by the system, which compares them to pre-established keywords, hashes, and IP addresses before performing tasks like logging, quarantining, and sending immediate alerts using Telegram. Real-time monitoring is made possible by the Streamlit dashboard, which also makes the service suitable by both technical and non-technical users.

Despite being rule-based at the moment, the project provides a useful and practical framework for developing advanced EDR solutions. This solution can develop into a more complete endpoint security platform with future improvements including AI-driven detection, integration with real-time threat intelligence feeds, and improved event tracking.

All things considered, the project achieves its goal of offering a simple, user-friendly, effective endpoint monitoring solution that can be used for basic security monitoring, education, and as a proof-of-concept for larger-scale deployments.
























                                  Chapter-7
Bibliography















Bibliography

Offline References

1.	Strom D.  7 trends in advanced endpoint protection 2019. https://www.networkworld.com/article/3089858/endpoint-protection/7-trends-in-advanced-endpoint-protection.html
2.	Arcticwolf.  Endpoint  Detection  and  Response  Is  Not  Enough  2019. https://arcticwolf.com/resources/blog/end point-detection-and-response-is-not-enough/ 
3.	Asher-Dothan  L.  Seven  essential  elements  of  modern endpoint  security  2017.  https://www.cybereason.com/blog/ 7-elements-of-modern-endpoint-security
4.	Zhou, C., Cheng, Y., & Liao, H. (2019, October). Endpoint protection: Measuring the effectiveness of remediation technologies and methodologies for insider threat. In 2019 International Conference on Cyber-Enabled Distributed Computing and Knowledge Discovery (CyberC) (pp. xxx–xxx). IEEE
5.	Dong, F., Li, S., Jiang, P., Li, D., Wang, H., Huang, L., … Chen, X. (2023). Are we there yet? An Industrial Viewpoint on Provenance-based Endpoint Detection and Response Tools. arXiv
6.	Shen, X., Li, Z., Burleigh, G., Wang, L., & Chen, Y. (2024). Decoding the MITRE Engenuity ATT&CK Enterprise Evaluation: An Analysis of EDR Performance in Real-World Environments. arXiv.
7.	Kaur, H., & Tiwari, R. (2021). Endpoint detection and response using machine learning. Journal of Physics: Conference Series, 2062, 012013. 
8.	Shaik, S. (2024). Impact of Endpoint Detection and Response Tools on SOC Efficiency. Zenodo.
9.	“InMesh: A Zero-Configuration Agentless Endpoint Detection and Response System,” MDPI Electronics.
10.	cyberdyne-ventures, “OpenDR: A FOSS Endpoint Detection and Response Alternative Implemented in Python Using psutil,” GitHub, 2025.
11.	op7ic, “EDR-Testing-Script: Test the Accuracy of Endpoint Detection and Response Software,” GitHub, 2025.
12.	Constantin Hentgen, “Forge-EDR: An Educational Python EDR Project,” GitHub Blog, 2025.
13.	M. Rhode, P. Burnap, and A. Wedgbury, “Real-time malware process detection and automated process killing,” arXiv, Feb. 2019.
14.	K. Shulika et al., “A method of using modern endpoint detection and response (EDR) systems to protect against complex attacks,” Innov. Technol. Sci. Solut. Ind., no. 2(28), pp. 182–195, Jun. 2024.

Online References 

15.	Giampaolo Rodola. psutil: Cross-platform process and system utilities. Python Software Foundation. Available at: https://psutil.readthedocs.io
16.	D. Richard Hipp. SQLite Documentation. SQLite Consortium. Available at: https://www.sqlite.org/docs.html
17.	Python Software Foundation. logging — Logging facility for Python. Available at: https://docs.python.org/3/library/logging.html
18.	Telegram Messenger LLP. Telegram Bot API Documentation. Available at: https://core.telegram.org/bots/api
19.	Python Software Foundation. hashlib — Secure hashes and message digests. Available at: https://docs.python.org/3/library/hashlib.html
20.	Mendel Cooper. Advanced Bash-Scripting Guide. Available at: https://www.shellscript.sh

