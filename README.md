 # <b> DPUSEC PCAP Analyzer </b>

# 📌 About the Project
DPUSEC PCAP Analyzer is a PCAP file analysis tool for analyzing network traffic. This tool enables network administrators and cyber security experts to detect potential threats on the network, examine traffic flows and perform attack analysis.
This project was developed by Dumlupınar University Cyber Security Student Community (DPUSEC) Development Team.

# 🚀 Features
PCAP File Analysis: Analyzes network traffic with Suricata rules.
PCAP File Export: Allows you to download files passed in PCAP.
Simple and Detailed Views: Provides simple and detailed analysis reports for users.
Visualization: Shows statistical information about network traffic with graphs.
Custom Rule Upload: Users can upload their own security rules.
Filtering and Sorting: It can filter according to criteria such as source IP, destination IP, protocol, attack type.
Authorization System: Analysis results are stored securely with the user login system.

# 🛠️ Installation and Use

1️⃣ Install Required Dependencies
After cloning the project, run the following command to install the dependencies:


sudo apt update

sudo apt install docker.io 
sudo systemctl enable docker
sudo systemctl start docker

sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose

sudo chmod +x /usr/local/bin/docker-compose

sudo apt-get update
sudo apt-get install docker-compose-plugin
docker compose version


git clone https://github.com/DPUSEC/pcap-analyzer.git

cd pcap-analyzer/

sudo docker-compose up -d --build


This command will run the project on 127.0.0.1:3000.


# 🎯 User Manual

## 📌 Step 1: Login
Enter your user credentials to log in to the system.

## 📌 Step 2: Upload Your PCAP File
Upload your .pcap file you want to analyze.

## 📌 Step 3: Select or Customize Rules
You can use the default Suricata rules or
You can perform more detailed analysis by installing custom rules.

## 📌 Step 4: Start Analysis 🚀
Click on the “Analyze” button to start the process.

## 📌 Step 5: Review Results 📊
Simple View: General traffic analysis and attack types.
Detailed View: Attacks per IP, signature details and in-depth analysis.
.

# 🖥️ Technologies
This project uses the following technologies:

Next.js - React based framework

Go / Gin - Back End server

Tailwind CSS - Modern and fast style definitions

Recharts - Library for visualization

# 💡 Road Map

## 🚀 v1.0 - Release

✅ PCAP analysis module

✅ Simple and detailed view

✅ Suricata rule support

✅ IP filtering and sorting

## 🔜 v2.0 - New Features

🚀 Live traffic analysis

🚀 AI-powered threat detection

🚀 More detailed reporting

# ❓ Frequently Asked Questions (FAQ)

## 1️⃣ My PCAP file won't load, what should I do?

📌 Solution:
Check the size of your PCAP file. 
Be careful not to upload an unsupported or incorrect PCAP file.
.


If the file is corrupt, try with a new PCAP file.

## 2️⃣ How do I add my custom Suricata rules?


📌 Solution:
You can upload your Suricata rule file with .rules extension with the “Upload Custom Rule” button.
After importing the rule set, you should select the rule you uploaded from the Selecr Rule Sets section.
If you are getting errors, check for typos in your .rules file.


## 3️⃣ Analysis is taking too long, what should I do?

📌 Solution:
Check if your PCAP file is too large.
Filter unnecessary network traffic. To speed up the analysis, you can analyze specific IPs or protocols.
You can use a multi-core processor and more RAM to speed up the Suricata engine.

## 4️⃣ Which types of attacks can I detect?

📌 DPUSEC PCAP Analyzer can detect the following attacks and more:

✅ DDoS (Distributed Denial of Service) Attacks

✅ SSH Brute Force

✅ SQL Injection

✅ XSS (Cross Site Scripting) Attacks

✅ Port Scanning

✅ ARP Spoofing

If you want to detect a specific attack, you can add custom Suricata rules.

## 5️⃣ Can I export the results in CSV or JSON format?
Yes!
You can use the “Export Results” option to export the analysis results as JSON.


# 👥 DPUSEC Community Information
DPUSEC operates as Dumlupınar University Cyber Security Student Community in order to share information and develop projects in the field of cyber security.

# 📢 Join Us!
🌐 Website
https://dpusec.org/

🐦 Twitter (X)
https://x.com/DPUS3C

🔗 LinkedIn
https://www.linkedin.com/company/dpus3c/posts/?feedView=all

📷 Instagram
https://www.instagram.com/dpus3c/

If you want to contribute to our projects, you can contact us or join our community! 🚀

# 👨‍💻 Developer Team
This project was developed by DPUSEC Development Team:

👨‍💻 Baris Azar

👨‍💻 Abdullah Ahmet Durmaz

👨‍💻 Ali Umut Soran

👨‍💻 Salih Doğan Bülbül

👨‍💻 Yusuf Can Çakır

If you want to contribute, you can submit a pull request on GitHub!



# 📜 License
This project is licensed under the MIT License.
This license allows the project to be freely used, modified and commercially distributed. However, the project is provided “AS IS” i.e. “As Is” and the developers provide no warranty.

# ⭐ Support!
Don't forget to leave a star on GitHub if you like this project ⭐

<b> THIS IS A BETA VERSION OF THE PROJECT, DEVELOPMENT IS ONGOING </b>

