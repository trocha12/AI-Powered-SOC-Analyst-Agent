# AI-Powered-SOC-Analyst-Agent
An automated Tier-1 Security Operations Center (SOC) Analyst agent built using LangChain, LangGraph, and Google Gemini. This tool autonomously investigates security alert tickets by correlating data across multiple security platforms to generate a comprehensive incident report.

Project Overview
The agent follows a ReAct (Reasoning and Acting) pattern to analyze suspicious activity. It extracts indicators from a ticket, queries security tools for context, and summarizes findings into a structured report.

Key Features
Autonomous Investigation: Automatically extracts Source IP, Destination IP, and timestamps from incoming alerts.

Multi-Tool Integration:

VirusTotal: Performs reputation checks on external IP addresses.

Splunk: Queries network traffic logs for specific time windows.

DHCP: Maps internal IP addresses to specific hostnames and users.

Structured Reporting: Outputs a final report including Executive Summary, Indicators of Compromise (IoCs), Evidence, and Recommendations.

Prerequisites
Python 3.x

API Keys: Required for Google Gemini and VirusTotal.

Network Access: Connection to internal lab environments (e.g., via VPN) to reach Splunk and DHCP API endpoints.

Installation & Setup
Clone the Repository:

Bash

git clone https://github.com/your-username/soc-agent.git
cd soc-agent
Install Dependencies:

Bash

pip install requests python-dotenv langchain langgraph google-generativeai
Configure Environment Variables: Create a .env file in the root directory:

Plaintext

GOOGLE_API_KEY=your_gemini_key
VIRUSTOTAL_API_KEY=your_vt_key
SPLUNK_API_URL=http://<INTERNAL_IP>/api/splunk
DHCP_API_URL=http://<INTERNAL_IP>/api/dhcp
Usage
Run the agent by providing a security ticket as a text file argument:

Bash

python soc_agent.py alert_ticket.txt


DISCLAIMER: This tool is intended for educational and authorized security testing purposes only. The author is not responsible for any misuse.
