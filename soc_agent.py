import os
import sys
import requests
from dotenv import load_dotenv
from langchain.chat_models import init_chat_model
from langchain_core.tools import tool
from langgraph.prebuilt import create_react_agent

# --- INPUT REQUIREMENTS ---
# This script requires a .env file with VIRUSTOTAL_API_KEY and GOOGLE_API_KEY
load_dotenv() #

@tool
def check_virustotal(ip_address: str):
    """Checks the reputation of an IP address using VirusTotal API."""
    vt_key = os.getenv("VIRUSTOTAL_API_KEY") #
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}" #
    headers = {"x-apikey": vt_key} #
    
    try:
        response = requests.get(url, headers=headers) #
        return response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {}) #
    except Exception as e:
        return f"Error: {e}"

@tool
def search_splunk(source_ip: str, dest_ip: str, start_time: str, end_time: str):
    """Queries internal Splunk API for network traffic logs."""
    # Update with your authorized Splunk API endpoint
    url = "http://<INTERNAL_SPLUNK_IP>/api/splunk" #
    params = {"source_ip": source_ip, "dest_ip": dest_ip, "start_time": start_time, "end_time": end_time} #
    
    try:
        response = requests.get(url, params=params) #
        return response.json() #
    except Exception as e:
        return f"Splunk Connection Error: {e}"

@tool
def search_dhcp(source_ip: str, start_time: str, end_time: str):
    """Queries DHCP logs for internal user and hostname attribution."""
    # Update with your authorized DHCP API endpoint
    url = "http://<INTERNAL_DHCP_IP>/api/dhcp" #
    params = {"source_ip": source_ip, "start_time": start_time, "end_time": end_time} #
    
    try:
        response = requests.get(url, params=params) #
        return response.json() #
    except Exception as e:
        return f"DHCP Connection Error: {e}"

# --- AGENT INITIALIZATION ---
tools = [check_virustotal, search_splunk, search_dhcp] #
model = init_chat_model("gemini-2.0-flash", model_provider="google_genai") #

SYSTEM_PROMPT = """
You are a SOC Analyst. Follow these steps:
1. Extract IPs and timestamps from the ticket.
2. Use check_virustotal on suspicious IPs.
3. Use search_dhcp and search_splunk for internal context.
4. Generate a report with Executive Summary, IoCs, Evidence, and Recommendations.
""" #

agent = create_react_agent(model, tools) #

def main():
    # INPUT: Provide the path to a ticket text file as a command-line argument
    if len(sys.argv) < 2:
        print("Usage: python soc_agent.py ticket.txt") #
        sys.exit(1)
        
    try:
        with open(sys.argv[1], 'r') as f:
            ticket_content = f.read() #
    except FileNotFoundError:
        print("Error: Ticket file not found.") #
        sys.exit(1)

    messages = [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": ticket_content}] #

    print(f"--- Investigating {sys.argv[1]} ---")
    for step in agent.stream({"messages": messages}, stream_mode="values"): #
        step["messages"][-1].pretty_print() #

if __name__ == "__main__":
    main()
