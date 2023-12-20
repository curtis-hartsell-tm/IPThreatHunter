import pandas as pd
import requests
from azure.identity import ClientSecretCredential
from tqdm import tqdm
import json

# Azure AD credentials
client_id = 'YOUR_CLIENT_ID'
client_secret = 'YOUR_CLIENT_SECRET'
tenant_id = 'YOUR_TENANT_ID'

# Function to get access token
def get_access_token(client_id, client_secret, tenant_id):
    token_url = f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token'
    token_data = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
        'scope': 'https://graph.microsoft.com/.default'
    }
    token_r = requests.post(token_url, data=token_data)
    token = token_r.json().get("access_token")
    return token

# Function to get IP reputation from the MDTI API
def get_ip_reputation(ip, access_token):
    url = f'https://graph.microsoft.com/v1.0/security/threatIntelligence/hosts/{ip}/reputation'
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        try:
            data = response.json()
            classification = data.get('classification', 'Unknown')
            return classification
        except json.JSONDecodeError:
            return "Failed to parse JSON response"
    else:
        return f"Failed with status code {response.status_code}"

# Replace with the path to your CSV file
file_path = 'YOUR_FLOW_TRAFFIC_CSV_FILE.csv'

# Read the CSV file
df = pd.read_csv(file_path)

# Extract unique IP addresses
unique_ips = pd.concat([df['src_ip_addr'], df['dst_ip_addr']]).unique()

# Get access token
access_token = get_access_token(client_id, client_secret, tenant_id)

# Perform IP reputation checks
suspicious_or_malicious_ips = []
for ip in tqdm(unique_ips, desc="Checking IP Reputations", unit="IP"):
    reputation = get_ip_reputation(ip, access_token)
    if reputation in ["suspicious", "malicious"]:
        suspicious_or_malicious_ips.append((ip, reputation))

# Display the results
for ip, reputation in suspicious_or_malicious_ips:
    print(f"IP: {ip}, Reputation: {reputation}")