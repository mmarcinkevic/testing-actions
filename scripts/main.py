import os
import json
import requests
from requests.auth import HTTPBasicAuth
import jwt
import time

# Environment variables setup
OKTA_DOMAIN = os.getenv('OKTA_DOMAIN')
CLIENT_ID = os.getenv('CLIENT_ID')
KID = os.getenv('KID')
JIRA_AUTH = os.getenv('JIRA_AUTH')
JIRA_AUTH_TOKEN = os.getenv('JIRA_AUTH_TOKEN')
PRIVATE_KEY = os.getenv('PRIVATE_KEY')

def create_jwt(client_id, private_key, kid):
    current_time = int(time.time())
    payload = {
        'iss': client_id,
        'sub': client_id,
        'aud': f'{OKTA_DOMAIN}/oauth2/v1/token',
        'iat': current_time,
        'exp': current_time + 3600,
    }
    headers = {'alg': 'RS256', 'kid': kid}
    return jwt.encode(payload, private_key, algorithm='RS256', headers=headers)

def get_access_token():
    jwt_token = create_jwt(CLIENT_ID, PRIVATE_KEY, KID)
    token_url = f"{OKTA_DOMAIN}/oauth2/v1/token"
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    payload = {
        'grant_type': 'client_credentials',
        'scope': 'okta.users.read okta.groups.manage',
        'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        'client_assertion': jwt_token
    }
    response = requests.post(token_url, headers=headers, data=payload)
    response.raise_for_status()
    return response.json().get('access_token')

def log_message(message, logged_messages):
    formatted_message = message
    if "[FAILURE]" in message:
        formatted_message = message.replace("[FAILURE]", "{color:red}[FAILURE]{color}")
    elif "[SUCCESS]" in message:
        formatted_message = message.replace("[SUCCESS]", "{color:green}[SUCCESS]{color}")
    elif "[INFO]" in message:
        formatted_message = message.replace("[INFO]", "{color:orange}[INFO]{color}")
    
    print(formatted_message)
    logged_messages.append(formatted_message)

def get_user_id_and_display_name_by_email(headers, email):
    users_url = f"{OKTA_DOMAIN}/api/v1/users?q={email}"
    response = requests.get(users_url, headers=headers)
    response.raise_for_status()
    users = response.json()
    for user in users:
        user_email = user['profile']['email'].lower()
        if user_email == email.lower():
            user_display_name = f"{user['profile'].get('firstName', '')} {user['profile'].get('lastName', '')}"
            return user['id'], user_display_name
    return None, None

def get_group_id(headers, group_name):
    groups_url = f"{OKTA_DOMAIN}/api/v1/groups?q={group_name}"
    response = requests.get(groups_url, headers=headers)
    response.raise_for_status()
    if response.json():
        return response.json()[0]['id']
    return None

def is_user_in_group(headers, userID, group_id):
    url = f"{OKTA_DOMAIN}/api/v1/groups/{group_id}/users"
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    users = response.json() if response.status_code == 200 else []
    for user in users:
        if user['id'] == userID:
            return True
    return False

def add_user_to_group(headers, userID, group_id):
    url = f"{OKTA_DOMAIN}/api/v1/groups/{group_id}/users/{userID}"
    response = requests.put(url, headers=headers)
    return response.status_code == 204

def remove_user_from_group(headers, userID, group_id):
    url = f"{OKTA_DOMAIN}/api/v1/groups/{group_id}/users/{userID}"
    response = requests.delete(url, headers=headers)
    return response.status_code == 204

def send_jira_internal_note(issue_key, logged_messages):
    url = f"https://vinted.atlassian.net/rest/api/2/issue/{issue_key}/comment"
    auth = HTTPBasicAuth(JIRA_AUTH, JIRA_AUTH_TOKEN)
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    comments_to_jira = "\n".join(logged_messages)
    
    payload = json.dumps({
        "body": comments_to_jira,
        "properties": [
            {
              "key": "sd.public.comment",
              "value": {
                 "internal": "true"
              }
            }
          ]
    })

    response = requests.post(url, data=payload, headers=headers, auth=auth)
    if response.status_code != 201:
        print(f"Failed to send comment to Jira: {response.status_code} {response.text}")

def main():
    # Parse input data
    input_data = json.loads(os.getenv('INPUT_DATA'))
    access_token = get_access_token()
    headers = {'Authorization': f'Bearer {access_token}'}

    requestedOktaGroups = input_data.get("requestedOktaGroups", "")
    emailAddressReporter = input_data.get("emailAddressReporter", "")
    emailAddressOther = input_data.get("emailAddressOther", "")
    accessFor = input_data.get("accessFor", "")
    issue_key = input_data.get("issueKey", "")
    a_messages = input_data.get("asset_messages", "")
    accesstype = input_data.get("accesstype", "")
    requestedCustomGroups = input_data.get("requestedCustomGroups", "")

    if accessFor == "For me only":
        emailAddresses = emailAddressReporter.split(', ')
    elif accessFor == "Other user(s)":
        emailAddresses = emailAddressOther.split(', ')
    else:
        emailAddresses = []

    combined_groups = requestedOktaGroups + (', ' if requestedOktaGroups and requestedCustomGroups else '') + requestedCustomGroups
    groups = combined_groups.split(', ')
    
    logged_messages = []

    if accesstype == "Assign access":
        log_message(f"Action: Access request (Assign access)\n\nAction Log:", logged_messages)
        for email in emailAddresses:
            userID, _ = get_user_id_and_display_name_by_email(headers, email.strip())
            if userID:
                for group in groups:
                    group_id = get_group_id(headers, group.strip())
                    if group_id:
                        if is_user_in_group(headers, userID, group_id):
                            log_message(f"[FAILURE] User *{email}* is already in *{group}* group.", logged_messages)
                        elif add_user_to_group(headers, userID, group_id):
                            log_message(f"[SUCCESS] User *{email}* added to *{group}* group successfully.", logged_messages)
                        else:
                            log_message(f"[FAILURE] User *{email}* was not added to *{group}* group.", logged_messages)
                    else:
                        log_message(f"[FAILURE] Failed to find *{group}* group.", logged_messages)
            else:
                log_message(f"[FAILURE] No user found with email: *{email}*", logged_messages)
    
    elif accesstype == "Remove access":
        log_message(f"Action: Access request (Remove access)\n\nAction Log:", logged_messages)
        for email in emailAddresses:
            userID, _ = get_user_id_and_display_name_by_email(headers, email.strip())
            if userID:
                for group in groups:
                    group_id = get_group_id(headers, group.strip())
                    if group_id:
                        if not is_user_in_group(headers, userID, group_id):
                            log_message(f"[FAILURE] User *{email}* is not in *{group}* group.", logged_messages)
                        elif remove_user_from_group(headers, userID, group_id):
                            log_message(f"[SUCCESS] User *{email}* removed from *{group}* group successfully.", logged_messages)
                        else:
                            log_message(f"[FAILURE] User *{email}* was not removed from *{group}* group.", logged_messages)
                    else:
                        log_message(f"[FAILURE] Failed to find *{group}* group.", logged_messages)
            else:
                log_message(f"[FAILURE] No user found with email: *{email}*", logged_messages)

    if a_messages:
        asset_messages_list = a_messages.split(',')
        for message in asset_messages_list:
            info_message = f"[INFO] {message.strip()}"
            log_message(info_message, logged_messages)

    send_jira_internal_note(issue_key, logged_messages)
    print("Script completed successfully.")

if __name__ == "__main__":
    main()
