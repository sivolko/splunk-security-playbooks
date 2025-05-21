"""
AD/LDAP Account Locking Playbook
This playbook handles Active Directory/LDAP account locking incidents by:
1. Extracting user details
2. Analyzing authentication logs
3. Determining if the lock is due to legitimate user error or suspicious activity
4. Taking appropriate response actions

Type: Response
Author: Splunk Security Research Team
"""

import phantom.rules as phantom
import json
from datetime import datetime

def on_start(container):
    phantom.debug('on_start() called')
    
    # Get the event that triggered this playbook
    event = phantom.get_event()
    
    # Extract username and domain from the event
    username = phantom.get_param(container, "username")
    domain = phantom.get_param(container, "domain")
    
    if not username or not domain:
        phantom.error("Required parameters 'username' or 'domain' are missing")
        return
    
    # Add a note to document the incident
    phantom.add_note(container=container, 
                    note_type="general", 
                    title="Account Locking Investigation Started", 
                    content=f"Started investigation of locked account for user: {username}@{domain}")
    
    # Collect user account information from AD
    get_ad_user_info(container, username, domain)
    return

def get_ad_user_info(container, username, domain):
    """Query Active Directory for user account information"""
    phantom.debug(f'Getting user info for {username}@{domain}')
    
    # Set parameters for AD user info query
    parameters = [
        {
            "username": username,
            "domain": domain
        }
    ]
    
    phantom.act(action="get user attributes", 
               parameters=parameters, 
               assets=["active_directory"], 
               callback=query_authentication_logs, 
               name="get_ad_user_info")
    
def query_authentication_logs(action_result=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    """Query authentication logs for the user account"""
    phantom.debug('Querying authentication logs')
    
    # Get username from previous action results
    username = results[0].get("action_result", {}).get("data", [{}])[0].get("samaccountname")
    
    if not username:
        phantom.error("Could not retrieve username from AD query")
        return
    
    # Set timeframe for auth log query - last 24 hours
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    timeframe = "-24h"
    
    # Set parameters for auth log query
    parameters = [
        {
            "query": f"index=windows sourcetype=WinEventLog:Security EventCode=4740 OR EventCode=4625 user={username} | table _time, EventCode, user, src_ip, result",
            "display": "table",
            "start_time": timeframe,
            "end_time": current_time
        }
    ]
    
    phantom.act(action="run query", 
               parameters=parameters, 
               assets=["splunk"], 
               callback=analyze_auth_patterns, 
               name="query_auth_logs")

def analyze_auth_patterns(action_result=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    """Analyze authentication patterns to determine if lock is due to user error or suspicious activity"""
    phantom.debug('Analyzing authentication patterns')
    
    # Get auth log results
    auth_logs = results[0].get("action_result", {}).get("data", [])
    
    if not auth_logs:
        phantom.debug("No authentication logs found")
        determine_response_action(container=container, is_suspicious=False, reason="No authentication logs found")
        return
    
    # Count failed login attempts
    failed_attempts = [log for log in auth_logs if log.get("EventCode") == "4625"]
    failed_count = len(failed_attempts)
    
    # Analyze source IPs
    unique_ips = set([log.get("src_ip") for log in failed_attempts if log.get("src_ip")])
    
    # Determine if pattern is suspicious based on heuristics
    is_suspicious = False
    reason = "Account locked due to user error (multiple failed attempts from same location)"
    
    # If attempts from multiple IPs, mark as suspicious
    if len(unique_ips) > 2:
        is_suspicious = True
        reason = f"Account locked due to suspicious activity (attempts from {len(unique_ips)} different IPs)"
    
    # If excessive number of attempts, mark as suspicious
    if failed_count > 10:
        is_suspicious = True
        reason = f"Account locked due to suspicious activity (excessive failed attempts: {failed_count})"
    
    # Proceed to determine response action
    determine_response_action(container=container, is_suspicious=is_suspicious, reason=reason)
    return

def determine_response_action(action_result=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, is_suspicious=False, reason=""):
    """Determine appropriate response action based on analysis"""
    phantom.debug(f'Determining response action - Suspicious: {is_suspicious}')
    
    # Add note with analysis results
    phantom.add_note(container=container, 
                    note_type="general", 
                    title="Account Lock Analysis", 
                    content=reason)
    
    if is_suspicious:
        # For suspicious activity, maintain lock and alert SOC
        phantom.add_note(container=container, 
                        note_type="general", 
                        title="Response: Maintain Lock", 
                        content="Account will remain locked due to suspicious activity. Escalating to SOC team.")
        
        # Change severity of the event
        phantom.set_severity(container=container, severity="high")
        
        # Alert SOC team (could be email, ticket, etc.)
        alert_soc_team(container=container, reason=reason)
    else:
        # For user error, ask whether to unlock account
        prompt_to_unlock_account(container=container)
    
    return

def alert_soc_team(action_result=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, reason=""):
    """Alert SOC team about suspicious account locking incident"""
    phantom.debug('Alerting SOC team')
    
    # Get container information
    container_info = phantom.get_container_info(container)
    container_id = container_info.get('id', 'Unknown')
    
    # Create alert message
    alert_subject = f"ALERT: Suspicious Account Locking Incident (Case #{container_id})"
    alert_body = f"""
    A suspicious account locking incident has been detected and requires SOC investigation.
    
    Reason: {reason}
    Case ID: {container_id}
    Link: {phantom.get_base_url()}mission/{container_id}
    
    Please investigate this incident as soon as possible.
    """
    
    # Set parameters for email action
    parameters = [
        {
            "to": "soc@example.com",
            "subject": alert_subject,
            "body": alert_body
        }
    ]
    
    phantom.act(action="send email", 
               parameters=parameters, 
               assets=["smtp_server"], 
               callback=document_incident, 
               name="alert_soc_team")
    
    return

def prompt_to_unlock_account(action_result=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    """Prompt analyst whether to unlock the account"""
    phantom.debug('Prompting to unlock account')
    
    # Get username from previous results
    user_info = phantom.collect2(container=container, datapath=['get_ad_user_info:action_result.data.*.samaccountname'])
    username = user_info[0][0] if user_info and user_info[0][0] else "unknown"
    
    # Prompt message
    message = f"""
    User account {username} is locked due to failed login attempts but does not appear suspicious.
    
    Do you want to:
    1. Unlock the account
    2. Unlock and reset password
    3. Keep account locked
    """
    
    # Prompt options
    response_types = [
        {
            "prompt": "Unlock Account",
            "response": "unlock"
        },
        {
            "prompt": "Unlock and Reset Password",
            "response": "reset"
        },
        {
            "prompt": "Keep Locked",
            "response": "keep_locked"
        }
    ]
    
    phantom.prompt2(container=container, 
                   message=message, 
                   response_types=response_types, 
                   name="unlock_prompt", 
                   callback=process_unlock_decision)
    
    return

def process_unlock_decision(action_result=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    """Process the decision from the unlock prompt"""
    phantom.debug('Processing unlock decision')
    
    if not results or not results.get("response"):
        phantom.error("No response received from prompt")
        return
    
    # Get the response from the prompt
    response = results.get("response")
    
    # Get username and domain from previous results
    user_info = phantom.collect2(container=container, 
                               datapath=['get_ad_user_info:action_result.data.*.samaccountname', 
                                        'get_ad_user_info:action_result.data.*.domain'])
    
    username = user_info[0][0] if user_info and user_info[0][0] else "unknown"
    domain = user_info[0][1] if user_info and user_info[0][1] else "unknown"
    
    if response == "unlock":
        # Unlock the account
        unlock_account(container=container, username=username, domain=domain)
    elif response == "reset":
        # Reset password and unlock
        reset_password_and_unlock(container=container, username=username, domain=domain)
    else:
        # Keep locked, just document
        phantom.add_note(container=container, 
                        note_type="general", 
                        title="Response: Maintain Lock", 
                        content="Decided to keep account locked.")
        document_incident(container=container)
    
    return

def unlock_account(action_result=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, username="", domain=""):
    """Unlock the user account"""
    phantom.debug(f'Unlocking account for {username}@{domain}')
    
    parameters = [
        {
            "username": username,
            "domain": domain
        }
    ]
    
    phantom.act(action="unlock account", 
               parameters=parameters, 
               assets=["active_directory"], 
               callback=notify_user, 
               name="unlock_account")
    
    return

def reset_password_and_unlock(action_result=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, username="", domain=""):
    """Reset password and unlock account"""
    phantom.debug(f'Resetting password for {username}@{domain}')
    
    # Generate a secure random password
    import random
    import string
    new_password = ''.join(random.choice(string.ascii_letters + string.digits + "!@#$%^&*()") for _ in range(12))
    
    # Reset password
    parameters = [
        {
            "username": username,
            "domain": domain,
            "password": new_password
        }
    ]
    
    phantom.act(action="reset password", 
               parameters=parameters, 
               assets=["active_directory"], 
               callback=unlock_account_after_reset, 
               name="reset_password",
               container=container)
    
    # Store new password securely for notification
    phantom.save_run_data(key="new_password", value=new_password, auto_delete=True)
    
    return

def unlock_account_after_reset(action_result=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    """Unlock account after password reset"""
    phantom.debug('Unlocking account after password reset')
    
    # Get username and domain
    user_info = phantom.collect2(container=container, 
                               datapath=['get_ad_user_info:action_result.data.*.samaccountname', 
                                        'get_ad_user_info:action_result.data.*.domain'])
    
    username = user_info[0][0] if user_info and user_info[0][0] else "unknown"
    domain = user_info[0][1] if user_info and user_info[0][1] else "unknown"
    
    parameters = [
        {
            "username": username,
            "domain": domain
        }
    ]
    
    phantom.act(action="unlock account", 
               parameters=parameters, 
               assets=["active_directory"], 
               callback=notify_user_with_password, 
               name="unlock_after_reset")
    
    return

def notify_user(action_result=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    """Notify user that their account has been unlocked"""
    phantom.debug('Notifying user about account unlock')
    
    # Get user's email from AD info
    user_info = phantom.collect2(container=container, 
                               datapath=['get_ad_user_info:action_result.data.*.mail', 
                                        'get_ad_user_info:action_result.data.*.samaccountname'])
    
    user_email = user_info[0][0] if user_info and user_info[0][0] else None
    username = user_info[0][1] if user_info and user_info[0][1] else "user"
    
    if not user_email:
        phantom.error("Could not find user email for notification")
        document_incident(container=container)
        return
    
    # Prepare notification email
    parameters = [
        {
            "to": user_email,
            "subject": "Your account has been unlocked",
            "body": f"""
            Hello {username},
            
            Your account was locked due to multiple failed login attempts. It has now been unlocked.
            
            If you did not experience login problems, please contact IT Security immediately as your account may have been targeted.
            
            IT Security Team
            """
        }
    ]
    
    phantom.act(action="send email", 
               parameters=parameters, 
               assets=["smtp_server"], 
               callback=document_incident, 
               name="notify_user")
    
    return

def notify_user_with_password(action_result=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    """Notify user about account unlock and password reset"""
    phantom.debug('Notifying user about account unlock and password reset')
    
    # Get user's email and username
    user_info = phantom.collect2(container=container, 
                               datapath=['get_ad_user_info:action_result.data.*.mail', 
                                        'get_ad_user_info:action_result.data.*.samaccountname'])
    
    user_email = user_info[0][0] if user_info and user_info[0][0] else None
    username = user_info[0][1] if user_info and user_info[0][1] else "user"
    
    if not user_email:
        phantom.error("Could not find user email for notification")
        document_incident(container=container)
        return
    
    # Get the temporary password from saved data
    new_password = phantom.get_run_data(key="new_password")
    
    # Prepare notification email
    parameters = [
        {
            "to": user_email,
            "subject": "Your account has been unlocked - Password Reset",
            "body": f"""
            Hello {username},
            
            Your account was locked due to multiple failed login attempts. It has been unlocked and your password has been reset.
            
            Your temporary password is: {new_password}
            
            Please change this password immediately after logging in.
            
            If you did not experience login problems, please contact IT Security immediately as your account may have been targeted.
            
            IT Security Team
            """
        }
    ]
    
    phantom.act(action="send email", 
               parameters=parameters, 
               assets=["smtp_server"], 
               callback=document_incident, 
               name="notify_user_with_password")
    
    return

def document_incident(action_result=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    """Document incident resolution and close if appropriate"""
    phantom.debug('Documenting incident')
    
    # Get results from all previous actions
    all_results = phantom.collect_results()
    
    # Create summary of actions taken
    summary = "Account Locking Incident Resolution:\n\n"
    
    if phantom.get_action_results(action_name="unlock_account"):
        summary += "- Account was unlocked\n"
    
    if phantom.get_action_results(action_name="reset_password"):
        summary += "- Password was reset\n"
    
    if phantom.get_action_results(action_name="notify_user") or phantom.get_action_results(action_name="notify_user_with_password"):
        summary += "- User was notified\n"
    
    if phantom.get_action_results(action_name="alert_soc_team"):
        summary += "- SOC team was alerted due to suspicious activity\n"
        summary += "- Incident was escalated\n"
    
    # Add final documentation note
    phantom.add_note(container=container, 
                    note_type="general", 
                    title="Incident Resolution Summary", 
                    content=summary)
    
    # Close the incident if it was a simple user error that was resolved
    if not phantom.get_action_results(action_name="alert_soc_team"):
        phantom.set_status(container=container, status="closed")
    
    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    
    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.
    
    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)
    
    return
