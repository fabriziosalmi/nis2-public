import requests
import json
import logging

logger = logging.getLogger(__name__)

def send_alert(webhook_url: str, target: str, critical_issues: list):
    """
    Send an alert to a webhook (e.g., Slack) if critical issues are found.
    """
    if not critical_issues:
        return

    payload = {
        "text": f"🚨 **NIS2 Alert**: Critical issues found on {target}",
        "attachments": [
            {
                "color": "#ff0000", 
                "text": "\n".join([f"- {issue}" for issue in critical_issues])
            }
        ]
    }
    
    # Slack-specific formatting adjustment if needed, but standard webhooks usually accept JSON
    # For generic webhooks, payload structure might vary, but Slack/Teams usually handle this or similar.
    
    try:
        response = requests.post(webhook_url, json=payload, timeout=5)
        if response.status_code != 200:
            logger.error(f"Failed to send alert. Status code: {response.status_code}, Response: {response.text}")
        else:
            logger.info(f"Alert sent for {target}")
    except Exception as e:
        logger.error(f"Failed to send alert: {e}")
