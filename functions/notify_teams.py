import json
import logging
import os
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from typing import Any, Dict

HOOK_URL = os.environ['TEAMS_WEBHOOK_URL']

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def is_cloudwatch_alarm(message: str) -> bool:
    try:
        message_json = json.loads(message)
        return 'AlarmName' in message_json
    except json.JSONDecodeError:
        return False


def parse_cloudtrail_event(detail: Dict[str, Any]) -> Dict[str, str]:
    logger.info("CloudTrail detail: %s", json.dumps(detail))

    alarm_name = detail.get('eventName', 'UnknownEvent')
    reason = detail.get('errorMessage', 'No error message provided')

    title = f"Alert - {reason.split(':')[6].split(' ')[0]} - Issue: {alarm_name}" if ':' in reason else f"Alert - Issue: {alarm_name}"

    return {
        "colour": "Attention",
        "title": title,
        "text": json.dumps({
            "Subject": alarm_name,
            "Type": detail.get('eventType', 'Unknown'),
            "MessageId": detail.get('eventID', 'Unknown'),
            "Message": reason,
            "Timestamp": detail.get('eventTime', 'Unknown')
        }, indent=2)
    }


def build_adaptive_card(data: Dict[str, str]) -> Dict[str, Any]:
    return {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.5",
                    "body": [
                        {
                            "type": "TextBlock",
                            "text": data["title"],
                            "weight": "Bolder",
                            "size": "Medium",
                            "color": data.get("colour", "Default")
                        },
                        {
                            "type": "TextBlock",
                            "text": data["text"],
                            "wrap": True
                        }
                    ]
                }
            }
        ]
    }


def lambda_handler(event, context):
    logger.info("Event: %s", json.dumps(event))
    sns_record = event['Records'][0]['Sns']
    message = sns_record['Message']
    message_json = json.loads(message)

    data = {}

    if 'AlarmName' in message_json and is_cloudwatch_alarm(message):
        alarm_name = message_json['AlarmName']
        old_state = message_json['OldStateValue']
        new_state = message_json['NewStateValue']
        reason = message_json['NewStateReason']

        logger.info("CloudWatch Alarm: %s", json.dumps(message_json))

        base_data = {
            "colour": "Good" if new_state.lower() != 'alarm' else "Attention",
            "title": f"{'Resolved' if new_state.lower() != 'alarm' else 'Red Alert'} - {alarm_name}",
            "text": f"**{alarm_name}** changed from **{old_state}** to **{new_state}**\n\nReason: {reason}"
        }

        overrides = {
            ('ALARM', 'my-alarm-name'): {
                "colour": "Attention",
                "title": "Red Alert - A bad thing happened.",
                "text": "These are the specific details of the bad thing."
            },
            ('OK', 'my-alarm-name'): {
                "colour": "Good",
                "title": "The bad thing stopped happening",
                "text": "These are the specific details of how we know the bad thing stopped happening"
            }
        }

        data = overrides.get((new_state, alarm_name), base_data)

    elif message_json.get('detail-type') == 'AWS Service Event via CloudTrail':
        logger.info("Parsing CloudTrail event")
        data = parse_cloudtrail_event(message_json['detail'])

    else:
        logger.info("Fallback SNS message")
        data = {
            "colour": "Warning",
            "title": f"Alert - {sns_record.get('Subject', 'No Subject')}",
            "text": json.dumps({
                "Subject": sns_record.get('Subject'),
                "Type": sns_record.get('Type'),
                "MessageId": sns_record.get('MessageId'),
                "TopicArn": sns_record.get('TopicArn'),
                "Message": sns_record.get('Message'),
                "Timestamp": sns_record.get('Timestamp')
            }, indent=2)
        }

    card_payload = build_adaptive_card(data)

    try:
        req = Request(
            HOOK_URL,
            data=json.dumps(card_payload).encode('utf-8'),
            headers={'Content-Type': 'application/json'}
        )
        with urlopen(req) as response:
            response.read()
        logger.info("Message posted successfully.")
    except HTTPError as e:
        logger.error("Request failed: %d %s", e.code, e.reason)
    except URLError as e:
        logger.error("Server connection failed: %s", e.reason)
