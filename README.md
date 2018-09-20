# gcp-dlp-slackbot
Making a Slackbot using Google's DLP API to inspect messages. Deploy to Google App Engine.
## Overview
This is a Slackbot that is deployed to Google's App Engine. It receives messages via the Events API from Slack, sends the message to Google's DLP API to inspect for sensitive data, and reports any sensitive data found. Currently, it will post a message in the channel where the message was created to notify the user that it found sensitive data, and in an specified "Incident Response" channel to notify the IR team of the incident.
## Details
To be written...