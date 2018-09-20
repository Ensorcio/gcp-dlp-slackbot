from flask import Flask
from slackeventsapi import SlackEventAdapter
from slackclient import SlackClient
import google.cloud.dlp
import googleapiclient.discovery
from google.cloud import storage
import base64
import threading
import json
import os
import logging

# Read Slack Tokens from encrypted GCS file
def read_file(ciphertext_data):
    """Read an encrypted file and decrypt it using Google KMS."""
    project_id = os.environ["kms_project"]
    location_id = os.environ["kms_location"]
    key_ring_id = os.environ["kms_keyring"]
    crypto_key_id = os.environ["kms_cryptokey"]
    tokens = json.loads(ciphertext_data, encoding='utf-8')
    SLACK_SIGNING_SECRET = decrypt_contents(tokens["SLACK_SIGNING_SECRET"].encode('ascii'), project_id, location_id, key_ring_id, crypto_key_id)
    SLACK_BOT_TOKEN = decrypt_contents(tokens["SLACK_BOT_TOKEN"].encode('ascii'), project_id, location_id, key_ring_id, crypto_key_id)
    return SLACK_SIGNING_SECRET, SLACK_BOT_TOKEN

# Function to decrypt encrypted contents of the GCS file
def decrypt_contents(ciphertext_contents, project_id, location_id, key_ring_id, crypto_key_id):
    """Decrypts data from ciphertext_contents that was previously encrypted
    using the provided CryptoKey."""
    # Creates an API client for the KMS API.
    kms_client = googleapiclient.discovery.build('cloudkms', 'v1')

    # The resource name of the CryptoKey.
    name = 'projects/{}/locations/{}/keyRings/{}/cryptoKeys/{}'.format(project_id, location_id, key_ring_id, crypto_key_id)
    
    # Use the KMS API to decrypt the data.
    crypto_keys = kms_client.projects().locations().keyRings().cryptoKeys()
    request = crypto_keys.decrypt(
        name=name,
        body={'ciphertext': ciphertext_contents.decode('ascii')})
    response = request.execute()
    plaintext = base64.b64decode(response['plaintext'].encode('ascii'))
    return plaintext.decode('utf-8')

#DLP Inspection and Reporting Function
def dlp_inspect(message, custom_dictionaries=None, custom_regexes=None):
    """Inspect a message from posted to a Slack channel using Google DLP API.
    If data matches identifers, post a messsage in the Original channel and IR channel."""
    # Edit this with your Google Cloud Project ID.
    project = os.environ["GOOGLE_CLOUD_PROJECT"]

    # Instantiate a client.
    dlp = google.cloud.dlp.DlpServiceClient()
   
    # The text to inspect
    item = {'value': message["text"]}

    # The info types to search for in the content. Required.
    info_types = [{'name': 'US_SOCIAL_SECURITY_NUMBER'}, {'name': 'US_INDIVIDUAL_TAXPAYER_IDENTIFICATION_NUMBER'}, {'name': 'CANADA_SOCIAL_INSURANCE_NUMBER'}, {'name': 'CREDIT_CARD_NUMBER'} ]

    # Prepare custom_info_types by parsing the dictionary word lists and
    # regex patterns.
    if custom_dictionaries is None:
        custom_dictionaries = ['Test_Keyword']
    dictionaries = [{
        'info_type': {'name': 'CUSTOM_DICTIONARY_{}'.format(i)},
        'dictionary': {
            'word_list': {'words': custom_dict.split(',')}
        }
    } for i, custom_dict in enumerate(custom_dictionaries)]
    if custom_regexes is None:
        custom_regexes = []
    regexes = [{
        'info_type': {'name': 'CUSTOM_REGEX_{}'.format(i)},
        'regex': {'pattern': custom_regex}
    } for i, custom_regex in enumerate(custom_regexes)]
    custom_info_types = dictionaries + regexes

    # The minimum likelihood to constitute a match. Optional.
    min_likelihood = 'LIKELIHOOD_UNSPECIFIED'

    # The maximum number of findings to report (0 = server maximum). Optional.
    max_findings = 0

    # Whether to include the matching string in the results. Optional.
    include_quote = True

    # Construct the configuration dictionary. Keys which are None may
    # optionally be omitted entirely.
    inspect_config = {
        'info_types': info_types,
        'custom_info_types': custom_info_types,
        'min_likelihood': min_likelihood,
        'include_quote': include_quote,
        'limits': {'max_findings_per_request': max_findings},
    }

    # Convert the project id into a full resource id.
    parent = dlp.project_path(project)

    # Call the API.
    response = dlp.inspect_content(parent, inspect_config, item)

    # Send results to Slack Channels.
    if response.result.findings:
        for finding in response.result.findings:
            try:
                channel = message["channel"]
                # Translate the encoded channel name into it's actual name.
                channel_translated = CLIENT.api_call("channels.info", channel=channel)
                user = CLIENT.api_call("users.info", user=message["user"])
                #If you have an IR channel you want to alert in. Fill it in here. Otherwise, comment it out.
                ir_channel = os.environ["ir_channel"]
                # Send a message to notify the channel where the sensitive data was found.
                bot_message = "The following text in your message was found to have sensitive data: `{}`. Type: `{}`.".format(finding.quote, finding.info_type.name)
                # Send a message to notify an Incident Response channel that sensitive data was found. If no IR channel is being used, comment it out.
                ir_message = "<@{}> might have posted some sensitive data in #{}. You might want to check it out.".format(user["user"]["name"], channel_translated["channel"]["name"])
                # Post alert message in the channel where the data was found.
                CLIENT.api_call("chat.postMessage", channel=channel, text=bot_message)
                # Post the message in the IR Channel. If not using an IR channel, comment it out.
                CLIENT.api_call("chat.postMessage", channel=ir_channel, text=ir_message)
            except AttributeError:
                pass

# Function to process the Slack message
def handle_message(event_data):
    message = event_data["event"]
    if message.get("subtype") is None:
        dlp_inspect(message, custom_dictionaries=None, custom_regexes=None)

# This `app` represents your existing Flask app
app = Flask(__name__)

# Instantiate the Google Storage client and set the bucket
storage_client = storage.Client()
bucket = storage_client.get_bucket(os.environ["gcs_bucket"])

# Get the encrypted Slack token file from GCS and read it.
blob = bucket.get_blob('slack_tokens.enc')
cipher_file = blob.download_as_string()
SLACK_SIGNING_SECRET, SLACK_BOT_TOKEN = read_file(ciphertext_data=cipher_file)

# Our app's Slack Event Adapter for receiving actions via the Events API
# Use this is there is no encrypted file. SLACK_SIGNING_SECRET = os.environ["SLACK_SIGNING_SECRET"]
slack_events_adapter = SlackEventAdapter(SLACK_SIGNING_SECRET, "/slack/events", app)

# Create a SlackClient for your bot to use for Web API requests
# Use this is there is no encrypted file. SLACK_BOT_TOKEN = os.environ["SLACK_BOT_TOKEN"]
CLIENT = SlackClient(SLACK_BOT_TOKEN)

# Responder to message
@slack_events_adapter.on("message")
def message_worker(event_data):
    t = threading.Thread(target=handle_message, args=[event_data])
    t.start()
    return '', 200



if __name__ == '__main__':
    # This is used when running locally. Gunicorn is used to run the
    # application on Google App Engine. See entrypoint in app.yaml.
    app.run(host='127.0.0.1', port=8000, debug=True)