import os
import pickle
import pandas as pd
import joblib
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
import time
from email import message_from_bytes
import textwrap
from email_alert import show_alert, extract_email_content


# If modifying these SCOPES, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/gmail.modify']

def authenticate_gmail():
    """Authenticate with Google and get the service."""
    creds = None
    if os.path.exists('token.json'):
        with open('token.json', 'rb') as token:
            creds = pickle.load(token)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)

        with open('token.json', 'wb') as token:
            pickle.dump(creds, token)

    service = build('gmail', 'v1', credentials=creds)
    return service

def list_messages(service, max_results=10, query="is:unread"):
    """List unread message IDs in the authenticated Gmail account."""
    try:
        results = service.users().messages().list(userId='me', labelIds=['INBOX'], q=query, maxResults=max_results).execute()
        messages = results.get('messages', [])
        return messages
    except Exception as error:
        print(f'An error occurred: {error}')
        return []

def clean_domain(value):
    """Clean domains and paths to remove unwanted characters like <, >, or trailing characters."""
    if value.startswith("<") and value.endswith(">"):
        value = value[1:-1]
    if value.endswith(">"):
        value = value[:-1]
    return value.strip()

def calculate_rule_based_prediction(row):
    """Calculate the rule-based prediction."""
    if row['DMARC'] == 'Pass':
        return 0
    elif row['DMARC'] == 'Fail':
        return 1
    elif row['Return-Path'] == '':
        return 1
    elif row['DKIM'] == 'Pass' and row['DKIM Domain'] == row['From Domain']:
        return 0
    elif not row['DKIM Signature']:
        return 1
    elif row['SPF'] == 'Fail':
        return 1
    elif row['SPF'] == 'Pass' and row['DKIM'] == 'Pass':
        return 0
    return 1

def extract_headers_for_model(msg):
    """Extract and preprocess headers to match model training format."""
    headers = {header['name'].lower(): header['value'] for header in msg['payload']['headers']}

    # Detect DKIM-Signature presence and validate format
    dkim_signature_value = headers.get('dkim-signature', '')
    has_dkim_signature = (
        'v=1;' in dkim_signature_value.lower() and
        'a=rsa-sha256;' in dkim_signature_value.lower()
    )

    # Parse the raw email content for additional validation if available
    raw_email = msg.get('raw')
    if raw_email:
        email_message = message_from_bytes(raw_email.encode('ASCII'))
        dkim_signature_present = email_message['DKIM-Signature'] is not None
        # Revalidate DKIM Signature
        has_dkim_signature = has_dkim_signature or dkim_signature_present

    # Map extracted headers to the required feature names
    data = {
        'DKIM': 'Pass' if 'dkim=pass' in headers.get('authentication-results', '').lower() else 'Fail',
        'DMARC': 'Pass' if 'dmarc=pass' in headers.get('authentication-results', '').lower() else 'Fail',
        'SPF': 'Pass' if 'spf=pass' in headers.get('authentication-results', '').lower() else 'Fail',
        'Return-Path': clean_domain(headers.get('return-path', '')),
        'From Domain': clean_domain(headers.get('from', '').split('@')[-1]) if '@' in headers.get('from', '') else '',
        'DKIM Domain': clean_domain(dkim_signature_value.split('d=')[-1].split(';')[0]) if 'd=' in dkim_signature_value else '',
        'DKIM Signature': has_dkim_signature
    }

    # Convert data to DataFrame for preprocessing
    df = pd.DataFrame([data])

    # Calculate Rule-Based Prediction
    df['Rule-Based Prediction'] = df.apply(calculate_rule_based_prediction, axis=1)

    # Ensure the DataFrame matches the model training format
    df = df[['Rule-Based Prediction', 'DKIM', 'DMARC', 'SPF', 'Return-Path', 'From Domain', 'DKIM Domain', 'DKIM Signature']]

    print("\nProcessed Data for Model:")
    print(df)
    return df

def load_model():
    """Load the trained model."""
    model = joblib.load('email_spoofing_detection_model.joblib')
    return model

def predict_spoofed_status(processed_data, model,email_details,service):
    """Predict if the email is spoofed or legitimate."""
    # Ensure categorical features are encoded as in training
    categorical_columns = ['DKIM', 'DMARC', 'SPF', 'Return-Path', 'From Domain', 'DKIM Domain', 'DKIM Signature']
    processed_data[categorical_columns] = processed_data[categorical_columns].apply(lambda col: col.astype('category').cat.codes)

    # Predict using the model
    prediction = model.predict(processed_data)
    # print("\nPrediction:", "Spoofed" if prediction[0] == 1 else "Legitimate")
    if prediction[0] == 1:
        print("\nPrediction: Spoofed")
        show_alert(email_details,service)
    else:
        print("\nPrediction: Legitimate")
    return prediction
    # return prediction

def print_message_headers(msg):
    """Print all headers of a single message in a table-like format."""
    headers = msg['payload']['headers']
    if headers:
        # Define the box width for the table
        box_width = 90  # Adjust the width as needed
        print("+" + "-" * (box_width - 2) + "+")
        print(f"| {'Headers for message ID: ' + msg['id']:<80} |")
        print("+" + "-" * (box_width - 2) + "+")

        # Header Name and Value column widths
        header_col_width = 30
        value_col_width = box_width - header_col_width - 4  # Subtract for borders and spacing

        # Loop through all headers and print them
        for header in headers:
            name = header['name']
            value = header['value']

            # Format the header name and value to fit within the table structure
            header_name = f"{name}:"
            header_value = value

            # Check if the header name fits within the width
            if len(header_name) > header_col_width:
                header_name = header_name[:header_col_width]  # Truncate if necessary

            # Wrap the header value to fit within the value column width
            wrapped_value = textwrap.fill(header_value, width=value_col_width)
            wrapped_value_lines = wrapped_value.split('\n')

            # Print the first line of the wrapped value
            print(f"| {header_name:<{header_col_width}} | {wrapped_value_lines[0]:<{value_col_width}} |")
            
            # For any subsequent wrapped lines, indent them properly
            for line in wrapped_value_lines[1:]:
                print(f"| {' ' * (header_col_width + 2)} | {line:<{value_col_width}} |")

            # Print a separator line below the current header for better visual distinction
            print(f"|{'-' * (box_width - 2)}|")

        # End the table with a closing line
        print("+" + "-" * (box_width - 2) + "+")
    else:
        print("No headers found for this message.")
        print("=" * 90)  # Separator for no headers case

def main():
    """Main function to fetch initial unread emails and wait for new ones."""
    service = authenticate_gmail()
    model = load_model()
    print("Fetching and processing the first 10 unread emails...")

    # Fetch and process the first 10 unread emails
    messages = list_messages(service, max_results=10)
    last_message_id = None  # Track the last processed message ID

    for message in messages:
        msg = service.users().messages().get(userId='me', id=message['id']).execute()
        print_message_headers(msg)
        email_details = extract_email_content(msg)

        processed_data = extract_headers_for_model(msg)
        print("\nProcessed Data:")
        print(processed_data)
        predict_spoofed_status(processed_data, model,email_details,service)
        last_message_id = message['id']  # Update the last processed message ID

    # Continuously check for new unread emails
    print("\nWaiting for new unread emails...")
    while True:
        new_messages = list_messages(service, max_results=1, query="is:unread")
        if new_messages:
            for message in new_messages:
                if message['id'] != last_message_id:  # Process only if the message is new
                    msg = service.users().messages().get(userId='me', id=message['id']).execute()
                    email_details = extract_email_content(msg)
                    print_message_headers(msg)
                    processed_data = extract_headers_for_model(msg)
                    print("\nProcessed Data:")
                    print(processed_data)
                    predict_spoofed_status(processed_data, model,email_details,service)
                    last_message_id = message['id']  # Update the last processed message ID
                    break  # Exit after processing one new email
        time.sleep(5)  # Wait before checking again to avoid excessive polling

if __name__ == '__main__':
    main()
