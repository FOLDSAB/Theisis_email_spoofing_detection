# from tkinter import Tk, messagebox
# from googleapiclient.discovery import build

# def show_alert(email_details, service):
#     """Show a message box alert for spoofed emails with options to move to trash or check later."""
#     root = Tk()
#     root.withdraw()  # Hide the main tkinter window

#     alert_message = (
#         f"ALERT: This email is detected as spoofed!\n\n"
#         f"From: {email_details.get('From', 'Unknown')}\n"
#         f"To: {email_details.get('To', 'Unknown')}\n"
#         f"Subject: {email_details.get('Subject', 'No Subject')}\n"
#         f"Message: {email_details.get('Body', 'No Content')}\n\n"
#         "What would you like to do?"
#     )

#     response = messagebox.askyesnocancel(
#         "Spoofed Email Detected", 
#         alert_message, 
#         default=messagebox.YES, 
#         icon="warning"
#     )
    
#     if response is None:
#         print("User chose to check it later.")
#     elif response:
#         print("Moving email to trash...")
#         move_to_trash(email_details, service)
#     else:
#         print("User will check the email later.")
    
#     root.destroy()

# def move_to_trash(email_details, service):
#     """Move the email to trash using Gmail API."""
#     try:
#         email_id = email_details.get('id')
#         if email_id:
#             service.users().messages().modify(
#                 userId='me',
#                 id=email_id,
#                 body={'removeLabelIds': ['INBOX'], 'addLabelIds': ['TRASH']}
#             ).execute()
#             print(f"Email from {email_details.get('From', 'Unknown')} moved to trash.")
#         else:
#             print("Email ID not found.")
#     except Exception as e:
#         print(f"An error occurred while moving email to trash: {e}")

# import base64

# def extract_email_content(msg):
#     """Extract basic details like From, To, Subject, and Body from the email."""
#     payload = msg.get('payload', {})
#     headers = {header['name']: header['value'] for header in payload.get('headers', [])}

#     # Decode the body content
#     body_data = payload.get('body', {}).get('data', '')
#     if body_data:
#         try:
#             body = base64.urlsafe_b64decode(body_data).decode('utf-8')
#         except Exception as e:
#             body = f"[Error decoding body: {e}]"
#     else:
#         body = "No Content"

#     return {
#         'From': headers.get('From', 'Unknown'),
#         'To': headers.get('To', 'Unknown'),
#         'Subject': headers.get('Subject', 'No Subject'),
#         'Body': body,
#         'id': msg.get('id', '')
#     }







from tkinter import Tk, Toplevel, Button, Label
from googleapiclient.discovery import build

def show_alert(email_details, service):
    """Show a message box alert for spoofed emails with custom buttons."""
    root = Tk()
    root.withdraw()  # Hide the main tkinter window

    alert_window = Toplevel()
    alert_window.title("⚠️ Spoofed Email Alert ⚠️")

    message = (
        f"⚠️ ALERT: This email is detected as SPOOFED! ⚠️\n\n"
        f"From: {email_details.get('From', 'Unknown')}\n"
        f"To: {email_details.get('To', 'Unknown')}\n"
        f"Subject: {email_details.get('Subject', 'No Subject')}\n"
        f"Message: {email_details.get('Body', 'No Content')}\n\n"
        "What would you like to do?"
    )

    label = Label(alert_window, text=message, justify="left", padx=20, pady=10, wraplength=500)
    label.pack()

    def move_to_trash_action():
        print("Moving email to trash...")
        move_to_trash(email_details, service)
        alert_window.destroy()
        root.quit()  # Ensure Tkinter exits properly

    def check_later_action():
        print("User chose to check it later.")
        alert_window.destroy()
        root.quit()  # Ensure Tkinter exits properly

    move_to_trash_button = Button(alert_window, text="Move to Trash", command=move_to_trash_action, padx=10, pady=5)
    move_to_trash_button.pack(side="left", padx=20, pady=10)

    check_later_button = Button(alert_window, text="Check it Later", command=check_later_action, padx=10, pady=5)
    check_later_button.pack(side="right", padx=20, pady=10)

    alert_window.mainloop()
    root.destroy()  # Ensures Tkinter fully exits

def move_to_trash(email_details, service):
    """Move the email to trash using Gmail API."""
    try:
        email_id = email_details.get('id')
        if email_id:
            service.users().messages().modify(
                userId='me',
                id=email_id,
                body={'removeLabelIds': ['INBOX'], 'addLabelIds': ['TRASH']}
            ).execute()
            print(f"✅ Email from {email_details.get('From', 'Unknown')} moved to trash successfully.")
        else:
            print("⚠️ Email ID not found.")
    except Exception as e:
        print(f"❌ An error occurred while moving email to trash: {e}")

import base64

def extract_email_content(msg):
    """Extract basic details like From, To, Subject, and Body from the email."""
    payload = msg.get('payload', {})
    headers = {header['name']: header['value'] for header in payload.get('headers', [])}

    # Decode the body content
    body_data = payload.get('body', {}).get('data', '')
    if body_data:
        try:
            body = base64.urlsafe_b64decode(body_data).decode('utf-8')
        except Exception as e:
            body = f"[Error decoding body: {e}]"
    else:
        body = "No Content"

    return {
        'From': headers.get('From', 'Unknown'),
        'To': headers.get('To', 'Unknown'),
        'Subject': headers.get('Subject', 'No Subject'),
        'Body': body,
        'id': msg.get('id', '')
    }
