# Define a list of keywords that indicate suspicious activity
suspicious_keywords = ["error", "alert", "intrusion", "unauthorized", "malware"]

# Specify the path to the log file you want to analyze
log_file_path = r"C:\Users\TALHA\Desktop\Projects\Security\logs.evtx"

# Initialize a list to store suspicious log entries
suspicious_entries = []

# Open and read the log file with the 'utf-16-le' encoding
with open(log_file_path, "rb") as log_file:
    for line in log_file:
        try:
            # Decode each line as 'utf-16-le' and ignore any decoding errors
            decoded_line = line.decode("utf-16-le", errors="ignore")
            # Check if any of the suspicious keywords are present in the log entry
            if any(keyword in decoded_line.lower() for keyword in suspicious_keywords):
                suspicious_entries.append(decoded_line)
        except UnicodeDecodeError:
            # Handle decoding errors gracefully, ignoring problematic lines
            pass

# Print suspicious log entries
if suspicious_entries:
    print("Suspicious log entries found:")
    for entry in suspicious_entries:
        print(entry.strip())
else:
    print("No suspicious log entries found.")
