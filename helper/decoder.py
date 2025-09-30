import re
import codecs
import urllib.parse
import base64
import pandas as pd
from helper.bot import is_valid_bot
from concurrent.futures import ThreadPoolExecutor, as_completed

# Variables
log_pattern = re.compile(
    r'(?P<ip>\S+) - - \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+)\s+(?P<url>.+?)\s+(?P<protocol>[^"]+)" '
    r'(?P<status>\d+) (?P<size>\d+) '
    r'"(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)" "(?P<extra>[^"]*)"'
)


STATIC_EXTENSIONS = re.compile(r'\.(css|js|jpg|jpeg|png|gif|ico|svg|woff|woff2)$', re.IGNORECASE)

# Functions
def esc_nl(text):
    """
    Escape newline and carriage return characters in a string.

    Replaces newline (\n) and carriage return (\r) characters with their
    escaped versions (\\n and \\r respectively), and strips leading/trailing whitespace.

    Args:
        text (str): The input string to sanitize.

    Returns:
        str: The cleaned string with escaped newlines.
    """
    return text.replace('\n', '\\n').replace('\r', '\\r').strip()


def dec_url(text):
    """
    Decode a URL-encoded string up to two iterations.

    Useful when URLs are encoded multiple times. Attempts decoding twice to
    retrieve the most human-readable form.

    Args:
        text (str): The URL-encoded string.

    Returns:
        str: The decoded string.
    """
    try:
        first = urllib.parse.unquote(text)
        if first == text:
            return text

        second = urllib.parse.unquote(first)
        if second == first:
            return first

        return second
    except Exception:
        return text


def dec_esc(text):
    """
    Decode escaped character sequences such as \\xNN and \\uNNNN.

    This function converts common escape sequences found in logs or obfuscated payloads
    into readable Unicode characters.

    Args:
        text (str): The string potentially containing escape sequences.

    Returns:
        str: The decoded string with escape sequences resolved.
    """
    try:
        if '\\x' in text or '\\u' in text:
            decoded = codecs.escape_decode(text.encode())[0].decode('utf-8', errors='replace')
            return decoded
        return text
    except Exception:
        return text


def dec_base64(text):
    """
    Detect and decode a Base64-encoded segment in the final URL path.

    If the last part of the URL path resembles a Base64-encoded string, this function
    decodes it and appends the decoded result as an annotation.

    Args:
        text (str): A URL string to inspect.

    Returns:
        str: The original text with an appended decoded Base64 value, if applicable.
    """
    try:
        last_part = text.rsplit("/", 1)[-1]
        
        # Heuristic: reasonably long, valid base64 characters
        if re.fullmatch(r'[A-Za-z0-9+/=]{8,}', last_part):
            decoded = base64.b64decode(last_part, validate=False).decode('utf-8', errors='ignore')
            annotated = f"{text}(base64:{decoded})"
            return annotated

        return text
    except Exception:
        return text

    
def dec_combined(text):
    """
    Apply a sequence of decoding techniques to a string:
    1. URL decoding (up to two iterations)
    2. Escape sequence decoding (e.g., \\xNN, \\uNNNN)
    3. Base64 decoding on the last URL path segment

    Args:
        text (str): The input string to decode.

    Returns:
        str: Fully decoded string with all heuristics applied.
    """
    text = dec_url(text)
    text = dec_esc(text)
    text = dec_base64(text)
    return text


def parse_dec_line(line):
    """
    Parse and decode a single NGINX access log line.

    Extracts components using regex and applies decoding functions to key fields:
    - Decodes URL and Referrer using multi-step decoding
    - Escapes newlines in all fields

    Args:
        line (str): A raw line from an NGINX access log.

    Returns:
        tuple:
            - str: The reconstructed, cleaned log line.
            - dict: A dictionary of individual decoded fields, or (None, None) if the line is invalid.
    """
    match = log_pattern.match(line)
    if not match:
        return None, None  # Unparsable log line

    fields = match.groupdict()

    # Decode URL field (multi-step decoding)
    fields['url'] = dec_combined(fields['url'])

    # Decode referrer field (only take the decoded text, not flags)
    fields['referrer'] = dec_combined(fields['referrer'])

    # Apply newline escaping cleanup
    for key in fields:
        fields[key] = esc_nl(fields[key])

    decoded = (
        f'{fields["ip"]} - - [{fields["time"]}] '
        f'"{fields["method"]} {fields["url"]} {fields["protocol"]}" '
        f'{fields["status"]} {fields["size"]} '
        f'"{fields["referrer"]}" "{fields["user_agent"]}" "{fields["extra"]}"'
    )

    return decoded, fields


def parse_dec_file(in_path, out_path):
    """
    Decode and clean all entries in a log file and write the results to a new file.

    Skips unparsable lines and entries determined to be from valid bots.

    Args:
        in_path (str): Path to the input raw log file.
        out_path (str): Path where the decoded log will be written.
    """
    with open(in_path, 'r', encoding='utf-8', errors='replace') as in_file, \
        open(out_path, 'w', encoding='utf-8') as out_file:
        
        for line in in_file:
            decoded, fields = parse_dec_line(line)
            
            if not fields:
                continue  # Skip unparsed line  

            if is_valid_bot(fields['ip'], fields['user_agent']):
                continue  # Skip valid bot

            out_file.write(f"{decoded}\n")


def parse_dec_file_to_dataframe(in_path):
    """
    Versi optimasi yang memproses validasi bot secara paralel.
    """
    
    all_parsed_records = []
    bots_to_validate = set() 
    
    with open(in_path, 'r', encoding='utf-8', errors='replace') as in_file:
        for no, line in enumerate(in_file, 1):
            _, fields = parse_dec_line(line)
            if not fields:
                continue
            
            fields['no'] = no
            all_parsed_records.append(fields)
                   
            if 'bot' in fields['user_agent'].lower():
                bots_to_validate.add((fields['ip'], fields['user_agent']))
    
    
    verified_ips = set()
    unique_bots_to_validate = list(bots_to_validate)
        
    with ThreadPoolExecutor(max_workers=16) as executor:
        future_to_bot = {executor.submit(is_valid_bot, ip, ua): (ip, ua) for ip, ua in unique_bots_to_validate}
        
        for future in as_completed(future_to_bot):
            ip, ua = future_to_bot[future]
            try:
                is_valid = future.result()
                if is_valid:
                    verified_ips.add(ip)
            except Exception as exc:
                print(f'Validasi untuk IP {ip} menghasilkan error: {exc}')
    
    
    final_records = []
    for fields in all_parsed_records:
        if fields['ip'] not in verified_ips:
            final_records.append(fields)
            
    if not final_records:
        print("Peringatan: Tidak ada data yang tersisa setelah filtering. DataFrame akan kosong.")
        return pd.DataFrame()

    df = pd.DataFrame(final_records)
    df['time'] = pd.to_datetime(df['time'], format='%d/%b/%Y:%H:%M:%S %z', errors='coerce', utc=True)
    df['status'] = pd.to_numeric(df['status'], errors='coerce').fillna(0).astype(int)
    df['size'] = pd.to_numeric(df['size'], errors='coerce').fillna(0).astype(int)
    # Hapus baris yang gagal di-parse waktunya
    df.dropna(subset=['time'], inplace=True)
    
    return df