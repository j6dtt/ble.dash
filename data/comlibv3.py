import logging
import socket
import json
 
#----- Convert a list of messages to CEF messages ----
def data_to_cef(data, headers):
    import logging
    try:
        #----- Ignore special chars in data ----
        def escape_values(value):
            # Escapes special characters.
            special_chars = {
                '\\': '\\\\',
                '=': '\\=',
                '|': '\\|',
                ';': '\\;',
            }
            for char, escaped_char in special_chars.items():
                value = value.replace(char, escaped_char)
            return value
        #----- End -----
        #logging.info("Converting data to CEF messages...")
        cef_messages = []
        Numrec = len(data)
        Recnum = 0
        for d in data:
            Recnum += 1
            cef_headers = headers.format(Recnum, Numrec)
            cef_extension = ''.join(f"{key}={escape_values(str(value))}; " for key, value in d.items())
            cef_messages.append(''.join(cef_headers + cef_extension))
            #cef_messages.append(''.join(cef_headers + f'__recNum={Recnum}; __numRec={Numrec}; ' + cef_extension))
        return '\n'.join(cef_messages)
    except Exception as e:
        logging.error(f"Error converting data to CEF messages(commonlib): {str(e)}")
        exit()
#----- End CEF conversion -----
#
#----- Convert a json message object to a CEF message ----
def message_to_cef(data, headers):
    import logging
    try:
        def escape_values(value):
            special_chars = {
                '\\': '\\\\',
                '=': '\\=',
                '|': '\\|',
                ';': '\\;',
            }
            for char, escaped_char in special_chars.items():
                value = value.replace(char, escaped_char)
            return value

        cef_messages = []

        if isinstance(data, dict):
            data = [data]  # wrap single dict in list

        Numrec = len(data)
        for i, d in enumerate(data, start=1):
            cef_headers = headers.format(i, Numrec)
            cef_extension = ''.join(f"{key}={escape_values(str(value))}; " for key, value in d.items())
            cef_messages.append(cef_headers + cef_extension)

        return '\n'.join(cef_messages)

    except Exception as e:
        logging.error(f"Error converting data to CEF messages(commonlib): {str(e)}")
        exit()

#----- End CEF conversion -----
#
#----- Convert list of json strings to a CEF messages ----
def string_to_cef(data, headers):
    import logging    
    def cef_escape(s: str) -> str:
        """Escape for CEF (so JSON stays intact and parseable later)."""
        return (s.replace("\\", "\\\\")
                 .replace("=", "\\=")
                 .replace("|", "\\|")
                 .replace("\r", " ")
                 .replace("\n", " "))
             
    try:
        cef_messages = []
        Numrec = len(data)
        Recnum = 0
        for d in data:
            Recnum += 1
            cef_headers = headers.format(Recnum, Numrec)
            cef_extension = cef_escape(json.dumps(d, separators=(",", ":")))
            cef_messages.append(''.join(cef_headers + cef_extension))

        return '\n'.join(cef_messages)
    except Exception as e:
        logging.error(f"Error converting data to CEF messages(commonlib): {str(e)}")
        exit()
#----- End CEF conversion -----
#
#----- Convert CEF messages to json list strings ----
def parse_string_in_cef(message: str):
    def cef_unescape(s: str) -> str:
        """Reverse the escaping applied by cef_escape."""
        return (s.replace("\\|", "|")
                 .replace("\\=", "=")
                 .replace("\\\\", "\\"))
             
    data = []
    tag = None
    for line in message.splitlines():
        if not line.startswith("CEF:"):
            continue
        cef_parts = line.strip().split("|", 7)
        if len(cef_parts) < 8:
            continue
        
        tag = cef_parts[5]
        extended_field = cef_parts[7]
        
        json_str = cef_unescape(extended_field)
        
        try:
            obj = json.loads(json_str)
        except json.JSONDecodeError:
            continue

        data.append(obj)
    return data, tag
#----- End conversion -----
#
#----- Parse CEF messages produced by data_to_cef back into a list of dicts ----
def parse_data_cef(message: str):
    import re

    def unescape(s: str) -> str:
        placeholder = "\x00"
        return (s.replace("\\\\", placeholder)
                 .replace("\\=", "=")
                 .replace("\\|", "|")
                 .replace("\\;", ";")
                 .replace(placeholder, "\\"))

    data = []
    for line in message.splitlines():
        line = line.strip()
        if not line.startswith("CEF:"):
            continue
        parts = line.split("|", 7)
        if len(parts) < 8:
            continue
        record = {}
        for pair in re.split(r"(?<!\\);\s*", parts[7]):
            pair = pair.strip()
            if not pair:
                continue
            m = re.split(r"(?<!\\)=", pair, maxsplit=1)
            if len(m) != 2:
                continue
            record[m[0].strip()] = unescape(m[1].strip())
        if record:
            data.append(record)
    return data
#----- End conversion -----
#
#----- Save dict list to json file -----
def save_to_json(data, path):
    with open(path, "w", encoding="utf-8") as json_file:
        json.dump(data, json_file, ensure_ascii=False, indent=4)
#----- End save json -----
#
#----- Send data in whole to remote server over tcp ----
def send_data_over_tcp(data, remote_host, remote_port):
    try:
        # Create a TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 5 * 1024 * 1024)
        snd_buffer_size = sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
        logging.info(f"Send buffer size: {snd_buffer_size}")
        # Connect to the server
        sock.connect((remote_host, remote_port))
        
        # Ensure the data ends with '\n'
        if not data.endswith('\n'):
            data += '\n'
        
        # Send the entire data
        sock.sendall(data.encode())
      
        # Close the socket
        sock.close()
        #logging.info(f"Data sent successfully: {len(data)}")
    except Exception as e:
        logging.error(f"An error occurred sending data to {remote_host}:{remote_port}/tcp(commonlib): {e}")
        exit()
#----- End Send data to remote server over tcp ----
#
#----- Send data in single line to remote server over udp by event ----
def send_events_over_udp(data, remote_host, remote_port):
     try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Ensure the data ends with '\n'. Added 07/22/2025
        if not data.endswith('\n'):
            data += '\n'
        
        for line in data.splitlines():
            #line += '\n'   #Removed 07/22/2025
            sock.sendto(line.encode(), (remote_host, remote_port))
            #logging.info(line)
        sock.close()
     except socket.timeout:
       logging.error("Socket timeout occurred while sending data.")
     except Exception as e:
       logging.error(f"An error occurred while sending data: {e}")
#----- End Send data to remote server over udp ----
#
#----- Send data in chunk to remote server over udp by chunk ----
def send_data_over_udp(data, remote_host, remote_port):
    chunk_count = 0
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 16384)
        snd_buffer_size = sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF) #

        chunk_size =  3584 # 3.5kb
        
        chunks = []
        while len(data) > chunk_size:
            # Find the last newline character within the chunk size limit
            index = data.rfind('\n', 0, chunk_size)
            if index == -1:
                # If no newline is found, take the whole chunk_size
                index = chunk_size
            else:
                # Include the newline character in the chunk
                index += 1
            chunks.append(data[:index])
            data = data[index:].lstrip()  # Remove leading whitespace for the next chunk
        
        if data:
            chunks.append(data)

        for chunk in chunks:
            chunk_count += 1
            # Ensure each chunk except possibly the last ends with '\n'
            if not chunk.endswith('\n'):
                chunk += '\n'
            sock.sendto(chunk.encode(), (remote_host, remote_port))
            #logging.info(chunk)
        sock.close()
        #logging.info(f'Chunks sent: {chunk_count}')
        #logging.info(f"Send buffer size: {snd_buffer_size}") #

#        for line in data.splitlines():
#            message_count += 1
#            #line += '\n' #Use this when receiving NiFi(SIPR) 'Batch size' set to 1
#            sock.sendto(line.encode(), (host, port))
#
#            logging.info(f"{message_count}. {line}")
#        sock.close()
#        logging.info(f'Messages sent: {message_count}')

    except socket.timeout:
        logging.error("Socket timeout occurred while sending data.")
        exit()
    except Exception as e:
        logging.error(f"An error occurred while sending data to {remote_host}:{remote_port}/udp(commonlib): {e}")
        exit()
#----- End Send data to remote server over udp ----