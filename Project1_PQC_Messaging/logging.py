import logging

logging.basicConfig(filename="pqc_messaging.log", level=logging.INFO)

def log_message(direction, message, encrypted=False):
    tag = "Encrypted" if encrypted else "Decrypted"
    logging.info(f"{direction} | {tag}: {message}")
