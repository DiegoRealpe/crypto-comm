"""ProjectLogging.py: Util file to set up logger."""
import logging

# Configure the logger
logger = logging.getLogger("crypto_app")
logger.setLevel(logging.INFO)

# Create a console handler
console_handler = logging.StreamHandler()
console_handler.setFormatter(
    logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"),
)

# Avoid adding duplicate handlers
if not logger.hasHandlers():
    logger.addHandler(console_handler)
