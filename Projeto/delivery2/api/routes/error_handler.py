import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Lidar com erros
def handle_error(message, code=500, additional_info=None):
    error_response = {
        "error": message,
        "code": code,
        "additional_info": additional_info,
    }
    print(f"ERROR: {message}, Additional Info: {additional_info}")
    return error_response, code
