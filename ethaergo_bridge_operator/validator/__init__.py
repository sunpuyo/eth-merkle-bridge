import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

file_formatter = logging.Formatter(
    "{'level': '%(levelname)s', 'time: '%(asctime)s', 'name': '%(funcName)s', "
    "'message':'%(message)s'"
)
stream_formatter = logging.Formatter("'%(message)s'")


file_handler = logging.FileHandler('validator.log')
file_handler.setFormatter(file_formatter)

stream_handler = logging.StreamHandler()
stream_handler.setFormatter(stream_formatter)

logger.addHandler(file_handler)
logger.addHandler(stream_handler)
