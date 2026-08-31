import logging

def setup_logging(log_file, path):
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s |   %(levelname)-8s| %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[
            logging.FileHandler(f"{path}/{log_file}"),
            logging.StreamHandler()
        ]
    )

    return logging.getLogger(__name__)