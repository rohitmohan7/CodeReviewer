import logging
import logging.handlers
import os
from github import Github
import requests
import re

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger_file_handler = logging.handlers.RotatingFileHandler(
    "status.log",
    maxBytes=1024 * 1024,
    backupCount=1,
    encoding="utf8",
)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger_file_handler.setFormatter(formatter)
logger.addHandler(logger_file_handler)

try:
    SECRET_TOKEN = os.environ["SECRET_TOKEN"]
except KeyError:
    SECRET_TOKEN = "Token not available!"
    #logger.info("Token not available!")
    #raise

try:
    PR_NUMBER = os.environ["PR_NUMBER"]
except KeyError:
    PR_NUMBER = "PR Number not available!"

try:
    BRANCH = os.environ["BRANCH"]
except KeyError:
    BRANCH = "BRANCH not available!"

try:
    REPO_NAME = os.environ["REPO_NAME"]
except KeyError:
    REPO_NAME = "BRANCH not available!"

if __name__ == "__main__":
    g = Github(SECRET_TOKEN)
    logger.info(f"Token value: {SECRET_TOKEN}")

    r = requests.get('https://weather.talkpython.fm/api/weather/?city=Berlin&country=DE')
    if r.status_code == 200:
        data = r.json()
        temperature = data["forecast"]["temp"]
        logger.info(f'Weather in Berlin: {temperature}')

    if str(PR_NUMBER) != "":
        logger.info(f"PR value: {PR_NUMBER}")
        logger.info(f"BRANCH value: {BRANCH}")
        logger.info(f"REPO value: {REPO_NAME}")
        repo = g.get_repo(REPO_NAME)
        pr = repo.get_pull(int(str(PR_NUMBER)))
        head_sha = pr.head.sha
        for file in pr.get_files():
            logger.info(f"REPO file name: {file.filename}")
            patch = file.patch
            path = file.filename
            contents = repo.get_contents(path, ref=head_sha)
            content = contents.decoded_content.decode()
            contents = repo.get_contents(path, ref=repo.get_branch("main").commit.sha)
            main_content = contents.decoded_content.decode()
            pattern = r"^\+[\s\S]*?(?=\n[^+]+|\Z)"
            x = re.findall(pattern, patch)
            logger.info(f"REPO added lines: {x}")

            #logger.info(f"REPO patch: {patch}")
            #logger.info(f"REPO content: {content}")
        
        #commits = pr.get_commits()
        #files = commits[commits.totalCount - 1].files
        #for file in files:
        #    logger.info(f"REPO file name: {file.filename}")
        #    logger.info(f"REPO patch: {file.patch}")
