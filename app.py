import os
import time
import docker
from datetime import datetime, timedelta, timezone
import logging
import re
from dateutil import parser
from elasticsearch import Elasticsearch

CONTAINER_NAME_FILTER = os.getenv("CONTAINER_NAME_FILTER", "kibana")
LOGS_TIME_OFFSET_MINUTES = int(os.getenv("LOGS_TIME_OFFSET_MINUTES", 20))
APP_ENVIRONMENT = os.getenv("APP_APP_ENVIRONMENTIRONMENT", "staging")
APP_NAME = os.getenv("APP_NAME", "kibana")
DEFAULT_INDEX_NAME = APP_NAME+"-"+"on-demand-logs"
INDEX_NAME = os.getenv("INDEX_NAME", DEFAULT_INDEX_NAME)
ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "https://localhost:9200")
ELASTICSEARCH_CA_CERT = os.getenv("ELASTICSEARCH_CA_CERT", "/Volumes/project/Docker-X/elastic-stack/synonyms-search/certs/ca/ca.crt")
ELASTICSEARCH_USER = os.getenv("ELASTICSEARCH_USER", "elastic")
ELASTICSEARCH_PASSWORD = os.getenv("ELASTICSEARCH_PASSWORD", "elastic123")
LAST_TIMESTAMP_FILE = os.getenv("LAST_TIMESTAMP_FILE", "last_timestamp.txt")

def connect_to_elasticsearch():
    try:
        if ELASTICSEARCH_USER and ELASTICSEARCH_PASSWORD and ELASTICSEARCH_CA_CERT:
            client = Elasticsearch(
                ELASTICSEARCH_URL,
                ca_certs=ELASTICSEARCH_CA_CERT,
                basic_auth=(ELASTICSEARCH_USER, ELASTICSEARCH_PASSWORD)
            )
        else:
            client = Elasticsearch(ELASTICSEARCH_URL)

        print(client.info())
        return client
    except Exception as e:
        print(f"Error connecting to Elasticsearch: {e}")
        return None

def index_logs(es, index_name, container_id, container_name, start_time, log_entries):
    try:
        # Index the log entries into Elasticsearch
        for log_entry in log_entries:
            log_entry["container_id"] = container_id
            log_entry["container_name"] = container_name
            log_entry["start_time"] = start_time.isoformat()
            es.index(index=index_name, body=log_entry)

        logging.info(f"Container ID: {container_id}, Name: {container_name}\nLogs since {start_time} indexed to Elasticsearch\n")
    except Exception as e:
        logging.error(f"Error indexing logs: {e}")


def retrieve_container_logs():
    try:
        es = connect_to_elasticsearch()

        if es:
            client = docker.from_env()
            current_time = datetime.now(timezone.utc)
            start_time = current_time - timedelta(minutes=LOGS_TIME_OFFSET_MINUTES)

            start_timestamp = int(start_time.timestamp())

            containers = client.containers.list(all=True)

            for container in containers:
                container_name = container.attrs['Name'].lstrip('/')

                if CONTAINER_NAME_FILTER.lower() in container_name.lower():
                    container_id = container.id

                    logs = client.containers.get(container_id).logs(since=start_timestamp).decode('utf-8')

                    log_entries = []
                    current_log_entry = {"env": APP_ENVIRONMENT, "app_name": APP_NAME, "message": ""}
                    timestamp_pattern = re.compile(r'\[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}[+-]\d{2}:\d{2}\]')

                    for line in logs.splitlines():
                        if timestamp_pattern.match(line):
                            # Start a new log entry
                            if current_log_entry["message"]:
                                log_entries.append(current_log_entry)
                            current_log_entry = {"env": APP_ENVIRONMENT, "app_name": APP_NAME, "message": line.strip()}
                        else:
                            # Continue the current log entry
                            current_log_entry["message"] += f"\n{line.strip()}"

                    # Check if the last log entry is not empty
                    if current_log_entry["message"]:
                        log_entries.append(current_log_entry)

                    # Index the log entries into Elasticsearch
                    index_logs(es, INDEX_NAME, container_id, container_name, start_time, log_entries)

    except docker.errors.APIError as e:
        logging.error(f"Error: {e}")

    finally:
        if client:
            client.close()
        if es:
            es.transport.close()

if __name__ == "__main__":
    # Call the function
    retrieve_container_logs()
