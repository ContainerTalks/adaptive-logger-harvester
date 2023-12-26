import os
import docker
from datetime import datetime, timedelta
import logging
import re
from elasticsearch import Elasticsearch

# Set environment variables or provide default values
CONTAINER_NAME_PATTERN = os.getenv("CONTAINER_NAME_PATTERN", "kibana")
TIME_SINCE_IN_MIN = int(os.getenv("TIME_SINCE_IN_MIN", 20))
ENV = os.getenv("ENV", "staging")
APP_NAME = os.getenv("APP_NAME", "kibana")
INDEX_NAME = os.getenv("INDEX_NAME", "on-demand-logs")
ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "https://localhost:9200")
ELASTICSEARCH_CA_CERT = os.getenv("ELASTICSEARCH_CA_CERT", "/path/to/your/ca.crt")
ELASTICSEARCH_USER = os.getenv("ELASTICSEARCH_USER", "elastic")
ELASTICSEARCH_PASSWORD = os.getenv("ELASTICSEARCH_PASSWORD", "elastic123")
LAST_TIMESTAMP_FILE = os.getenv("LAST_TIMESTAMP_FILE", "last_timestamp.txt")

def connect_to_elasticsearch():
    try:
        client = Elasticsearch(
            ELASTICSEARCH_URL,
            ca_certs=ELASTICSEARCH_CA_CERT,
            basic_auth=(ELASTICSEARCH_USER, ELASTICSEARCH_PASSWORD)
        )
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

def read_last_timestamp():
    try:
        with open(LAST_TIMESTAMP_FILE, "r") as file:
            return int(file.read())
    except (FileNotFoundError, ValueError):
        return None

def write_last_timestamp(timestamp):
    with open(LAST_TIMESTAMP_FILE, "w") as file:
        file.write(str(timestamp))

def retrieve_container_logs():
    try:
        # Connect to Elasticsearch
        es = connect_to_elasticsearch()
        
        if es:
            client = docker.from_env()

            current_time = datetime.now()
            start_time = current_time - timedelta(minutes=TIME_SINCE_IN_MIN)
            
            start_timestamp = int(start_time.timestamp())
            
            containers = client.containers.list(all=True)
            
            for container in containers:
                container_name = container.attrs['Name'].lstrip('/')
                
                if CONTAINER_NAME_PATTERN.lower() in container_name.lower():
                    container_id = container.id
                    logs = client.containers.get(container_id).logs(since=start_timestamp).decode('utf-8')
                    
                    # Combine multiline logs with the same timestamp into a single entry
                    log_entries = []
                    current_log_entry = {"env": ENV, "app_name": APP_NAME, "message": ""}
                    timestamp_pattern = re.compile(r'\[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}[+-]\d{2}:\d{2}\]')

                    for line in logs.splitlines():
                        if timestamp_pattern.match(line):
                            # Start a new log entry
                            if current_log_entry["message"]:
                                log_entries.append(current_log_entry)
                            current_log_entry = {"env": ENV, "app_name": APP_NAME, "message": line.strip()}
                        else:
                            # Continue the current log entry
                            current_log_entry["message"] += f"\n{line.strip()}"

                    # Index the log entries into Elasticsearch
                    print(INDEX_NAME)
                    print(log_entries)
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
