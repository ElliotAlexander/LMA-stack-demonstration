import json
import os
import requests

import re
import textwrap
import time
import urllib3

from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv

# Disable unverified HTTPS request warnings, to avoid spamming stdout.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

domain = "elliotalexander.xyz"
apis = {
    "cadvisor": "cadvisor." + domain,
    "grafana": "grafana." + domain,
    "prometheus": "prometheus." + domain,
}

# Used to validate prometheus datasource settings.
prometheus_internal_url = 'http://prometheus:9090'

# Used to compare against a list of available metrics in Grafana.
metric_queries = ['container_cpu_load_average_10s', 'container_last_seen', 'prometheus_http_requests_total']

prefix_ok = "[OK] "
prefix_info = "[INFO] "
prefix_fail = "[FAIL] "

def main():
    print("\n--- Starting Tests ---\n")

    load_dotenv()

    grafana_username = "admin"
    if "GF_SECURITY_ADMIN_USER" in os.environ:
        grafana_username = os.environ["GF_SECURITY_ADMIN_USER"]
    
    grafana_password = "admin"
    if "GF_SECURITY_ADMIN_PASSWORD" in os.environ:
        grafana_password = os.environ["GF_SECURITY_ADMIN_PASSWORD"]

    try:
        check_cadvisor_api_version()
        check_prometheus_version()

        # Future checks may require an API key - generate one or load it from env.
        grafana_api_key = generate_grafana_api_keys(username=grafana_username, password=grafana_password)

        check_grafana_version(grafana_api_key)

        # Check prometheus datasource is connected properly. Return datasource ID for future queries.
        datasource_id = fetch_prometheus_datasource_from_grafana(grafana_api_key)

        # Check cAdvisor and prometheus data proxied from Grafana.
        check_proxied_cadvisor_version(grafana_api_key, datasource_id=datasource_id)
        check_proxied_container_data(grafana_api_key, datasource_id=datasource_id)
    except AssertionError as e:
        print("[FAIL] Failed to complete tests. Error: \n")
        print(e)
        pass
    except Exception as e:
        print("[FAIL] Unhandled failure in testing. Error: \n")
        print(e)


    print("\n--- done ---")

def make_api_get_request(api, path, api_key="", scheme="https://"):
    uri = scheme + apis.get(api) + path

    # If we're using self-signed certs, verify SSL/TLS needs to be disabled.
    if api_key:
        header = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }
        return requests.get(uri, verify=False, headers=header)
    else:
        return requests.get(uri, verify=False)

def generate_grafana_api_keys(username="admin", password="admin"):
    
    # load from environment if applicable - saves re-registering api keys in dev.
    if "GF_API_KEY" in os.environ:
        print(prefix_info + "Loaded Grafana API key from environment.")
        return os.environ["GF_API_KEY"]

    path = "/api/auth/keys"
    scheme = "https://"

    headers = {
        'Content-Type': 'application/json'
    }

    data = {
        "name": f"ci_key{int(time.time())}",
        "role": "Admin"
    }

    response = requests.post(scheme + apis.get("grafana") + path, 
        auth=HTTPBasicAuth(username, password),
        json=data,
        headers=headers,
        verify=False
    )

    data = json.loads(response.text)
    if "key" in data:
        print("Registered API key for Grafana")
        return data.get("key")
    else:
        print("Warning - failed to register API key for Grafana.")
        return "Test"

def check_cadvisor_api_version():
    # A status overview of cAdvisors data.
    path = "/api/v1.0/containers"
    response = make_api_get_request("cadvisor", path)
    content_type = response.headers.get('Content-Type')

    if (response.status_code != 200):
        raise AssertionError(textwrap.dedent(f"""\
            Incorrect status code from cAdvisor direct checks.
            Expected 200, got {response.status_code}.
        """))

    if "application/json" not in content_type:
        raise AssertionError(textwrap.dedent(f"""\
            Received incorrect content from cAdvisor API.
            Expected JSON, got {content_type}.
        """))
    else:
        print(prefix_ok + "Got cAdvisor instance.")

def check_prometheus_version():
    path = "/api/v1/status/buildinfo"

    # If we're using self-signed certs, verify SSL/TLS needs to be disabled.
    response = make_api_get_request("prometheus", path)
    content_type = response.headers.get('Content-Type')

    if (response.status_code != 200):
        raise AssertionError(textwrap.dedent(f"""\
            Incorrect status code from Prometheus direct check.
            Expected 200, got {response.status_code}.
        """))

    if "application/json" not in content_type:
        raise AssertionError(textwrap.dedent(f"""\
            Received incorrect content from Prometheus API.
            Expected JSON, got {content_type}.
        """))

    data = json.loads(response.text).get("data")
    if "version" not in data:
        raise AssertionError(textwrap.dedent(f"""\
            Expected to find Prometheus version number. 
            Got {data}
        """))
    else:
        print(prefix_ok + "Got Prometheus Version %s" % data.get("version"))

def check_grafana_version(grafana_api_key):
    # Load a general list of build information about Grafana.
    path = "/api/frontend/settings"

    response = make_api_get_request("grafana", path, api_key=grafana_api_key)
    content_type = response.headers.get('Content-Type')

    if (response.status_code != 200):
        raise AssertionError("""
            Incorrect status code from Grafana version check.\n
            Expected 200, got %d.\n
        """ % (response.status_code))

    if "application/json" not in content_type:
        raise AssertionError("""
            Received incorrect content from Grafana API.\n
            Expected JSON, got %s.\n
        """ % (content_type)) 

    # Verify we've got a prometheus version number in Grafana.
    data = json.loads(response.text)
    if "buildInfo" not in data:
        if "version" not in data.get("buildInfo"):
            raise AssertionError("""
                Expected to find Prometheus version number. 
                Got %s
            """ % (data)) 
        else:
            print(prefix_ok + "Got Grafana Version %s" % data.get("buildInfo").get("version"))

def fetch_prometheus_datasource_from_grafana(grafana_api_key):
    # Load a list of datasources from Grafana.
    path = "/api/datasources"
    response = make_api_get_request("grafana", path, api_key=grafana_api_key)

    if (response.status_code != 200):
        raise AssertionError("""
            Incorrect status code from Grafana Prometheus data source check.\n
            Expected 200, got %d.\n
        """ % (response.status_code)) 

    data = json.loads(response.text)
    if len(data) == 0:
        raise AssertionError("""
            Prometheus Datasource not enabled.\n
            Expected 1, got %d.\n
        """ % (len(data))) 

    if data[0].get('name').strip() != 'Prometheus':
        raise AssertionError("""
            Datasource is incorrect\n
            Expected Prometheus, got %s.\n
        """ % (data[0].get('name')))
    else:
        print(prefix_ok + "Prometheus datasource has correct name.")

    # Check the datasource URL is correct
    # Note that this is _not_ publicweb traffic, so we expect docker internal URLs.
    if data[0].get('url').strip() != prometheus_internal_url:
        raise AssertionError("""
            Datasource URL is incorrect\n
            Expected %s, got %s.\n
        """ % (prometheus_internal_url, data[0].get('url'))) 
    else:
        print(prefix_ok + "Prometheus datasource has correct URL.")

    print(prefix_info + "Using Prometheus Datasource %d" % (data[0].get('id')))
    # Grafana datasource ID's are unique, we expect them to change.
    # Store this data to use it later.
    return data[0].get('id')

def check_proxied_cadvisor_version(grafana_api_key, datasource_id):

    # Query Prometheus datasource indirectly through Grafana.
    path = f'/api/datasources/proxy/{datasource_id}/api/v1/query'

    # Query for cAdvisor version number
    cadversion_query = "cadvisor_version_info"

    header = {
        'Authorization': f'Bearer {grafana_api_key}',
        'Content-Type': 'application/json'
    }
    data = {
        'query': f'{cadversion_query}{{}}',
        'time': time.time()
    }

    uri = "https://" + apis.get("grafana") + path
    response = requests.post(uri, params=data, headers=header, verify=False)
    data = json.loads(response.text).get("data")

    if (response.status_code != 200):
        raise AssertionError("""
            Incorrect status code from Grafana Proxied data source value.\n
            Expected 200, got %d.\n
        """ % (response.status_code))

    results = data.get("result")
    if len(results) == 0:
        raise AssertionError("""
            Proxied Grafana Datasource returned no data.\n
            Expected 1, got %d.\n
        """ % (len(results))) 

    # Check a version number for cAdvsior has made it into Grafana.
    metric = results[0].get("metric")
    if not metric.get("cadvisorVersion"):
        raise AssertionError("""
            Proxied Grafana Datasource failed to return cAdvisor version\n
            Got %d.\n
        """ % (metric.get("cadvisorVersion"))) 
    else:
        print(prefix_ok + "Fetch cAdvisor version data %s from Grafana." % (metric.get("cadvisorVersion")))

def check_proxied_container_data(grafana_api_key, datasource_id):
    # Query a list of metrics.
    # We should be expecting cAdvisor metrics to be returned.
    path = f'/api/datasources/proxy/{datasource_id}/api/v1/label/__name__/values'

    response = make_api_get_request("grafana", path, api_key=grafana_api_key)
    data = json.loads(response.text).get("data")

    if (response.status_code != 200):
        raise AssertionError(textwrap.dedent(f"""\
            Incorrect status code from Grafana proxied data source values.
            Expected 200, got {response.status_code}.
        """))
    else:
        print(prefix_ok + "Correct status code from Grafana.")

    # Check a few common cAdvisor prometheus metrics.
    for query in metric_queries:
        if query not in data:
            raise AssertionError(textwrap.dedent(f"""\
                Failed to find metric from Grafana.
                Expected {query}.
            """))
        else: 
            print(prefix_ok + "Metric %s exists in Grafana." % (query))

main()