#!/bin/sh
WAZUH_PATH="/var/ossec"
${WAZUH_PATH}/framework/python/bin/python3 ${WAZUH_PATH}/integrations/custom-virustotal-dns.py "$@"