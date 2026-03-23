#!/var/ossec/framework/python/bin/python3
import json
import sys
import os
import requests
from socket import AF_UNIX, SOCK_DGRAM, socket

pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
LOG_FILE = f'{pwd}/logs/integrations.log'
SOCKET_ADDR = f'{pwd}/queue/sockets/queue'

def log(msg):
    with open(LOG_FILE, 'a') as f:
        f.write(msg + '\n')

def send_msg(msg, agent):
    if not agent or agent['id'] == '000':
        string = '1:virustotal:{0}'.format(json.dumps(msg))
    else:
        location = '[{0}] ({1}) {2}'.format(
            agent['id'], agent['name'],
            agent.get('ip', 'any')
        )
        location = location.replace('|', '||').replace(':', '|:')
        string = '1:{0}->virustotal:{1}'.format(location, json.dumps(msg))
    try:
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(SOCKET_ADDR)
        sock.send(string.encode())
        sock.close()
    except Exception as e:
        log(f'# Error sending message: {e}')

def query_virustotal_domain(domain, apikey):
    url = f'https://www.virustotal.com/api/v3/domains/{domain}'
    headers = {'x-apikey': apikey}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            return r.json()
        elif r.status_code == 404:
            return {'error': 'not_found'}
        elif r.status_code == 204:
            return {'error': 'rate_limit'}
        else:
            return {'error': f'http_{r.status_code}'}
    except Exception as e:
        return {'error': str(e)}

def main(args):
    log(f'# custom-virustotal-dns called with args: {args}')

    if len(args) < 3:
        log('# Error: bad arguments')
        sys.exit(1)

    alert_file = args[1]
    apikey = args[2]

    try:
        with open(alert_file) as f:
            alert = json.load(f)
    except Exception as e:
        log(f'# Error reading alert: {e}')
        sys.exit(1)

    try:
        domain = alert['data']['win']['eventdata']['queryName']
    except KeyError:
        log('# No queryName found in alert')
        sys.exit(0)

    log(f'# Querying VirusTotal for domain: {domain}')

    vt_data = query_virustotal_domain(domain, apikey)

    alert_output = {
        'integration': 'virustotal',
        'virustotal': {
            'domain': domain,
            'source': {
                'alert_id': alert.get('id', ''),
                'agent': alert.get('agent', {}).get('name', ''),
                'file': domain,  # Requis par règle 87104/87105
            }
        }
    }

    if 'error' in vt_data:
        alert_output['virustotal']['error'] = vt_data['error']
        log(f'# VT error for {domain}: {vt_data["error"]}')
    else:
        try:
            stats = vt_data['data']['attributes']['last_analysis_stats']
            reputation = vt_data['data']['attributes'].get('reputation', 0)
            malicious_count = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total = sum(stats.values())

            alert_output['virustotal'].update({
                # Booléen 0/1 pour les règles natives 87104/87105
                'malicious': 1 if malicious_count > 0 else 0,
                # Détail du score dans un champ séparé
                'positives': malicious_count,
                'suspicious': suspicious,
                'total': total,
                'reputation': reputation,
                'found': 1 if total > 0 else 0,
                'permalink': f'https://www.virustotal.com/gui/domain/{domain}'
            })
            log(f'# VT result for {domain}: malicious={malicious_count}/{total}')
        except Exception as e:
            log(f'# Error parsing VT response: {e}')
            alert_output['virustotal']['error'] = str(e)

    send_msg(alert_output, alert.get('agent'))

if __name__ == '__main__':
    main(sys.argv)