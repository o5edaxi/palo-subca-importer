"""Takes the host + port of a TLS server and uploads any trusted intermediate CA certificates to a
Palo Alto firewall or Panorama.

usage: palo_subca_importer.py [-h] [-k] [-z] [-s] [-t TEMPLATE] [-v VSYS] [-f] [-y] [-d]
    [-x {DEBUG,INFO,WARNING,ERROR,CRITICAL}] device domain_port [domain_port ...]"""
import logging
import argparse
import configparser
import os
import sys
import ssl
import socket
import hashlib
from datetime import datetime
from difflib import unified_diff
from getpass import getpass
import pandas as pd
import requests
import urllib3.exceptions
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from lxml import etree

CFG_FILENAME = 'palo_subca_importer.cfg'
CONN_TIMEOUT = 10
logger = logging.getLogger(__name__)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_issuer_cert_der(url):
    """Download a certificate and return in DER format"""
    issuer_response = requests.get(url, verify=True)
    if issuer_response.ok:
        issuer_der = issuer_response.content
        return issuer_der
    logging.debug('%s', issuer_response.text)
    raise Exception(f'Fetching issuer cert failed with response status '
                    f'{issuer_response.status_code}')


def upload_cert(sess, certificate, cert_name, fw, template='', vsys=''):
    """Upload PEM certificate to Palo Alto PanOS
    Cases: 1. vanilla fw 2. Panorama 3. VSYS fw 4. VSYS Panorama"""
    file = {'file': (cert_name, bytes(certificate, encoding='utf8'), 'utf-8')}
    # Unset any targets
    if template:
        sess.get(f'https://{fw}/api?type=op&cmd=<set><system><setting><target><none></none>'
                 f'</target></setting></system></set>')
    elif vsys:
        sess.get(f'https://{fw}/api?type=op&cmd=<set><system><setting><target-vsys>none'
                 f'</target-vsys></setting></system></set>')
    else:
        pass
    # Apparently "&target-tpl-vsys" in the import POST doesn't do anything, so we have to do this
    if template and not vsys:  # Case 2
        sess.get(f'https://{fw}/api?type=op&cmd=<set><system><setting><target><template>'
                 f'<name>{template}</name></template></target></setting></system></set>')
    elif template and vsys:  # Case 4
        sess.get(f'https://{fw}/api?type=op&cmd=<set><system><setting><target><template>'
                 f'<name>{template}</name><vsys>{vsys}</vsys></template></target></setting>'
                 f'</system></set>')
    elif vsys:  # Case 3
        sess.get(f'https://{fw}/api?type=op&cmd=<set><system><setting><target-vsys>{vsys}'
                 f'</target-vsys></setting></system></set>')
    else:  # Case 1
        pass
    response = sess.post(f'https://{fw}/api?type=import&category=certificate'
                         f'&certificate-name={cert_name}&format=pem', files=file)
    # Unset targets
    if template:
        sess.get(f'https://{fw}/api?type=op&cmd=<set><system><setting><target><none></none>'
                 f'</target></setting></system></set>')
    elif vsys:
        sess.get(f'https://{fw}/api?type=op&cmd=<set><system><setting><target-vsys>none'
                 f'</target-vsys></setting></system></set>')
    else:
        pass
    logging.debug('%s', response.text)
    response.raise_for_status()
    got_xml = etree.ElementTree(etree.fromstring(response.text))
    if got_xml.xpath(r'/response/@status')[0] != 'success':
        raise Exception(f'API call unsuccessful: {response.text}')
    return response


def check_cert_exists(sess, fw, cert_name, template='', vsys=''):
    """Check if certificate of given name is already trusted on Palo Alto PanOS
    Cases: 1. vanilla fw 2. Panorama 3. VSYS fw 4. VSYS Panorama"""
    template = f"/config/devices/entry/template/entry[@name='{template}']" if template else template
    vsys = f"/devices/entry/vsys/entry[@name='{vsys}']" if vsys else '/shared'
    response = sess.get(f'https://{fw}/api/?type=config&action=get&xpath={template}/config{vsys}'
                        f'/ssl-decrypt/trusted-root-CA&element')
    logging.debug('%s', response.text)
    response.raise_for_status()
    got_xml = etree.ElementTree(etree.fromstring(response.text))
    if got_xml.xpath(r'/response/@status')[0] != 'success':
        raise Exception(f'API call unsuccessful: {response.text}')
    if cert_name in got_xml.xpath(r'.//member/text()'):
        return True
    return False


def set_cert_trusted(sess, fw, cert_name, template='', vsys=''):
    """Set the Trusted CA aspect of a certificate on Palo Alto PanOS
    Cases: 1. vanilla fw 2. Panorama 3. VSYS fw 4. VSYS Panorama"""
    template = f"/config/devices/entry/template/entry[@name='{template}']" if template else template
    vsys = f"/devices/entry/vsys/entry[@name='{vsys}']" if vsys else '/shared'
    response = sess.get(f'https://{fw}/api/?type=config&action=set&xpath={template}/config{vsys}'
                        f'/ssl-decrypt/trusted-root-CA&element=<member>{cert_name}</member>')
    logging.debug('%s', response.text)
    response.raise_for_status()
    got_xml = etree.ElementTree(etree.fromstring(response.text))
    if got_xml.xpath(r'/response/@status')[0] != 'success':
        raise Exception(f'API call unsuccessful: {response.text}')
    return response


def commit(sess, fw):
    """Initiates a normal commit on Palo Alto PanOS"""
    response = sess.get(f'https://{fw}/api/?type=commit&cmd=<commit></commit>')
    logging.debug('%s', response.text)
    response.raise_for_status()
    got_xml = etree.ElementTree(etree.fromstring(response.text))
    if got_xml.xpath(r'/response/@status')[0] != 'success':
        raise Exception(f'API call unsuccessful: {response.text}')
    return response


def get_config(sess, fw, cfg_type):
    """Retrieves the global config from Palo Alto PanOS in XML format"""
    if cfg_type not in ('running', 'candidate'):
        raise ValueError(f'Type {cfg_type} is not one of "running", "candidate"')
    response = sess.get(f'https://{fw}/api/?type=op&cmd=<show><config><{cfg_type}>'
                        f'</{cfg_type}></config></show>')
    logging.debug('%s', response.text)
    response.raise_for_status()
    got_xml = etree.ElementTree(etree.fromstring(response.text))
    if got_xml.xpath(r'/response/@status')[0] != 'success':
        raise Exception(f'API call unsuccessful: {response.text}')
    return response.text


def check_tpl_vsys_exists(sess, fw, template='', vsys=''):
    """Checks that the Template and/or Vsys exist
    Cases: 1. Panorama 2. VSYS fw 3. VSYS Panorama"""
    template = f"/config/devices/entry/template/entry[@name='{template}']" if template else template
    vsys = f"/devices/entry/vsys/entry[@name='{vsys}']" if vsys else vsys
    response = sess.get(f'https://{fw}/api/?type=config&action=show&xpath={template}/config{vsys}')
    logging.debug('%s', response.text)
    response.raise_for_status()
    got_xml = etree.ElementTree(etree.fromstring(response.text))
    if got_xml.xpath(r'/response/@status')[0] == 'success':
        return True
    if got_xml.xpath(r'/response/msg/line/text()')[0] == 'No such node':
        return False
    raise Exception(f'API call unsuccessful: {response.text}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Takes the host + port  of a TLS server and '
                                                 'uploads any trusted intermediate CA certificates '
                                                 'to a Palo Alto firewall or Panorama.')
    parser.add_argument('device', type=str, help='Firewall or Panorama IP or FQDN')
    parser.add_argument('domain_port', type=str, nargs='+', help='FQDN or IP and port of a '
                                                                 'TLS Server, e.g. example.com:443.'
                                                                 ' Will use 443 as port if '
                                                                 'not specified.')
    parser.add_argument('-k', '--ignore-fw-certs', action='store_true', help='Do not validate the '
                                                                             'firewall or Panorama '
                                                                             'certificate when '
                                                                             'connecting to it. '
                                                                             'Default: False')
    parser.add_argument('-z', '--upload-dangerous', action='store_true', help='DANGEROUS: Upload '
                                                                              'the CA to the '
                                                                              'device even if it '
                                                                              'is not found in '
                                                                              'the Mozilla CCADB. '
                                                                              'This means it does '
                                                                              'not chain up to a '
                                                                              'publicly trusted '
                                                                              'root CA, it is '
                                                                              'expired/revoked, or '
                                                                              'it is not an '
                                                                              'intermediate CA. '
                                                                              'Default: False')
    parser.add_argument('-s', '--deprecated-tls', action='store_true', help='Enable checking sites '
                                                                            'using SSLv3, TLSv1.0, '
                                                                            'TLSv1.1. These may '
                                                                            'already work, '
                                                                            'depending on the '
                                                                            'version of the ssl '
                                                                            'library. '
                                                                            'Default: False')
    parser.add_argument('-t', '--template', type=str, default='', help='Destination Panorama '
                                                                       'Template, must be set for'
                                                                       ' Panoramas')
    parser.add_argument('-v', '--vsys', type=str, default='', help='Destination Vsys, otherwise '
                                                                   'Shared')
    parser.add_argument('-f', '--upload-duplicates', action='store_true', help='Upload '
                                                                               'certificate to '
                                                                               'the firewall even '
                                                                               'if a certificate '
                                                                               'with the same '
                                                                               'name is already '
                                                                               'present. Default: '
                                                                               'False')
    parser.add_argument('-y', '--automatic', action='store_true', help='Start the commit without '
                                                                       'asking for confirmation. '
                                                                       'Default: False')
    parser.add_argument('-d', '--dry-run', action='store_true', help='Run the mechanism without '
                                                                     'changing anything on the '
                                                                     'firewall. Default: False')
    parser.add_argument('-x', '--debug-level', type=str, choices=['DEBUG', 'INFO', 'WARNING',
                                                                  'ERROR', 'CRITICAL'],
                        default='WARNING', help='Logging message verbosity. Default: WARNING')
    args = parser.parse_args()
    FW_IP = args.device
    DESTINATIONS = [d.split(':') if ':' in d else [d, 443] for d in args.domain_port]
    DESTINATIONS = [{'name': str(d[0]), 'port': int(d[1])} for d in DESTINATIONS]
    logging.basicConfig(level=args.debug_level, format='%(asctime)s [%(levelname)s] %(message)s')
    logging.info('Starting with args %s', args)
    config = configparser.ConfigParser()
    try:
        logging.info('Attempting to read config from %s', CFG_FILENAME)
        config.read(CFG_FILENAME)
        moz_section = config['Mozilla']
        MOZILLA_URL = str(moz_section.get('MOZILLA_URL'))
        MOZILLA_FILE = str(moz_section.get('MOZILLA_FILE'))
        if MOZILLA_URL == 'None' or MOZILLA_FILE == 'None':
            raise ValueError('MOZILLA_URL/MOZILLA_FILE not found in config')
        logging.info('Successfully retrieved config')
    except (configparser.Error, ValueError) as err:
        logging.critical('ERROR: unable to read config file %s with error %s\nPlease ensure the '
                         'file and variables exist.', CFG_FILENAME, err)
        sys.exit(1)
    try:
        logging.info('Attempting to read API key from %s', CFG_FILENAME)
        key_section = config['API Key']
        API_KEY = str(key_section.get('API_KEY'))
        if API_KEY == 'None':
            raise ValueError('Entry not found in config')
        logging.info('Successfully retrieved API key')
    except (configparser.Error, ValueError) as err:
        logging.error('API key not found in config file %s: %s.', CFG_FILENAME, err)
        USERNAME = input('API key not found. Please enter device username:')
        PASSWORD = getpass('Enter device password:')
    if os.path.isfile(MOZILLA_FILE):
        logging.info('Found CSV file at %s', MOZILLA_FILE)
        today = datetime.now().date()
        last_modify_time = os.stat(MOZILLA_FILE).st_mtime
        last_modify_time = datetime.fromtimestamp(last_modify_time).date()
    if not os.path.isfile(MOZILLA_FILE) or today != last_modify_time:
        logging.info('CSV file %s missing or older than today', MOZILLA_FILE)
        dl_session = requests.Session()
        dl_session.timeout = CONN_TIMEOUT
        csv = dl_session.get(MOZILLA_URL, verify=True)
        logging.info('Got return code %d for Mozilla URL', csv.status_code)
        logging.debug('Downloaded CSV file: %s', csv.text)
        csv.raise_for_status()
        with open(MOZILLA_FILE, 'w', encoding='utf-8') as f:
            f.write(csv.text)
        logging.info('Wrote CSV to disk.')
    logging.info('CSV file is recent.')
    with open(MOZILLA_FILE, 'r', encoding='utf-8') as f:
        data = pd.read_csv(f)
    logging.info('Read CSV file from disk.')
    logging.debug('%s', data)
    # data[['Subject', 'SHA256', 'PEM', ...]]
    logging.info('Found domains: %s', DESTINATIONS)
    certs_uploaded = 0
    destinations_checked = []
    for dest in DESTINATIONS:
        logging.info('Scanning %s', dest)
        if dest in destinations_checked:
            logging.warning('Skipping %s:%s due to duplicate entry', dest['name'], dest['port'])
            continue
        ssl_context = ssl.SSLContext()
        # Strictly to retrieve the cert. No data is exchanged.
        if args.deprecated_tls:
            ssl_context.minimum_version = ssl.TLSVersion.SSLv3
        client_socket = socket.socket()
        client_socket.settimeout(CONN_TIMEOUT)
        # server_hostname sets the SNI
        encr_client_socket = ssl_context.wrap_socket(client_socket, server_hostname=dest['name'])
        try:
            # This does not validate anything about the server, it's just to get its certificate!
            encr_client_socket.connect((dest['name'], dest['port']))
            site_certificate: bytes = encr_client_socket.getpeercert(binary_form=True)
        except socket.error as sock_err:
            logging.critical('Error while checking %s:%s, %s', dest['name'], dest['port'], sock_err)
            logging.critical('Skipping...')
            destinations_checked.append(dest)
            continue
        finally:
            encr_client_socket.close()
            client_socket.close()
        loaded_site_cert = x509.load_der_x509_certificate(site_certificate, default_backend())
        try:
            aia_section = loaded_site_cert.extensions.\
                get_extension_for_oid(x509.oid.ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
        except x509.ExtensionNotFound as ext_err:
            logging.critical('Error while checking %s:%s, %s', dest['name'], dest['port'], ext_err)
            logging.critical('Skipping...')
            destinations_checked.append(dest)
            continue
        issuer_cert_url = None
        for ia in aia_section:
            if ia.access_method == x509.AuthorityInformationAccessOID.CA_ISSUERS:
                issuer_cert_url = ia.access_location.value
        if not issuer_cert_url:
            logging.critical('AIA Issuer URL not found in certificate. Skipping...')
            destinations_checked.append(dest)
            continue
        logging.info('Issuer available at: %s', issuer_cert_url)
        try:
            issuer_cert_der = get_issuer_cert_der(issuer_cert_url)
        except requests.exceptions.InvalidSchema:
            logging.critical('Unsupported AIA URL: %s', issuer_cert_url)
            logging.critical('Skipping...')
            destinations_checked.append(dest)
            continue
        issuer_cert_digest = hashlib.sha256(issuer_cert_der).hexdigest()
        logging.info('Downloaded issuer DER having digest %s', issuer_cert_digest)
        final_file = None
        for index, row in data.iterrows():
            if issuer_cert_digest.casefold() == row['SHA256'].casefold():
                logging.info('Found match in Mozilla list in the SHA256 column')
                # Recheck hash from actual PEM
                ccadbder = ssl.PEM_cert_to_DER_cert(row['PEM'])
                if issuer_cert_digest.casefold() == hashlib.sha256(ccadbder).hexdigest().casefold():
                    logging.info('Rechecked hash and it matches with the Mozilla file')
                    file_name = 'Intermediate' + '--' + row['SHA256'][:16]
                    final_file = row['PEM']
                    logging.debug('PEM from file: %s', final_file)
        if not final_file:
            logging.critical('ATTENTION: Issuer for %s:%s is not trusted by Mozilla', dest['name'],
                             dest['port'])
            print(f"ATTENTION: Issuer for {dest['name']}:{dest['port']} is not trusted by Mozilla")
            if not args.upload_dangerous:
                logging.error('Skipping %s:%s due to CA not trusted', dest['name'], dest['port'])
                print(f"Skipping {dest['name']}:{dest['port']} due to issuer not trusted by "
                      f"Mozilla")
                destinations_checked.append(dest)
                continue
            logging.critical('*** Continuing due to -z flag. Commit at your own risk. ***')
            print('*** Continuing due to -z flag. Commit at your own risk. ***')
            final_file = ssl.DER_cert_to_PEM_cert(issuer_cert_der)
        fw_req = requests.Session()
        fw_req.verify = False if args.ignore_fw_certs else True
        fw_req.timeout = CONN_TIMEOUT
        try:
            if API_KEY == 'None':
                raise NameError
            fw_req.headers.update({'X-PAN-KEY': API_KEY})
        except NameError:
            fw_req.auth = (USERNAME, PASSWORD)
        if args.template or args.vsys:
            if not check_tpl_vsys_exists(fw_req, FW_IP, args.template, args.vsys):
                logging.critical('Template "%s" and/or Vsys "%s" do not exist. Exiting...',
                                 args.template, args.vsys)
                print(f'Template "{args.template}" and/or Vsys "{args.vsys}" do not exist.'
                      f' Exiting...')
                sys.exit(1)
        if check_cert_exists(fw_req, FW_IP, file_name, args.template, args.vsys):
            if not args.upload_duplicates:
                logging.warning("A certificate called %s already exists on the device. "
                                "Skipping...", file_name)
                destinations_checked.append(dest)
                continue
            logging.warning("A certificate called %s already exists on the device. Uploading "
                            "anyway...", file_name)
        logging.info('Uploading cert.')
        if args.dry_run:
            logging.info('Skipping upload due to dry run')
        else:
            upload_cert(fw_req, final_file, file_name, FW_IP, args.template, args.vsys)
        logging.info('Cert %s uploaded for %s:%s', file_name, dest['name'], dest['port'])
        print(f"Uploaded {file_name} for {dest['name']}:{dest['port']}")
        certs_uploaded += 1
        destinations_checked.append(dest)
        if not args.dry_run:
            set_cert_trusted(fw_req, FW_IP, file_name, args.template, args.vsys)
        logging.info('Cert trust set on device for %s:%s', dest['name'], dest['port'])
    if certs_uploaded == 0:
        logging.warning('No certificates sent to firewall. Exiting...')
        sys.exit(0)
    print('Loop done. Previewing configuration changes...')
    running_config = get_config(fw_req, FW_IP, 'running')
    logging.info('Got Running Config')
    logging.debug('%s', running_config)
    candidate_config = get_config(fw_req, FW_IP, 'candidate')
    logging.info('Got Candidate Config')
    logging.debug('%s', candidate_config)
    for line in unified_diff(running_config.splitlines(True), candidate_config.splitlines(True),
                             fromfile='running', tofile='candidate', n=10):
        print(line, end='')
    if not args.automatic:
        choice = input('\n\nEnter "COMMIT" to start the commit, anything else to exit.\n'
                       '(This is a local commit, not a Panorama push)\n')
        if choice != 'COMMIT':
            print('Exiting without commit...')
            sys.exit(0)
    if not args.dry_run:
        commit(fw_req, FW_IP)
    print('Commit started. Exiting...')
