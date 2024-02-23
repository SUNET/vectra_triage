#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import os
import smtplib
import time
from io import UnsupportedOperation
from json import JSONDecodeError

import urllib3
import vat.vectra as vectra
import yaml
from requests.exceptions import ConnectionError
from vat.vectra import HTTPException

from libsocscan.devinfo import ptr_from_addr
from libsocscan.email import smtp_connect, SmtpSettings, \
    format_email_message_json, sending_confirmed, pick_abuse_addr
from whoisinfo.whoisinfo import WhoisInfo

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CACHE_TTL_DEFAULT = 604800  # One week

def ourfunction(test1, test2, test3):
    print(test1, test2)

class AlertCache:
    """
    This is a simple cache on disk for Vectra alerts. For a distributed setup please
    use Redis or a similarly robust solution.
    """

    def __init__(self, cache_file, ttl=CACHE_TTL_DEFAULT):
        self._ttl = ttl
        self._cache_file = cache_file

    def is_in_cache(self, ip, alert):
        update_cache, cache_content = self.__alert_cache_read(ip, self._cache_file)
        if cache_content:
            for cache_alert in cache_content:

                if cache_alert['alert'] == alert:
                    if update_cache:
                        self.__alert_cache_write(ip, cache_content, self._cache_file)  # Update cache

                    return True

            # Add the missing alert for the found host and update the cache accordingly
            cache_content.append(alert)
            self.__alert_cache_write(ip, cache_content, self._cache_file)
            return False

        self.__alert_cache_write(ip, [alert], self._cache_file)  # Add missing host and alert
        return False


    def is_partially_in_cache(self, ip, alert):
        update_cache, cache_content = self.__alert_cache_read(ip, self._cache_file)
        if update_cache:
            self.__alert_cache_write(ip, cache_content, self._cache_file)  # Update cache

        if cache_content:
            for cache_alert in cache_content:
                for key in cache_alert['alert']:
                    if key in alert:
                        for value in cache_alert['alert'][key]:
                            if value in alert[key]:
                                return True

            # Add the missing alert for the found host and update the cache accordingly
            cache_content.append(alert)
            self.__alert_cache_write(ip, cache_content, self._cache_file)
            return False

        self.__alert_cache_write(ip, [alert], self._cache_file)  # Add missing host and alert
        return False


    def __alert_cache_read(self, ip, cache_file):
        update_cache = False

        try:
            with open(cache_file, 'r') as f:

                try:
                    alert_cache = json.load(f)

                except (UnsupportedOperation, JSONDecodeError):
                    return update_cache, None

                ip_alert_list = alert_cache.get(ip)
                if ip_alert_list is not None:
                    cache_alerts_to_return = []

                    for cache_alert in ip_alert_list:
                        now = time.mktime(time.localtime())

                        if cache_alert['cache_timestamp'] + self._ttl >= now:
                            cache_alerts_to_return.append(cache_alert)

                    if len(ip_alert_list) != len(cache_alerts_to_return):
                        update_cache = True

                    return update_cache, cache_alerts_to_return

                return update_cache, None

        except (IOError, FileNotFoundError):
            return update_cache, None


    def __alert_cache_write(self, ip, alert_list, cache_file):
        if os.path.isfile(cache_file):
            file_access_flag = 'r+'
        else:
            file_access_flag = 'w+'

        try:
            with open(cache_file, file_access_flag) as f:
                try:
                    alert_cache_json = json.load(f)

                except (UnsupportedOperation, JSONDecodeError):
                    alert_cache_json = {}

                alert_cache_json[ip] = []
                for alert_dict in alert_list:

                    if alert_dict.get('cache_timestamp') is None:
                        cache_timestamp = time.mktime(time.localtime())
                        alert_cache_json[ip].append({'cache_timestamp': cache_timestamp, 'alert': alert_dict})
                    else:
                        alert_cache_json[ip].append(alert_dict)

                f.seek(0)  # Go to beginning of file before writing
                json.dump(alert_cache_json, f, sort_keys=True, indent=2)

        except (IOError, FileNotFoundError):
            raise


def identify_portscan_without_reply(detection):
    """
    Identify if the detection was a portscan against a closed port with no reply.
    :param detection: a single JSON detection as returned by the appliance.
    :returns: verdict regarding if a portscan was detected.
    :rtype: dict
    """
    portscan = False  # Default value

    detection_category = detection['detection_category']
    detection_type = detection['detection_type']
    detection_summary = detection['summary']
    detection_id = detection['id']
    detected_host_id = detection['src_host']['id']
    detected_host_ip = detection['src_host']['ip']
    detected_host_name = detection['src_host']['name']

    # 0 will be interpreted as false here so we have to
    # explicitly compare against None.
    if detection_summary.get('bytes_sent') is not None:
        data_sent = detection_summary.get('bytes_sent')
    elif detection_summary.get('data_sent') is not None:
        data_sent = detection_summary.get('data_sent')
    else:
        data_sent = None

    if detection_summary.get('bytes_received') is not None:
        data_received = detection_summary.get('bytes_received')
    elif detection_summary.get('data_received') is not None:
        data_received = detection_summary.get('data_received')
    else:
        data_received = None

    if detection_category == 'COMMAND & CONTROL' \
        and (detection_type == 'Vectra Threat Intelligence Match'
        or detection_type == 'Threat Intelligence Match'):

            if data_sent == 0:
                portscan = True

    return {'portscan': portscan,
            'detection_id': detection_id,
            'detected_host_id': detected_host_id,
            'detected_host_ip': detected_host_ip,
            'detected_host_name': detected_host_name,
            'summary_data_sent': data_sent,
            'summary_data_received': data_received}


def get_vectra_client(url, token):
    """
    Wrapper function to abstract away getting a VectraClient and handle errors.
    :param url: IP or hostname of Vectra brain (ex https://www.example.com).
    :param token: API token for authentication when using API v2*.
    :return: a VectraClient instance.
    """
    # retry for a whole day if needed
    for retry in (0, 8640):
        try:
            return vectra.VectraClient(url=url, token=token)

        except ConnectionError:
            # This can e.g. happen when the connection to the appliance goes down.
            print("Caught a ConnectionError exception in get_vectra_client(), sleeping for 10s ...")
            time.sleep(10)


def get_detection_generator(vectra_client, detection_category=None, detection_type=None, is_triaged=False):
    """
    Wrapper function to abstract away getting a detection generator and handle errors.
    :param vectra_client: an instance of VectraClient.
    :param detection_category: the category of the detection.
    :param detection_type: the type of the detection.
    :param is_triaged: whether or not triaged detections are of interest.
    :return: a VectraClient detection generator.
    """
    # retry for a whole day if needed
    for retry in (0, 8640):
        try:
            detection_generator = vectra_client.get_all_detections(
                page_size=500,
                is_triaged=is_triaged,
                detection_category=detection_category,
                detection_type=detection_type)

            return detection_generator

        except ConnectionError:
            # This can e.g. happen when the connection to the appliance goes down.
            print("Caught a ConnectionError exception in get_detection_generator(), sleeping for 10s ...")
            time.sleep(10)


def send_alert_to_owner(recipient, detection, email_template, smtp_settings):
    """
    Send alert to the owner of the system.
    :param recipient: email address of the owner.
    :param detection: a JSON representation of the detection that we should send.
    :param email_template: the template to use for the email.
    :param smtp_settings: an instance of SmtpSettings.
    """
    try:
        smtp = smtp_connect(smtp_settings)
        msg = format_email_message_json(recipient, 'soc@sunet.se',
                                        'Enhet infekterad med miner: {}'.format(detection['src_ip']),
                                        detection, "email_templates/{}".format(email_template), 'SSR')

        if sending_confirmed(recipient, msg, no_confirm_before_send=True) and smtp is not None:
            try:
                smtp.send_message(msg)
            except smtplib.SMTPRecipientsRefused as e:
                print("ERROR: recipients refused: {}".format(e.recipients))

    except OSError:
        raise ConnectionError


def determine_alert_recipient(detection_groups, customer_settings, whois_abuse_mail):
    """
    Determine who should be informed about the alert.
    :param detection_groups: the groups, as specified in the appliance, who are responsible for the network.
    :param customer_settings: static info about recipients for customers networks.
    :param whois_abuse_mail: the recipient as found with a whois lookup.
    :return: an email address
    """
    # First check if there's a static address specified for this network
    for group in detection_groups:
        for customer in customer_settings:
            if group['description'] == customer:
                return customer_settings[customer]

    # Otherwise try to use the abuse email address from whois
    if pick_abuse_addr(whois_abuse_mail.split(';')):
        return pick_abuse_addr(whois_abuse_mail.split(';'))

    # Default recipient if above fails
    return 'soc@sunet.se'


def triage_cryptocurrency_mining(url, token, smtp_settings, customer_settings):
    """
    Triage cryptocurrency mining detections.
    :param url: IP or hostname of Vectra brain (ex https://www.example.com).
    :param token: API token for authentication when using API v2*.
    :param smtp_settings: an instance of SmtpSettings.
    :param customer_settings: static info about recipients for customers networks.
    """

    start_time = time.time()
    counter = 0
    wi = WhoisInfo('whoisinfo_cache', ttl=86400)
    ac = AlertCache('cryptocurrency_mining')

    try:
        vectra_client = get_vectra_client(url, token)
        detection_generator = get_detection_generator(vectra_client, detection_type='Cryptocurrency Mining')

        for page in detection_generator:

            for detection in page.json()['results']:
                detection_id = detection['id']
                detected_host_ip = detection['src_host']['ip']
                detected_groups = detection['groups']
                detection_details = detection['grouped_details']
                detection_state = detection['state']
                cached_alert = {'dst_ips': detection['summary']['dst_ips']}

                if detection_state == 'active':
                    whois_info = wi.lookup(detected_host_ip)
                    counter += 1

                    alert_to_send = {'src_ip': detected_host_ip,
                                     'PTR': ptr_from_addr(detected_host_ip),
                                     'ASN': whois_info['whois_asn'],
                                     'whois_description': whois_info['whois_description'],
                                     'detections (only the three latest shown)': [alert for alert in detection_details[:3]]}

                    recipient = determine_alert_recipient(detected_groups, customer_settings, whois_info['whois_abuse_mail'])

                    if not ac.is_partially_in_cache(detected_host_ip, cached_alert):
                        print("Sending crypto mining alert with id: {} regarding: {} to: {}"
                              .format(detection_id, detected_host_ip, recipient))
                        send_alert_to_owner(recipient, alert_to_send, 'crypto_email_template', smtp_settings)
                    else:
                        print("Skipping since {} has already received a crypto mining alert with id: {} regarding: {}"
                              " within the specified TTL".format(recipient, detection_id, detected_host_ip))

                    print("Marking id {} as fixed".format(detection_id))
                    vectra_client.mark_detections_fixed([detection_id])

    except ConnectionError:
        #  This can e.g. happen when the connection to the appliance goes down.
        print("Caught a ConnectionError exception in triage_cryptocurrency_mining(), sleeping for 10s ...")
        time.sleep(10)

    except HTTPException:
        #  This can e.g. happen when a system update is in progress and 502 is returned.
        print("Caught a HTTPException exception in triage_cryptocurrency_mining(), sleeping for 10s ...")
        time.sleep(10)

    except JSONDecodeError:
        #  This can e.g. happen when a system is not available.
        print("Caught a JSONDecodeError exception in triage_command_and_control(), sleeping for 10s ...")
        time.sleep(10)

    print("Total crypto miners that were handled: {}".format(counter))

    end_time = time.time()
    print("The analysis of outstanding crypto mining detections took: {}s".format(end_time - start_time))


def triage_command_and_control(url, token, smtp_settings, customer_settings):
    """
    Triage COMMAND & CONTROL detections. Currently only handles false positives
    that were genererated by portscans from botnets and other sources of noise.
    Please note that this category still contains to much noise to act on
    and send alerts to our customers and some arguments are therefore no-ops.
    :param url: IP or hostname of Vectra brain (ex https://www.example.com).
    :param token: API token for authentication when using API v2*.
    :param smtp_settings: an instance of SmtpSettings.
    :param customer_settings: static info about recipients for customers networks.
    """
    start_time = time.time()
    counter = 0

    try:
        vectra_client = get_vectra_client(url, token)
        detection_generator = get_detection_generator(vectra_client, detection_category='COMMAND & CONTROL')

        for page in detection_generator:

            for detection in page.json()['results']:
                detection_info = identify_portscan_without_reply(detection)

                if detection_info['portscan']:
                    counter += 1
                    print("Portscan (recv: {}, sent: {}) without reply detected with id: {} for {}"
                        .format(
                            detection_info['summary_data_received'],
                            detection_info['summary_data_sent'],
                            detection_info['detection_id'],
                            detection_info['detected_host_ip'],
                        )
                    )

                    print("Marking id {} as 'Ports scanned by external host'".format(detection_info['detection_id']))
                    vectra_client.mark_detections_custom(
                        detection_ids=[detection_info['detection_id']],
                        triage_category='Ports scanned by external host')

    except ConnectionError:
        #  This can e.g. happen when the connection to the appliance goes down.
        print("Caught a ConnectionError exception in triage_command_and_control(), sleeping for 10s ...")
        time.sleep(10)

    except HTTPException:
        #  This can e.g. happen when a system update is in progress and 502 is returned.
        print("Caught a HTTPException exception in triage_command_and_control(), sleeping for 10s ...")
        time.sleep(10)

    except JSONDecodeError:
        #  This can e.g. happen when a system is not available.
        print("Caught a JSONDecodeError exception in triage_command_and_control(), sleeping for 10s ...")
        time.sleep(10)

    print("Total false positives of this type that were handled: {}".format(counter))

    end_time = time.time()
    print("The analysis of outstanding C&C detections took: {}s".format(end_time - start_time))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--url')
    parser.add_argument('--token')
    parser.add_argument('--smtp_server')
    parser.add_argument('--smtp_user')
    parser.add_argument('--smtp_password')
    args = parser.parse_args()

    if args.url \
        and args.token \
        and args.smtp_server \
        and args.smtp_user \
        and args.smtp_password:
            url = args.url
            token = args.token

            smtp_settings = SmtpSettings(args.smtp_server,
                                         args.smtp_user,
                                         args.smtp_password)
    else:
        with open('settings.yaml', 'r') as f:
            settings = yaml.safe_load(f)
            url = settings['url']
            token = settings['token']
            customer_settings = settings['customers']
            smtp_settings = SmtpSettings(settings['smtp_server'],
                                         settings['smtp_user'],
                                         settings['smtp_password'])

    while True:
        triage_cryptocurrency_mining(url, token, smtp_settings, customer_settings)
        triage_command_and_control(url, token, smtp_settings, customer_settings)


if __name__ == '__main__':
    main()
