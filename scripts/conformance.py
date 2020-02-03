#!/usr/bin/env python
#
# python wrapper for conformance suite API

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import base64
import json
import time


class Conformance(object):
    def __init__(self, api_url_base, api_token, requests_session):
        self.api_url_base = api_url_base
        self.requests_session = requests_session
        headers = {'Content-Type': 'application/json'}
        if api_token is not None:
            headers['Authorization'] = 'Bearer {0}'.format(api_token)
        self.requests_session.headers = headers

    def get_all_test_modules(self):
        """ Returns an array containing a dictionary per test module """
        api_url = '{0}api/runner/available'.format(self.api_url_base)
        response = self.requests_session.get(api_url)

        if response.status_code != 200:
            raise Exception("get_all_test_modules failed - HTTP {:d} {}".format(response.status_code, response.content))
        return json.loads(response.content.decode('utf-8'))

    def create_test_plan(self, name, configuration, variant=None):
        api_url = '{0}api/plan'.format(self.api_url_base)
        payload = {'planName': name}
        if variant != None:
            payload['variant'] = json.dumps(variant)
        response = self.requests_session.post(api_url, params=payload, data=configuration)

        if response.status_code != 201:
            raise Exception("create_test_plan failed - HTTP {:d} {}".format(response.status_code, response.content))
        return json.loads(response.content.decode('utf-8'))

    def create_test(self, test_name, configuration):
        api_url = '{0}api/runner'.format(self.api_url_base)
        payload = {'test': test_name}
        response = self.requests_session.post(api_url, params=payload, data=configuration)

        if response.status_code != 201:
            raise Exception("create_test failed - HTTP {:d} {}".format(response.status_code, response.content))
        return json.loads(response.content.decode('utf-8'))

    def create_test_from_plan(self, plan_id, test_name):
        api_url = '{0}api/runner'.format(self.api_url_base)
        payload = {'test': test_name, 'plan': plan_id}
        response = self.requests_session.post(api_url, params=payload)

        if response.status_code != 201:
            raise Exception("create_test_from_plan failed - HTTP {:d} {}".format(response.status_code, response.content))
        return json.loads(response.content.decode('utf-8'))

    def get_module_info(self, module_id):
        api_url = '{0}api/info/{1}'.format(self.api_url_base, module_id)
        response = self.requests_session.get(api_url)

        if response.status_code != 200:
            raise Exception("get_module_info failed - HTTP {:d} {}".format(response.status_code, response.content))
        return json.loads(response.content.decode('utf-8'))

    def get_test_log(self, module_id):
        api_url = '{0}api/log/{1}'.format(self.api_url_base, module_id)
        response = self.requests_session.get(api_url)

        if response.status_code != 200:
            raise Exception("get_test_log failed - HTTP {:d} {}".format(response.status_code, response.content))
        return json.loads(response.content.decode('utf-8'))

    def start_test(self, module_id):
        api_url = '{0}api/runner/{1}'.format(self.api_url_base, module_id)
        response = self.requests_session.post(api_url)

        if response.status_code != 200:
            raise Exception("start_test failed - HTTP {:d} {}".format(response.status_code, response.content))
        return json.loads(response.content.decode('utf-8'))

    def wait_for_state(self, module_id, required_states, timeout=240):
        timeout_at = time.time() + timeout
        while True:
            if time.time() > timeout_at:
                raise Exception("Timed out waiting for test module {} to be in one of states: {}".
                                format(module_id, required_states))

            info = self.get_module_info(module_id)

            status = info['status']
            print("module id {} status is {}".format(module_id, status))
            if status in required_states:
                return status
            if status == 'INTERRUPTED':
                raise Exception("Test module {} has moved to INTERRUPTED".format(module_id))

            time.sleep(1)

    def upload_log_file_to_placeholder(self, module_id, stdout_log_content, stderr_log_content, timeout=30):
        timeout_at = time.time() + timeout

        while True:
            if time.time() > timeout_at:
                raise Exception("Timed out waiting for test module {} upload log file".format(module_id))

            test_entry_logs = self.get_test_log(module_id)
            if len(test_entry_logs):

                if any('upload' in entry for entry in test_entry_logs):
                    if sum('upload' in entry for entry in test_entry_logs) > 1:
                        raise Exception("Test module {} existing more than one placeholder".format(module_id))

                    for entry in test_entry_logs:
                        if 'upload' in entry:
                            api_url = '{0}api/log/{1}/logfile/{2}'.format(self.api_url_base, module_id, entry['upload'])
                            content_log = '========= STDOUT =========\n{}\n========= STDERR =========\n{}'.format(stdout_log_content, stderr_log_content)
                            response = self.requests_session.post(api_url, data=content_log.encode('utf-8'))

                            if response.status_code != 200:
                                raise Exception("Upload log file to placeholder failed - HTTP {:d} {}".format(response.status_code, response.content))

                            break
                    break

                else:
                    time.sleep(1)

            else:
                raise Exception("Upload log file to placeholder failed, test logs is not an array - {}".format(test_entry_logs))
