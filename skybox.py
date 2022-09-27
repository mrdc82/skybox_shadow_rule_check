#!/usr/bin/env python3

import requests
import sys
import json
from rich import print
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

# HTTP SETUP SESSION
retry_strategy = Retry(
    total=10,
    status_forcelist=[429, 500, 502, 503, 504],
)
adapter = HTTPAdapter(max_retries=retry_strategy)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

MAX_NUMBER_OF_iTEMS_PER_REQUEST = 10  # DON'T CHANGE THIS VALUE, THIS IS THE MAX!


class skybox:
    def __init__(
        self,
        host,
        port,
        external_api_user,
        externernal_api_password,
        internal_api_user,
        internal_api_password,
    ):

        self.host = host
        self.port = port
        self.external_api_user = external_api_user
        self.externernal_api_password = externernal_api_password
        self.internal_api_user = internal_api_user
        self.internal_api_password = internal_api_password

    def access_rule_info(self, rule_id):
        """
        Function to get the rule information from a skybox rule id
        """

        endpoint = f"/skybox/webservice/jaxrs/model/v1/access-rules/{rule_id}"
        url = f"https://{self.host}:{self.port}{endpoint}"

        headers = {
            "Accept": "application/json",
        }

        with self.__get_http_session__() as http:

            response = http.get(
                url,
                headers=headers,
                verify=False,
                auth=HTTPBasicAuth(
                    self.external_api_user, self.externernal_api_password
                ),
            )

            jsonResponse = json.loads(response.text)

            if jsonResponse:
                return jsonResponse
            else:
                return None

    def shadowing_rule_ids_for_rule_id(self, rule_id):
        """
        Function to get the shadowing rule information from skybox rule id
        """

        endpoint = "/skybox/webservice/jaxrs/internalAPI/analytics/shadow/getCoveringRulesForAccessRule"
        url = f"https://{self.host}:{self.port}{endpoint}"

        headers = {
            "Accept": "application/json",
        }

        params = {"modelType": "LIVE", "accessRuleId": rule_id}

        with self.__get_http_session__() as http:

            response = http.get(
                url,
                headers=headers,
                params=params,
                verify=False,
                auth=HTTPBasicAuth(self.internal_api_user, self.internal_api_password),
            )

            jsonResponse = json.loads(response.text)

            if jsonResponse["coveringRulesIds"]:
                return jsonResponse["coveringRulesIds"]
            else:
                return None

    def changes(self, period=1):
        """
        get all firewall changes for specified period
        1 = TODAY_LASTDAY (day 0-1)
        2 = LASTDAY_LAST_WEEK (day 2-7)
        """

        endpoint = "/skybox/webservice/jaxrs/changetracking/group"
        url = f"https://{self.host}:{self.port}{endpoint}"

        headers = {
            "Accept": "application/json",
        }

        if period == 1:
            changeTime = "TODAY_LASTDAY"
        elif period == 2:
            changeTime = "LASTDAY_LAST_WEEK"

        analysisId = self.__get_change_tracking_bag_id__()

        params = {"analysisId": analysisId, "changeTime": changeTime}

        with self.__get_http_session__() as http:

            response = http.get(
                url,
                headers=headers,
                params=params,
                verify=False,
                auth=HTTPBasicAuth(self.internal_api_user, self.internal_api_password),
            )

            jsonResponse = json.loads(response.text)

            if jsonResponse:
                return jsonResponse
            else:
                return None

    def affected_rule_ids_for_change(self, change):
        """
        Lookup and return the ruleid that was affected by skybox change id number
        """

        if change["type"] != "com.skybox.view.transfer.fwchanges.FwChangeTypeEnum.ACL":

            raise ValueError(
                'change["type"] must be of type "com.skybox.view.transfer.fwchanges.FwChangeTypeEnum.ACL" to this function'
            )

        change_id = change["id"]

        endpoint = f"/skybox/webservice/jaxrs/changetracking/details/{change_id}/aclId"
        url = f"https://{self.host}:{self.port}{endpoint}"

        headers = {
            "Accept": "application/json",
        }

        with self.__get_http_session__() as http:

            response = http.get(
                url,
                headers=headers,
                verify=False,
                auth=HTTPBasicAuth(self.internal_api_user, self.internal_api_password),
            )

            jsonResponse = json.loads(response.text)

            if not "value" in jsonResponse:
                return None
            else:
                return jsonResponse["value"]

    def __get_change_tracking_bag_id__(self):
        """
        Function to get the internal skybox bag id for "All Changes"
        Used to query changes, and filtered for time in "changes()"
        """
        endpoint = "/skybox/webservice/jaxrs/changetracking"
        url = f"https://{self.host}:{self.port}{endpoint}"

        headers = {
            "Accept": "application/json",
        }

        with self.__get_http_session__() as http:

            response = http.get(
                url,
                headers=headers,
                verify=False,
                auth=HTTPBasicAuth(self.internal_api_user, self.internal_api_password),
            )

            jsonResponse = json.loads(response.text)

            for resp in jsonResponse["elements"]:
                if resp["name"] == "All Changes":
                    return resp["id"]

    def __get_http_session__(self):
        """
        create a new requests.session, return object
        use with "with" statement, so that we can close sessions reliably
        """
        http = requests.Session()
        http.mount("https://", adapter)
        http.mount("http://", adapter)

        return http
