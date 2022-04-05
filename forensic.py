import mailparser
from collections import OrderedDict
import geoip2.database as iplocate
import re
import json
import socket


def parse_email_address(original_address):
    if len(original_address) > 1:
        if original_address[0] == "":
            display_name = None
        else:
            display_name = original_address[0]
        address = original_address[1]
    elif len(original_address) == 1:
        display_name = None
        address = original_address[0]
    address_parts = address.split("@")
    local = None
    domain = None
    if len(address_parts) > 1:
        local = address_parts[0].lower()
        domain = address_parts[-1].lower()

    return OrderedDict([("display_name", display_name),
                        ("address", address),
                        ("local", local),
                        ("domain", domain)])

def parse_forensic_email(feedback_report, sample, delivery_report):
    feedback_report_regex = re.compile(r"^([\w\-]+): (.+)$", re.MULTILINE)
    delivery_results = ["delivered", "spam", "policy", "reject", "other"]
    ct_reader = iplocate.Reader(city_mmdb)
    as_reader = iplocate.Reader(asn_mmdb)
    if feedback_report and sample:
        try:
            parsed_report = OrderedDict(); dv_parsed_report = OrderedDict()
            report_values = feedback_report_regex.findall(feedback_report)
            for report_value in report_values:
                key = report_value[0].lower().replace("-", "_")
                parsed_report[key] = report_value[1]

            if "arrival_date" not in parsed_report:
                if delivery_report:
                    dv_report_values = feedback_report_regex.findall(delivery_report)
                    for dv_report_value in dv_report_values:
                        dv_key = dv_report_value[0].lower().replace("-", "_")
                        dv_parsed_report[dv_key] = dv_report_value[1]
                    if "arrival_date" in dv_parsed_report:
                        parsed_report["arrival_date"] = dv_parsed_report["arrival_date"]

            if "version" not in parsed_report:
                parsed_report["version"] = 1

            if "user_agent" not in parsed_report:
                parsed_report["user_agent"] = None

            if "delivery_result" not in parsed_report:
                parsed_report["delivery_result"] = None
            else:
                for delivery_result in delivery_results:
                    if delivery_result in parsed_report["delivery_result"].lower():
                        parsed_report["delivery_result"] = delivery_result
                        break

            if parsed_report["delivery_result"] not in delivery_results:
                parsed_report["delivery_result"] = "other"

            sIP = parsed_report["source_ip"].split()[0]
            if sIP:
                sOrgName = sIP;
                reversed_dns = sIP;
                sIP_country = "NONE";
                sIP_as_number = "NONE";
                sIP_as_org = "NONE"
                if not IPAddress(sIP).is_private():
                    try:
                        ct_response = ct_reader.city(sIP)
                        sIP_country = ct_response.country.iso_code
                        as_response = as_reader.asn(sIP)
                        sIP_as_number = as_response.autonomous_system_number
                        sIP_as_org = as_response.autonomous_system_organization
                    except:
                        pass

                    try:
                        reversed_dns = socket.gethostbyaddr(sIP)[0]
                    except:
                        pass

                    if reversed_dns != "NONE":
                        sOrgName = reversed_dns[::-1]
                        sOrgName = sOrgName.split('.')[0] + "." + sOrgName.split('.')[1];
                        sOrgName = sOrgName[::-1]
                        if sOrgName in THREE_LEVEL_DOMAINS:
                            sOrgName = reversed_dns[::-1]
                            sOrgName = sOrgName.split('.')[0] + "." + sOrgName.split('.')[1] + "." + \
                                       sOrgName.split('.')[2]
                            sOrgName = sOrgName[::-1]
                    else:
                        sOrgName = sIP
                    if reversed_dns == "NONE":
                        reversed_dns = sIP
                    if sIP_country == "NONE":
                        sIP_country = "XX"
                    if sIP_as_number == "NONE":
                        sIP_as_number = ""
                    if sIP_as_org == "NONE":
                        sIP_as_org = ""
                    parsed_report["source"] = OrderedDict(
                        [('sIP', sIP), ('sOrgName', sOrgName), ('reversed_dns', reversed_dns),
                         ('sIP_country', sIP_country), ('sIP_as_number', sIP_as_number), ('sIP_as_org', sIP_as_org)])
                parsed_report["source"] = OrderedDict(
                    [('sIP', sIP), ('sOrgName', sOrgName), ('reversed_dns', reversed_dns), ('sIP_country', sIP_country),
                     ('sIP_as_number', sIP_as_number), ('sIP_as_org', sIP_as_org)])

            if "identity_alignment" not in parsed_report:
                parsed_report["authentication_mechanisms"] = []
            elif parsed_report["identity_alignment"] == "none":
                parsed_report["authentication_mechanisms"] = []
                del parsed_report["identity_alignment"]
            else:
                auth_mechanisms = parsed_report["identity_alignment"]
                auth_mechanisms = auth_mechanisms.split(",")
                parsed_report["authentication_mechanisms"] = auth_mechanisms
                del parsed_report["identity_alignment"]

            if "auth_failure" not in parsed_report:
                parsed_report["auth_failure"] = "dmarc"
            auth_failure = parsed_report["auth_failure"].split(",")
            parsed_report["auth_failure"] = auth_failure

            optional_fields = ["original_envelope_id", "dkim_domain",
                               "original_mail_from", "original_rcpt_to"]
            for optional_field in optional_fields:
                if optional_field not in parsed_report:
                    parsed_report[optional_field] = None

            parsed_email = mailparser.parse_from_string(sample)
            headers = json.loads(parsed_email.headers_json).copy()
            headers["Received"] = received_headers_parse(sample)
            parsed_email = json.loads(parsed_email.mail_json).copy()
            parsed_email["headers"] = headers

            if "arrival_date" not in parsed_report:
                parsed_report["arrival_date"] = parsed_email["date"]

            arrival_utc = human_timestamp_to_datetime(
                parsed_report["arrival_date"], to_utc=True)
            arrival_date_utc = arrival_utc.strftime("%Y-%m-%d %H:%M:%S")
            parsed_report["arrival_date_utc"] = arrival_date_utc
            parsed_report["arrival_date_timestamp"] = int(arrival_utc.strftime("%s"))

            if "from" not in parsed_email:
                if "From" in parsed_email["headers"]:
                    parsed_email["from"] = parsed_email["Headers"]["From"]
                else:
                    parsed_email["from"] = None

            if parsed_email["from"] is not None:
                parsed_email["from"] = parse_email_address(parsed_email["from"][0])

            if "to" in parsed_email:
                parsed_email["to"] = list(map(lambda x: parse_email_address(x),
                                              parsed_email["to"]))
            else:
                parsed_email["to"] = []

            if "cc" in parsed_email:
                parsed_email["cc"] = list(map(lambda x: parse_email_address(x),
                                              parsed_email["cc"]))
            else:
                parsed_email["cc"] = []

            if "bcc" in parsed_email:
                parsed_email["bcc"] = list(map(lambda x: parse_email_address(x),
                                               parsed_email["bcc"]))
            else:
                parsed_email["bcc"] = []

            if "delivered_to" in parsed_email:
                parsed_email["delivered_to"] = list(
                    map(lambda x: parse_email_address(x),
                        parsed_email["delivered_to"])
                        )

            if "subject" not in parsed_email:
                parsed_email["subject"] = None; parsed_report["subject"] = None
            else:
                parsed_report["subject"] = parsed_email["subject"]

            if "body" not in parsed_email:
                parsed_email["body"] = None

            if "reported_domain" not in parsed_report:
                parsed_report["reported_domain"] = parsed_email["from"]["domain"]

            if parsed_report["original_mail_from"] is None:
                parsed_report["original_mail_from"] = parsed_email["from"]["address"]

            if parsed_report["original_rcpt_to"] is None:
                parsed_report["original_rcpt_to"] = parsed_email["to"][0]["address"]

            parsed_report["sample"] = parsed_email["headers"]
            parsed_report["feedback_headers"] = feedback_report

        except InvalidForensicReport as e:
            error = 'Message with subject "{0}" ' \
                    'is not a valid ' \
                    'forensic DMARC report: {1}'.format(subject, e)
            raise InvalidForensicReport(error)
        except Exception as e:
            raise InvalidForensicReport(e.__str__())

        return parsed_report
