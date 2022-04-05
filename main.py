import pika
import sys
import json
import email
import binascii
from base64 import b64decode
from forensic import parse_forensic_email, parse_email_address

def process_forensic_email(mail, channel):
    print(mail['subject'])
    delivery_report = None
    if mail.get_content_maintype() == 'multipart' or mail.get_content_maintype() == 'multipart/report':
        for part in mail.walk():
            content_type = part.get_content_type()
            payload = part.get_payload()
            if type(payload) != list:
                payload = [payload]
            payload = payload[0].__str__()
            if content_type == "message/feedback-report":
                try:
                    if "Feedback-Type" in payload:
                        feedback_report = payload
                    else:
                        feedback_report = b64decode(payload).__str__()
                    feedback_report = feedback_report.lstrip(
                        "b'").rstrip("'")
                    feedback_report = feedback_report.replace("\\r", "")
                    feedback_report = feedback_report.replace("\\n", "\n")
                except (ValueError, TypeError, binascii.Error):
                    feedback_report = payload
            elif content_type == "text/rfc822-headers":
                sample = payload
            elif content_type == "message/rfc822":
                sample = payload
            elif content_type == "message/delivery-status":
                delivery_report = payload

        parsed_report = parse_forensic_email(feedback_report, sample, delivery_report)
        ruf_from = parse_email_address(mail["from"].split())
        parsed_report["ruf_from"] = ruf_from["address"].replace('<', '').replace('>', '')
        json_report = json.dumps(parsed_report)
        json_output = json.loads(json_report)
        # doc_domain = json_output['reported_domain']
        # result = None
        # if forensic_import_check(doc_domain=doc_domain, domains=domains_):
        channel.basic_publish(exchange='',
                      routing_key='ingesting',
                      body=json_output)
        return True
    return False


def main():
    # connection = pika.BaseConnection(pika.ConnectionParameters(host='localhost'))
    connection = pika.BlockingConnection(pika.ConnectionParameters(host='localhost'))
    channel = connection.channel()

    channel.queue_declare(queue='forensic_queue', durable=True)

    def callback(ch, method, properties, body):
        print(" [x] Received %r" % body)
        channel.basic_publish(exchange='',
                              routing_key='ingesting',
                              body=body)
        mail = email.message_from_bytes(body)
        try:
            result = process_forensic_email(mail, channel)
            if result:
                print('forensic - processed email : {0}'.format(mail['subject']))
            else:
                print('forensic - failed to process email {0}'.format(mail['subject']))
        except Exception:
            print('forensic - failed to process email {0}'.format(body))
            raise

    channel.basic_consume(queue='forensic_queue', on_message_callback=callback, auto_ack=True)
    print(' [*] Waiting for messages. To exit press CTRL+C')
    channel.start_consuming()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('Interrupted')
        sys.exit(0)



