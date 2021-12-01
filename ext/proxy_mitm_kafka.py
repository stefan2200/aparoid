"""
mitmproxy module for Kafka forwarding
"""
import base64
import json
import kafka.errors
from kafka import KafkaProducer

from mitmproxy import (
    ctx,
    http
)

from mitmproxy.net.http.http1 import assemble_request, assemble_response


class KafkaForwarder:
    """
    mitmproxy module to report requests/responses to kafka
    """

    def __init__(self):
        """
        Set producer to None
        """
        self.producer = None

    def load(self, loader):
        """
        Configure exported variables
        :param loader:
        :return:
        """
        loader.add_option(
            name="kafka",
            typespec=str,
            default="",
            help="Specify Kafka server",
        )
        loader.add_option(
            name="topic",
            typespec=str,
            default="",
            help="Specify Kafka topic",
        )

    def configure(self, updates):
        """
        Set the exported variables from the mitmproxy context
        :param updates:
        :return:
        """
        if "kafka" in updates:
            try:
                self.producer = KafkaProducer(
                    value_serializer=lambda m: json.dumps(m).encode('utf-8'),
                    bootstrap_servers=ctx.options.kafka.split(","))
            except kafka.errors.KafkaError as kafka_error:
                print(f"Error starting Kafka producer: {kafka_error}")

    def set_response(self, httpflow):
        """Dump HTTP Request and Response."""
        if self.producer:
            try:
                request = assemble_request(httpflow.request)
                response = assemble_response(httpflow.response)
                raw = {
                    "request": base64.b64encode(request).decode(),
                    "response": base64.b64encode(response).decode()
                }
                self.producer.send(f"http-{ctx.options.topic}", value=raw)
                print("Produced kafka message for Request/Response pair")
            except kafka.errors.KafkaError as kafka_error:
                print("Producer error: ", kafka_error)

    def response(self, flow: http.HTTPFlow) -> None:
        """
        Triggers when a response is received
        :param flow:
        :return:
        """
        self.set_response(flow)


addons = [KafkaForwarder()]
