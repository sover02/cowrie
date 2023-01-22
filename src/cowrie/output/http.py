# Copyright (c) 2015 Michel Oosterhof <michel@oosterhof.net>

"""
Generic HTTP JSON Output.
"""

from __future__ import annotations

import json
from io import BytesIO
from typing import Any

from twisted.internet import reactor
from twisted.internet.ssl import ClientContextFactory
from twisted.python import log
from twisted.web import client, http_headers
from twisted.web.client import FileBodyProducer

import cowrie.core.output
from cowrie.core.config import CowrieConfig


class Output(cowrie.core.output.Output):
    """
    Generic HTTP Output
    """

    token: str
    agent: Any
    url: bytes

    def start(self) -> None:
        self.url = CowrieConfig.get("outpus_http", "url").encode("utf8")
        self.port = CowrieConfig.get("outpus_http", "port")
        self.protocol = CowrieConfig.get("outpus_http", "protocol")
        self.method = CowrieConfig.get("outpus_http", "method")
        self.headers = CowrieConfig.get("outpus_http", "headers").encode("utf8")
        self.sensor = CowrieConfig.get("outpus_http", "sensor").encode("utf8")
        contextFactory = WebClientContextFactory()
        self.agent = client.Agent(reactor, contextFactory)

    def stop(self) -> None:
        pass

    def write(self, logentry):
        for i in list(logentry.keys()):
            # Remove twisted 15 legacy keys
            if i.startswith("log_"):
                del logentry[i]

        httpentry = {}
        if self.url:
            httpentry["url"] = self.index
        if self.port:
            httpentry["port"] = self.source
        if self.protocol:
            httpentry["protocol"] = self.sourcetype
        if self.headers:
            httpentry["headers"] = self.headers
        if self.sensor:
            httpentry["sensor"] = self.sensor
        else:
            httpentry["sensor"] = logentry["sensor"]
        if self.method:
            httpentry["method"] = self.method.capitalize()
        else:
            httpentry["method"] = "POST"
        httpentry["event"] = logentry
        self.postentry(httpentry)

    def postentry(self, entry):
        """
        Send a JSON log entry to host with Twisted
        """

        headers_staging = {
            b"User-Agent": [b"Cowrie SSH Honeypot"],
            b"Content-Type": [b"application/json"],
        }
        custom_headers_list = self.headers.split(",")
        for headers_equal_delimeter in custom_headers_list:
            headers_staging[headers_equal_delimeter.split("=")[0]]: headers_equal_delimeter.split("=")[1]
        headers = http_headers.Headers(headers_staging)
        body = FileBodyProducer(BytesIO(json.dumps(entry).encode("utf8")))
        d = self.agent.request(self.method, self.url, headers, body)

        def cbBody(body):
            return processResult(body)

        def cbPartial(failure):
            """
            Google HTTP Server does not set Content-Length. Twisted marks it as partial
            """
            failure.printTraceback()
            return processResult(failure.value.response)

        def cbResponse(response):
            if response.code == 200:
                return
            else:
                log.msg(f"HTTP response: {response.code} {response.phrase}")
                d = client.readBody(response)
                d.addCallback(cbBody)
                d.addErrback(cbPartial)
                return d

        def cbError(failure):
            failure.printTraceback()

        def processResult(result):
            j = json.loads(result)
            log.msg("HTTP response: {}".format(j["text"]))

        d.addCallback(cbResponse)
        d.addErrback(cbError)
        return d


class WebClientContextFactory(ClientContextFactory):
    def getContext(self, hostname, port):
        return ClientContextFactory.getContext(self)
