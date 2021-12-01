"""
Yeahh config!!
"""


class Config:
    """
    You can set the stuff below yourself
    Don't forget to restart afterwards
    """

    ca_name = "aparoid.mitm.com"
    cert_directory = "certs"
    cert_auto_recreate = False

    # you can also use /tmp/cert_cache for automatic cleanup
    cert_cache_directory = "cache"

    # dynamic use cert (point this to burp if you are not using the embedded proxy)
    cert_location = "certs/mitmproxy-ca-cert.pem"

    # use kafka for the http collector and frida
    use_kafka = True

    kafka_servers = ["kafka:29092"]

    # hard-coded adb location (default: use from PATH)
    adb_path = None

    # Use this as proxy port (for use with third-party proxy servers)
    proxy_port = 8088

    # Proxy listen host (pls do not expose)
    proxy_host = "127.0.0.1"

    # database connection string
    # database_connector = "sqlite:///aparoid.db"
    database_connector = "postgresql+psycopg2://aparoid:aparoid@postgres/aparoid"

    def get_key(self, key, default=None):
        """
        Get config entry
        Return default if not found
        :param key:
        :param default:
        :return:
        """
        return getattr(self, key, default)

    def set_key(self, key, value):
        """
        Temporary key override
        :param key:
        :param value:
        :return:
        """
        return setattr(self, key, value)
