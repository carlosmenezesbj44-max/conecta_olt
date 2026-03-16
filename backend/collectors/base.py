class CollectorError(Exception):
    pass


class BaseCollector:
    protocol = "base"

    def __init__(self, olt, connection, context):
        self.olt = olt
        self.connection = connection
        self.context = context

    def collect(self):
        raise NotImplementedError
