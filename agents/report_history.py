class ReportHistoryAgent:
    def __init__(self):
        self.seen_iocs = set()

    def add_seen(self, ioc):
        self.seen_iocs.add(ioc)

    def is_seen(self, ioc):
        return ioc in self.seen_iocs