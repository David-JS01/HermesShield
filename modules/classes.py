class MailServer:
    def __init__(self):
        self.ip_address = ""
        self.domain = ""
        self.blacklists = []
        self.perc=0

    def add_blacklist(self, blacklist):
        self.blacklists.append(blacklist)
