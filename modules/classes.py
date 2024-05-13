class MailServer:
    def __init__(self):
        self.ip_address = ""
        self.domain = ""
        self.blacklists = []
        self.perc=0

    def add_blacklist(self, blacklist):
        self.blacklists.append(blacklist)

class Mail:
    def __init__(self):
        self.ARC_cv_fail = False
        self.ARC_spf_fail = False
        self.ARC_dkim_fail = False
        self.ARC_dmarc_fail = False
        self.ARC_fail = False
        self.AUTH_spf_fail = False
        self.AUTH_dkim_fail = False
        self.AUTH_dmarc_fail = False
        self.AUTH_compauth_fail = False
        self.servidores = []
        self.emisor_missmatch = False
        self.checked = False
        self.spam_mail = False
        self._peligrosidad = 0

    @property
    def peligrosidad (self):
        return self._peligrosidad
    
    @peligrosidad.setter
    def peligrosidad(self, value):
        # Ensure the value does not exceed 100
        if value > 100:
            self._peligrosidad = 100
        else:
            self._peligrosidad = value

    def add_peligrosidad (self, valor):
        if self._peligrosidad + valor >= 100:
            self._peligrosidad=100
        else:
            self._peligrosidad = self._peligrosidad+valor
    
    def add_servidor(self, servidor):
        self.servidores.append(servidor)
