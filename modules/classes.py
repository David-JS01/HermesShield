#from dataclasses import dataclass, field, asdict
#from typing import List


class MailServer:
    def __init__(self):
        self.ip_address = ""
        self.domain = ""
        self.blacklists = []
        #blacklists: List[str] = field(default_factory=list)
        self.perc=0

    def add_blacklist(self, blacklist):
        self.blacklists.append(blacklist)

class engine_result:
    def __init__(self, name="", category="", result=""):
        self.name = name
        self.category = category
        self.result = result

class sandbox:
    def __init__(self, name="", confidence=0, category = ""):
        self.name = name
        self.category = category
        self.confidence = confidence
        self.classification = ""
        self.malName = ""
    
    def set_classification(self, classifications):
        self.classification = ", ".join(classifications)

class File:
    def __init__(self):
        self.name = ""
        self.date = ""
        self.harm = 0
        self.malicious = 0
        self.suspicious = 0
        self.undetected = 0
        self.reputation = 0
        self.sandboxResult = []
        self.type = ""
        self.hash = ""
        self.engine_analysis = []
        
    def add_engine(self, engine):
        self.engine_analysis.append(engine)
    
    def add_sandbox(self, sandbox):
        self.sandboxResult.append(sandbox)

class URL:
    def __init__(self):
        self.name = ""
        self.date = ""
        self.harm = 0
        self.malicious = 0
        self.suspicious = 0
        self.undetected = 0
        self.engine_analysis = []

    def add_engine(self, engine):
        self.engine_analysis.append(engine)
        

class Mail:
    def __init__(self):
        self.hash = ""
        self.From = ""
        self.To = ""
        self.Subject = ""
        self.Date = ""
        self.returnPath = ""
        self.distance = -1
        self.domain = ""
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
        self.fraudPatterns = False
        self.ip_sender = ""
        self._peligrosidad = 0
        self.urls = []
        self.files = []
        self.text = ""

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
    
    def add_url(self, url):
        self.urls.append(url)
    
    def add_file(self, file):
        self.files.append(file)
