#from dataclasses import dataclass, field, asdict
#from typing import List

class Report:
    def __init__(self, reported_at, comment, categories, reporter_country):
        self.reported_at = reported_at
        self.comment = comment
        self.categories = categories
        self.reporter_country = reporter_country

    def __repr__(self):
        return (f"Report(reported_at={self.reported_at}, "
                f"comment={self.comment}, "
                f"categories={self.categories}, "
                f"reporter_country={self.reporter_country})")

class IPReport:
    def __init__(self, ip_address, country, isp, domain, abuse_score, total_reports, last_reported_at):
        self.ip_address = ip_address
        self.country = country
        self.isp = isp
        self.domain = domain
        self.abuse_score = abuse_score
        self.total_reports = total_reports
        self.last_reported_at = last_reported_at
        self.reports = []

    def add_report(self, report):
        self.reports.append(report)

    def __repr__(self):
        return (f"IPReport(ip_address={self.ip_address}, "
                f"country={self.country}, "
                f"isp={self.isp}, "
                f"domain={self.domain}, "
                f"abuse_score={self.abuse_score}, "
                f"total_reports={self.total_reports}, "
                f"last_reported_at={self.last_reported_at}, "
                f"reports={self.reports})")

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
        self.spf_record = ""
        self.AUTH_dkim_fail = False
        self.dkim_record = ""
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
        self.ipInfo = None

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
