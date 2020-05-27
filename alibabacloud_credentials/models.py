from Tea.model import TeaModel


class Config(TeaModel):
    def __init__(self, **kwargs):
        super().__init__()
        self.type = ""
        self.access_key_id = ""
        self.access_key_secret = ""
        self.role_arn = ""
        self.role_session_name = ""
        self.public_key_id = ""
        self.role_name = ""
        self.private_key_file = ""
        self.bearer_token = ""
        self.security_token = ""
        self.host = ""
        self.timeout = 1000
        self.connect_timeout = 1000
        self.proxy = ""
        for k, v in kwargs.items():
            setattr(self, k, v)
