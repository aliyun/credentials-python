from Tea.model import TeaModel


class Config(TeaModel):
    def __init__(self, type='', access_key_id='', access_key_secret='', role_arn='', role_session_name='',
                 public_key_id='', role_name='', private_key_file='', bearer_token='', security_token='', host='',
                 timeout=1000, connect_timeout=1000, proxy=''):
        self.type = type
        self.access_key_id = access_key_id
        self.access_key_secret = access_key_secret
        self.role_arn = role_arn
        self.role_session_name = role_session_name
        self.public_key_id = public_key_id
        self.role_name = role_name
        self.private_key_file = private_key_file
        self.bearer_token = bearer_token
        self.security_token = security_token
        self.host = host
        self.timeout = timeout
        self.connect_timeout = connect_timeout
        self.proxy = proxy
