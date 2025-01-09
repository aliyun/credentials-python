class HttpOptions:
    def __init__(self,
                 *,
                 proxy: str = None,
                 connect_timeout: int = None,
                 read_timeout: int = None):
        self.proxy = proxy
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
