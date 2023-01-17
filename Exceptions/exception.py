class ArgParseError(Exception):
    pass


class NoTargetIpAddr(ArgParseError):
    def __str__(self) -> str:
        return 'Target ip address is missing'


class NoListenPort(ArgParseError):
    def __str__(self) -> str:
        return 'No Port to listen for connections'


class NoListenIp(ArgParseError):
    def __str__(self) -> str:
        return 'No IP address to listen for connections'


class NetworkParseError(Exception):
    pass


