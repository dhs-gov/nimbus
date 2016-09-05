""""
Exception classes
"""

class NimbusError(Exception):
    pass
class NotFound(NimbusError):
    pass
class ManyFound(NimbusError):
    pass

