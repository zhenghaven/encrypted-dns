from abc import ABC, abstractmethod


class BaseOutbound(ABC):
    def __init__(self):
        pass

    @classmethod
    @abstractmethod
    def from_dict(cls, outbound_dict):
        if not 'protocol' in outbound_dict:
            # raise an exception since basic attributes is not specified in the dict
            raise Exception()

    @abstractmethod
    def query(self, dns_message):
        pass
