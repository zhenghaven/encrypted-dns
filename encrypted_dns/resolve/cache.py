class CacheHandler:
    def __init__(self, override_ttl):
        self._cache = {}
        self._override_ttl = override_ttl

    def get_cache_dict(self):
        return self._cache

    def get(self, rrset):
        if (rrset.name, rrset.rdtype, rrset.rdclass) in self._cache:
            (response_rrset, ttl, put_time) = self._cache[(rrset.name, rrset.rdtype, rrset.rdclass)]

            if int(time.time()) - put_time >= ttl:
                self._cache.pop((rrset.name, rrset.rdtype, rrset.rdclass))
                return None, None
            else:
                return response_rrset, ttl
        return None, None

    def put(self, rrset):
        if self._override_ttl == -1:
            self._cache[(rrset.name, rrset.rdtype, rrset.rdclass)] = (rrset, rrset.ttl, int(time.time()))
        else:
            self._cache[(rrset.name, rrset.rdtype, rrset.rdclass)] = (rrset, self._override_ttl, int(time.time()))

    def flush(self):
        self._cache = {}
