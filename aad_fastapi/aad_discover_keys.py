import requests


class AadDiscoverKey:
    # static json, containing discovery urls
    _discovery_keys = None

    @staticmethod
    def get_discovery_key_json(key_url: str):
        if AadDiscoverKey._discovery_keys is None:
            AadDiscoverKey._discovery_keys = requests.get(key_url).json()

        return AadDiscoverKey._discovery_keys
