class Key:
    def __init__(self, key: str | list, friendly_name: str = None):
        self.key = key
        self.friendly_name = friendly_name

    def __str__(self) -> str:
        return self.friendly_name
