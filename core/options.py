"""Typed module options, mirroring Metasploit's datastore semantics.

Each option type validates and normalizes its value when set, raising
ValueError on bad input so the console can report it immediately.
"""


class Opt:
    """Base option: name, required flag, description, default value."""

    def __init__(self, name, required=False, description="", default=None):
        self.name = name.upper()
        self.required = required
        self.description = description
        self.default = self.normalize(default) if default is not None else None
        self.value = None

    def normalize(self, value):
        """Convert/validate a raw value. Raise ValueError on bad input."""
        return value

    def set(self, value):
        self.value = self.normalize(value)

    def unset(self):
        self.value = None

    @property
    def current(self):
        """Effective value: user-set value wins, then the default."""
        return self.value if self.value is not None else self.default

    def is_set(self):
        return self.current is not None

    def display_value(self):
        cur = self.current
        if cur is None:
            return ""
        if isinstance(self, OptBool):
            return "true" if cur else "false"
        return str(cur)


class OptString(Opt):
    def normalize(self, value):
        return str(value)


class OptPassword(OptString):
    """String option that masks its value in displays (passwords, tokens)."""

    def display_value(self):
        cur = self.current
        if cur is None or cur == "":
            return ""
        return "*" * min(len(str(cur)), 16)


class OptAddress(OptString):
    """Hostname or IP address. Resolution is left to the modules."""

    def normalize(self, value):
        v = str(value).strip()
        if not v:
            raise ValueError(f"{self.name}: address cannot be empty")
        return v


class OptInt(Opt):
    def normalize(self, value):
        try:
            return int(value)
        except (TypeError, ValueError):
            raise ValueError(f"{self.name}: expected an integer, got {value!r}")


class OptFloat(Opt):
    def normalize(self, value):
        try:
            return float(value)
        except (TypeError, ValueError):
            raise ValueError(f"{self.name}: expected a number, got {value!r}")


class OptPort(OptInt):
    def normalize(self, value):
        port = super().normalize(value)
        if not 1 <= port <= 65535:
            raise ValueError(f"{self.name}: port must be 1-65535, got {port}")
        return port


class OptBool(Opt):
    TRUE = {"true", "yes", "1", "on"}
    FALSE = {"false", "no", "0", "off"}

    def normalize(self, value):
        if isinstance(value, bool):
            return value
        v = str(value).strip().lower()
        if v in self.TRUE:
            return True
        if v in self.FALSE:
            return False
        raise ValueError(f"{self.name}: expected true/false, got {value!r}")


class OptEnum(Opt):
    """Option restricted to a fixed set of string choices."""

    def __init__(self, name, choices, required=False, description="", default=None):
        self.choices = list(choices)
        super().__init__(name, required, description, default)

    def normalize(self, value):
        v = str(value)
        if v not in self.choices:
            raise ValueError(
                f"{self.name}: expected one of {', '.join(self.choices)}, got {value!r}"
            )
        return v


class OptionContainer:
    """Ordered, case-insensitive collection of Opt objects."""

    def __init__(self, options=()):
        self._options = {}
        for opt in options:
            self.add(opt)

    def add(self, opt):
        self._options[opt.name.upper()] = opt

    def remove(self, name):
        del self._options[name.upper()]

    def __contains__(self, name):
        return name.upper() in self._options

    def __setitem__(self, name, value):
        key = name.upper()
        if key not in self._options:
            raise KeyError(f"Unknown option: {name}")
        self._options[key].set(value)

    def __getitem__(self, name):
        key = name.upper()
        if key not in self._options:
            raise KeyError(f"Unknown option: {name}")
        return self._options[key].current

    def get(self, name, default=None):
        key = name.upper()
        if key not in self._options:
            return default
        val = self._options[key].current
        return val if val is not None else default

    def unset(self, name):
        key = name.upper()
        if key not in self._options:
            raise KeyError(f"Unknown option: {name}")
        self._options[key].unset()

    def options(self):
        """All Opt objects in registration order."""
        return list(self._options.values())

    def missing_required(self):
        return [o.name for o in self._options.values() if o.required and not o.is_set()]
