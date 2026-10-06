from dataclasses import dataclass


@dataclass(slots=True)
class Event:
    source: str
    raw_file: str
    raw_line: int
    raw_sha: str
    raw_ts_ms: int
    ts_ms: int
    host: str = ""
    actor: str = ""
    event: str = ""
    image: str = ""
    parent: str = ""
    cmd: str = ""
    src_ip: str = ""
    dst: str = ""
    dst_port: str = ""
    corr: str = ""

    @property
    def eid(self):
        return f"{self.source}:{self.raw_line}"

    def key(self):
        return (self.ts_ms, self.source, self.raw_file, self.raw_line)
