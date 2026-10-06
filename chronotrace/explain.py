"""Plain-English narration of verdicts (no security background required)."""
from .util import human_duration, human_time

_STAGE_TEXT = {
    "persistence": "set up a scheduled task (a trick to keep access after a restart)",
    "staging": "packed files into a single archive",
    "egress": "sent data out to an outside address",
    "cleanup": "deleted the local copy to hide it",
}


def narrate(v):
    f, r = v["facts"], v["rule"]
    when = human_time(v["start_ms"])
    if r == "staging_exfil_chain":
        acts = [_STAGE_TEXT[s] for s in ("persistence", "staging", "egress", "cleanup") if s in f["stages_present"]]
        return (f"On {v['subject']} at {when}, a {f['entry_parent']} document opened a scripting tool "
                f"({f['entry_child']}). Within {human_duration(f['duration_s'])} the same computer " +
                ", ".join(acts[:-1]) + (", and " if len(acts) > 1 else "") + acts[-1] +
                f" (destination: {', '.join(f['destinations'])}). This is the classic shape of a malicious "
                "document followed by data theft." + _exfil(f.get("exfil")))
    if r == "staging_without_entry_point":
        dst = ", ".join(f["destinations"]) or "an unknown place"
        if v["status"] == "REJECTED_BENIGN":
            return (f"On {v['subject']} at {when}, files were archived and sent to {dst}. That looks like data "
                    "theft at first glance, but it was rejected as routine activity: " + "; ".join(v["reasons"]) + ".")
        return (f"On {v['subject']} at {when}, files were archived and sent to {dst} with no clear entry point "
                "and no approved change to explain it. Needs a human look.")
    if r == "auth_failure_burst":
        if v["status"] == "REJECTED_BENIGN":
            return (f"Address {f['src_ip']} failed {f['failures']} logins from {when}, which looks like password "
                    "guessing, but it was rejected as an authorised scan: " + "; ".join(v["reasons"]) + ".")
        tail = (f" It then succeeded as {f['success_account']}, meaning a guess may have worked."
                if f["followed_by_success"] else " No success followed.")
        return (f"Address {f['src_ip']} failed {f['failures']} logins across {f['distinct_accounts']} account(s) "
                f"starting {when}, a pattern consistent with password guessing." + tail)
    return f"{r} on {v['subject']} at {when}."


_STATUS = {"complete": "complete: nothing is missing", "incomplete": "incomplete: part of it was not captured",
           "unverified": "intact, but its full size could not be confirmed", "no_archive": "not an archive"}


def _exfil(x):
    if not x:
        return ""
    recs = f" ({x['records']:,} records)" if x.get("records") else ""
    return (f" The packet capture shows what left: a {x['bytes']:,}-byte archive holding {x['files']} file(s)"
            f"{recs}, and the recovered transfer is {_STATUS.get(x['status'], x['status'])}.")
