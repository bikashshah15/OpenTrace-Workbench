"""Live single-repository acquisition and scanning (I5, first live workflow).

Opt-in and allowlisted. Repository content is hostile data: it is fetched by full SHA, verified
against the commit's own tree, exported without any checkout filter or hook, and read by two pinned
scanners that run inside an OS isolation boundary. Nothing from the repository is built, installed
or executed.
"""
