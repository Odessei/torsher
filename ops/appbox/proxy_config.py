"""Convert the existing single owner route to a socket-free file provider."""

import ipaddress
import re


def owner_route(host_rule, source_ranges, depth, endpoint, entrypoint="web"):
    if not re.fullmatch(r"Host\(\x60[A-Za-z0-9.-]+\x60\)", host_rule):
        raise ValueError("expected one exact owner host rule")
    networks = [str(ipaddress.ip_network(value.strip())) for value in source_ranges]
    if not networks or not isinstance(depth, int) or depth < 0:
        raise ValueError("missing source network or invalid forwarding depth")
    return {"http": {
        "routers": {"owner": {
            "rule": host_rule, "entryPoints": [entrypoint],
            "service": "media", "middlewares": ["owner", "https"],
        }},
        "middlewares": {
            "owner": {"ipAllowList": {"sourceRange": networks, "ipStrategy": {"depth": depth}}},
            "https": {"headers": {"customRequestHeaders": {"X-Forwarded-Proto": "https"}}},
        },
        "services": {"media": {"loadBalancer": {"servers": [{"url": endpoint}]}}},
    }}


def from_docker_labels(labels, endpoint):
    prefix = "traefik.http."
    values = [
        "routers.torsher.rule",
        "routers.torsher.entrypoints",
        "routers.torsher.middlewares",
        "services.torsher.loadbalancer.server.port",
        "middlewares.torsher-https.headers.customrequestheaders.X-Forwarded-Proto",
        "middlewares.torsher-owner.ipallowlist.ipstrategy.depth",
        "middlewares.torsher-owner.ipallowlist.sourcerange",
    ]
    active = {key[len(prefix):]: value for key, value in labels.items() if key.startswith(prefix)}
    if active.keys() != set(values):
        raise ValueError("unexpected routing labels, review the proxy configuration")
    if (active[values[2]], active[values[3]], active[values[4]]) != (
        "torsher-owner,torsher-https", "8080", "https",
    ):
        raise ValueError("unexpected middleware chain or port")
    return owner_route(active[values[0]], active[values[6]].split(","), int(active[values[5]]),
                       endpoint, active[values[1]])


def startup_flags(current):
    safe = [flag for flag in current if not flag.lower().startswith("--providers.docker")]
    if any(flag.lower().startswith("--providers.file") for flag in safe):
        raise ValueError("file provider already configured")
    return [*safe, "--providers.file.directory=/conf", "--providers.file.watch=true"]
