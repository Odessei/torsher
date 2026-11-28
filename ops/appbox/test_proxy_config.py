import unittest

from proxy_config import from_docker_labels, startup_flags


class ProxyConfigTests(unittest.TestCase):
    def test_owner_route_retains_forwarding_and_rejects_additional_routes(self):
        labels = {
            "traefik.http.routers.torsher.rule": "Host(\x60fixture.example.test\x60)",
            "traefik.http.routers.torsher.entrypoints": "web",
            "traefik.http.routers.torsher.middlewares": "torsher-owner,torsher-https",
            "traefik.http.services.torsher.loadbalancer.server.port": "8080",
            "traefik.http.middlewares.torsher-https.headers.customrequestheaders.X-Forwarded-Proto": "https",
            "traefik.http.middlewares.torsher-owner.ipallowlist.ipstrategy.depth": "1",
            "traefik.http.middlewares.torsher-owner.ipallowlist.sourcerange": "192.0.2.6/32",
        }
        config = from_docker_labels(labels, "http://torsher:8080")["http"]
        self.assertEqual(config["routers"]["owner"]["middlewares"], ["owner", "https"])
        allow = config["middlewares"]["owner"]["ipAllowList"]
        self.assertEqual(allow["ipStrategy"], {"depth": 1})
        self.assertEqual(allow["sourceRange"], ["192.0.2.6/32"])
        labels["traefik.http.routers.extra.rule"] = "Host(\x60other.example.test\x60)"
        with self.assertRaisesRegex(ValueError, "unexpected routing"):
            from_docker_labels(labels, "http://torsher:8080")

    def test_replaces_only_docker_provider_flags(self):
        self.assertEqual(
            startup_flags(["--api.dashboard=false", "--providers.docker=true",
                           "--providers.docker.exposedbydefault=false"]),
            ["--api.dashboard=false", "--providers.file.directory=/conf",
             "--providers.file.watch=true"],
        )
