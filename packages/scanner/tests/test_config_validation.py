# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""The scanner's YAML surface validated nothing.

Every key was read with `.get()` and a default, and unknown keys were ignored. So
`concurrancy: 200` was accepted and the scan ran at the default 20 — no error, no
warning, and the operator believing they had changed something.

That matters more than an ordinary config typo because these values govern how
hard this platform touches third-party infrastructure. `concurrency` and
`max_hosts` are the two settings an operator reaches for after a customer
complains about scan load, and both could be silently ignored. It is also a
striking asymmetry: the same project refuses to boot the API over a weak secret
and accepted anything at all here.
"""

from __future__ import annotations

import textwrap

import pytest
import yaml

from nis2scan.config import Config


@pytest.fixture
def write(tmp_path):
    def _write(body: str) -> str:
        path = tmp_path / "config.yaml"
        path.write_text(textwrap.dedent(body))
        return str(path)

    return _write


VALID = """
    project_name: Acme
    targets:
      domains: [example.it]
    concurrency: 30
    scan_timeout: 15
"""


class TestAValidFileStillLoads:
    def test_it_loads(self, write):
        cfg = Config.load(write(VALID))
        assert cfg.project_name == "Acme"
        assert cfg.concurrency == 30
        assert cfg.targets.domains == ["example.it"]

    def test_defaults_still_apply_to_absent_keys(self, write):
        cfg = Config.load(write("targets:\n  domains: [example.it]\n"))
        assert cfg.concurrency == 20
        assert cfg.scan_timeout == 10


class TestATypoIsAnError:
    def test_a_misspelled_key_is_refused(self, write):
        """The defect in one assertion: this used to run at the default 20."""
        with pytest.raises(ValueError, match="concurrancy"):
            Config.load(write("targets:\n  domains: [x.it]\nconcurrancy: 200\n"))

    def test_the_error_lists_what_is_accepted(self, write):
        with pytest.raises(ValueError, match="Known keys"):
            Config.load(write("targets:\n  domains: [x.it]\nnonsense: 1\n"))

    def test_a_misspelled_target_key_is_refused(self, write):
        """`domain:` instead of `domains:` produced a scan with no targets."""
        with pytest.raises(ValueError, match="targets has unrecognised"):
            Config.load(write("targets:\n  domain: [x.it]\n"))


class TestBoundsMatchTheApi:
    @pytest.mark.parametrize(
        "body,needle",
        [
            ("targets:\n  domains: [x.it]\nconcurrency: 0\n", "between 1 and 200"),
            ("targets:\n  domains: [x.it]\nconcurrency: 500\n", "between 1 and 200"),
            ("targets:\n  domains: [x.it]\nscan_timeout: 0\n", "between 1 and 120"),
            ("targets:\n  domains: [x.it]\nmax_hosts: -1\n", "between 0 and 100000"),
        ],
    )
    def test_out_of_range_is_refused(self, write, body: str, needle: str):
        """A config file must not be able to ask for something the HTTP surface
        would have rejected."""
        with pytest.raises(ValueError, match=needle):
            Config.load(write(body))

    def test_a_non_integer_is_refused(self, write):
        with pytest.raises(ValueError, match="must be an integer"):
            Config.load(write("targets:\n  domains: [x.it]\nconcurrency: fast\n"))

    def test_a_boolean_is_not_an_integer(self, write):
        """`concurrency: true` is 1 to Python and a mistake to everyone else."""
        with pytest.raises(ValueError, match="must be an integer"):
            Config.load(write("targets:\n  domains: [x.it]\nconcurrency: true\n"))


class TestMalformedFiles:
    def test_an_empty_file_is_refused(self, write):
        with pytest.raises(ValueError, match="empty"):
            Config.load(write("\n"))

    def test_a_non_mapping_is_refused(self, write):
        with pytest.raises(ValueError, match="mapping"):
            Config.load(write("- just\n- a\n- list\n"))

    def test_what_the_init_wizard_writes_loads(self, write):
        """`nis2scan init` writes this shape. If the validator rejects any of its
        keys, the tool fails on its own output the first time it is used — which
        is the way a validation change most easily breaks a user."""
        generated = {
            "project_name": "NIS2 Compliance Audit",
            "scan_timeout": 10,
            "concurrency": 50,
            "max_hosts": 100,
            "targets": {"ip_ranges": ["192.168.1.0/24"], "domains": ["example.it"], "asns": []},
            "features": {
                "dns_checks": True,
                "web_checks": True,
                "port_scan": True,
                "whois_checks": True,
            },
            "compliance_profile": "standard_nis2",
        }
        cfg = Config.load(write(yaml.safe_dump(generated)))
        assert cfg.concurrency == 50
        assert cfg.max_hosts == 100
        assert cfg.compliance_profile == "standard_nis2"
