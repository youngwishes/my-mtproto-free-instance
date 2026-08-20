from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]


class TelemtGeoAllowTests(unittest.TestCase):
    def ansible(self, playbook: str, *args: str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as temp_dir:
            env = os.environ.copy()
            env["ANSIBLE_LOCAL_TEMP"] = temp_dir
            env["ANSIBLE_REMOTE_TEMP"] = temp_dir
            return subprocess.run(
                [
                    "ansible-playbook",
                    "-i",
                    str(ROOT / "inventory.ini"),
                    str(ROOT / playbook),
                    *args,
                ],
                cwd=ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )

    def write_fake_ipset(self, path: Path) -> None:
        path.write_text(
            textwrap.dedent(
                """#!/usr/bin/env bash
                set -euo pipefail
                state_dir="$IPSET_STATE_DIR"
                mkdir -p "$state_dir"
                command_name="${1:-}"
                set_name="${2:-}"

                if [[ "${IPSET_FAIL_COMMAND:-}" == "$command_name" ]]; then
                    exit 70
                fi

                case "$command_name" in
                    create)
                        if [[ -e "$state_dir/$set_name" && " $* " != *" -exist "* ]]; then
                            exit 1
                        fi
                        touch "$state_dir/$set_name"
                        ;;
                    destroy)
                        [[ -e "$state_dir/$set_name" ]]
                        rm -f "$state_dir/$set_name"
                        ;;
                    restore)
                        while read -r operation target entry; do
                            [[ "$operation" == "add" && "$entry" == */* ]]
                            [[ -e "$state_dir/$target" ]]
                            printf '%s\\n' "$entry" >> "$state_dir/$target"
                        done
                        ;;
                    swap)
                        other="${3:-}"
                        [[ -e "$state_dir/$set_name" && -e "$state_dir/$other" ]]
                        mv "$state_dir/$set_name" "$state_dir/.swap"
                        mv "$state_dir/$other" "$state_dir/$set_name"
                        mv "$state_dir/.swap" "$state_dir/$other"
                        ;;
                    list)
                        [[ -e "$state_dir/$set_name" ]]
                        count=$(wc -l < "$state_dir/$set_name" | tr -d ' ')
                        printf 'Name: %s\\nNumber of entries: %s\\nMembers:\\n' "$set_name" "$count"
                        cat "$state_dir/$set_name"
                        ;;
                    *)
                        exit 2
                        ;;
                esac
                """
            )
        )
        path.chmod(0o755)

    def write_fake_iptables(self, path: Path) -> None:
        path.write_text(
            textwrap.dedent(
                """#!/usr/bin/env bash
                set -euo pipefail
                printf '%s\\n' "$*" >> "$IPTABLES_LOG"
                op="${2:-}"
                chain="${3:-}"

                case "$op" in
                    -nL)
                        [[ "$chain" == "DOCKER-USER" ]]
                        ;;
                    -S)
                        if [[ "$chain" == "DOCKER-USER" ]]; then
                            printf '%s\\n' '-N DOCKER-USER'
                            if [[ -f "$IPTABLES_JUMP_STATE" ]]; then
                                while IFS= read -r rule; do
                                    [[ -n "$rule" ]] && printf '%s\\n' "-A DOCKER-USER $rule"
                                done < "$IPTABLES_JUMP_STATE"
                            fi
                            printf '%s\\n' '-A DOCKER-USER -j RETURN'
                        else
                            [[ -f "$IPTABLES_CHAIN_STATE" ]]
                            while IFS= read -r rule; do
                                [[ -n "$rule" ]] && printf '%s\\n' "-A $chain $rule"
                            done < "$IPTABLES_RULES_STATE"
                        fi
                        ;;
                    -C)
                        shift 3
                        rule="$*"
                        if [[ "$chain" == "DOCKER-USER" ]]; then
                            [[ -f "$IPTABLES_JUMP_STATE" ]] && grep -Fxq -- "$rule" "$IPTABLES_JUMP_STATE"
                        else
                            [[ -f "$IPTABLES_CHAIN_STATE" ]] && grep -Fxq -- "$rule" "$IPTABLES_RULES_STATE"
                        fi
                        ;;
                    -D)
                        shift 3
                        rule="$*"
                        grep -Fxq -- "$rule" "$IPTABLES_JUMP_STATE"
                        awk -v target="$rule" '
                            BEGIN { removed = 0 }
                            !removed && $0 == target { removed = 1; next }
                            { print }
                        ' "$IPTABLES_JUMP_STATE" > "$IPTABLES_JUMP_STATE.tmp"
                        mv "$IPTABLES_JUMP_STATE.tmp" "$IPTABLES_JUMP_STATE"
                        ;;
                    -N)
                        [[ ! -f "$IPTABLES_CHAIN_STATE" ]]
                        touch "$IPTABLES_CHAIN_STATE"
                        : > "$IPTABLES_RULES_STATE"
                        ;;
                    -F)
                        [[ -f "$IPTABLES_CHAIN_STATE" ]]
                        : > "$IPTABLES_RULES_STATE"
                        ;;
                    -X)
                        [[ -f "$IPTABLES_CHAIN_STATE" ]]
                        if grep -q -- '-j TELEMT_GEO_ALLOW' "$IPTABLES_JUMP_STATE" 2>/dev/null; then
                            exit 1
                        fi
                        rm -f "$IPTABLES_CHAIN_STATE" "$IPTABLES_RULES_STATE"
                        ;;
                    -A)
                        [[ -f "$IPTABLES_CHAIN_STATE" ]]
                        shift 3
                        printf '%s\\n' "$*" >> "$IPTABLES_RULES_STATE"
                        ;;
                    -I)
                        [[ "$chain" == "DOCKER-USER" && "${4:-}" == "1" ]]
                        shift 4
                        printf '%s\\n' "$*" >> "$IPTABLES_JUMP_STATE"
                        ;;
                    *)
                        exit 2
                        ;;
                esac
                """
            )
        )
        path.chmod(0o755)

    def test_extractor_keeps_only_russian_ipv4_networks(self) -> None:
        script = (
            ROOT / "roles" / "telemt_geo_allow" / "files" / "telemt-geo-extract"
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            (temp / "maxminddb.py").write_text(
                textwrap.dedent(
                    """
                    import ipaddress


                    class Reader:
                        def __enter__(self):
                            return self

                        def __exit__(self, *args):
                            return False

                        def __iter__(self):
                            yield ipaddress.ip_network("5.8.0.0/24"), {
                                "country": {"iso_code": "RU"},
                                "registered_country": {"iso_code": "RU"},
                            }
                            yield ipaddress.ip_network("31.13.24.0/24"), {
                                "registered_country": {"iso_code": "RU"},
                            }
                            yield ipaddress.ip_network("8.8.8.0/24"), {
                                "country": {"iso_code": "US"},
                                "registered_country": {"iso_code": "US"},
                            }
                            yield ipaddress.ip_network("2a00:1450::/32"), {
                                "country": {"iso_code": "RU"},
                            }


                    def open_database(_path):
                        return Reader()
                    """
                )
            )
            output = temp / "ru-ipv4.cidr"
            env = os.environ.copy()
            env["PYTHONPATH"] = str(temp)

            result = subprocess.run(
                [
                    "python3",
                    str(script),
                    str(temp / "GeoLite2-Country.mmdb"),
                    str(output),
                    "RU",
                    "2",
                ],
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                output.read_text().splitlines(),
                ["5.8.0.0/24", "31.13.24.0/24"],
            )

    def test_extractor_does_not_replace_cache_with_too_few_networks(self) -> None:
        script = (
            ROOT / "roles" / "telemt_geo_allow" / "files" / "telemt-geo-extract"
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            (temp / "maxminddb.py").write_text(
                textwrap.dedent(
                    """
                    import ipaddress


                    class Reader:
                        def __enter__(self):
                            return self

                        def __exit__(self, *args):
                            return False

                        def __iter__(self):
                            yield ipaddress.ip_network("5.8.0.0/24"), {
                                "country": {"iso_code": "RU"},
                            }


                    def open_database(_path):
                        return Reader()
                    """
                )
            )
            output = temp / "ru-ipv4.cidr"
            output.write_text("previous-cache\n")
            env = os.environ.copy()
            env["PYTHONPATH"] = str(temp)

            result = subprocess.run(
                [
                    "python3",
                    str(script),
                    str(temp / "GeoLite2-Country.mmdb"),
                    str(output),
                    "RU",
                    "2",
                ],
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(output.read_text(), "previous-cache\n")

    def test_firewall_is_fail_closed_and_rejects_bad_set_updates(self) -> None:
        script = (
            ROOT / "roles" / "telemt_geo_allow" / "files" / "telemt-geo-allow"
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            self.write_fake_ipset(temp / "ipset")
            self.write_fake_iptables(temp / "iptables")
            set_state = temp / "ipsets"
            jump_state = temp / "jump-state"
            chain_state = temp / "chain-state"
            rules_state = temp / "chain-rules"
            cache = temp / "ru-ipv4.cidr"
            env = os.environ.copy()
            env.update(
                {
                    "PATH": f"{temp}:{env['PATH']}",
                    "IPSET_STATE_DIR": str(set_state),
                    "IPTABLES_LOG": str(temp / "iptables.log"),
                    "IPTABLES_JUMP_STATE": str(jump_state),
                    "IPTABLES_CHAIN_STATE": str(chain_state),
                    "IPTABLES_RULES_STATE": str(rules_state),
                    "TELEMT_GEO_INTERFACE": "eth0",
                    "TELEMT_GEO_PORT": "443",
                    "TELEMT_GEO_SET": "telemt_ru_ipv4",
                    "TELEMT_GEO_CIDR_FILE": str(cache),
                    "TELEMT_GEO_MIN_NETWORKS": "2",
                }
            )

            result = subprocess.run(
                ["bash", str(script), "start"],
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((set_state / "telemt_ru_ipv4").read_text(), "")
            self.assertEqual(
                rules_state.read_text().splitlines(),
                [
                    "-m set --match-set telemt_ru_ipv4 src -j RETURN",
                    "-p tcp -j REJECT --reject-with tcp-reset",
                ],
            )
            self.assertEqual(
                jump_state.read_text().splitlines(),
                ["-i eth0 -p tcp --dport 443 --syn -j TELEMT_GEO_ALLOW"],
            )

            result = subprocess.run(
                ["bash", str(script), "check"],
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)

            valid = temp / "valid.cidr"
            valid.write_text("5.8.0.0/24\n31.13.24.0/24\n")
            result = subprocess.run(
                ["bash", str(script), "load", str(valid)],
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            expected = "5.8.0.0/24\n31.13.24.0/24\n"
            self.assertEqual((set_state / "telemt_ru_ipv4").read_text(), expected)

            result = subprocess.run(
                ["bash", str(script), "check"],
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

            replacement = temp / "replacement.cidr"
            replacement.write_text("46.17.40.0/24\n77.88.0.0/18\n")
            failed_env = env.copy()
            failed_env["IPSET_FAIL_COMMAND"] = "swap"
            result = subprocess.run(
                ["bash", str(script), "load", str(replacement)],
                env=failed_env,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((set_state / "telemt_ru_ipv4").read_text(), expected)

            cleanup_failed_env = env.copy()
            cleanup_failed_env["IPSET_FAIL_COMMAND"] = "destroy"
            result = subprocess.run(
                ["bash", str(script), "load", str(replacement)],
                env=cleanup_failed_env,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            expected = "46.17.40.0/24\n77.88.0.0/18\n"
            self.assertEqual((set_state / "telemt_ru_ipv4").read_text(), expected)

            invalid = temp / "too-small.cidr"
            invalid.write_text("192.0.2.0/24\n")
            result = subprocess.run(
                ["bash", str(script), "load", str(invalid)],
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((set_state / "telemt_ru_ipv4").read_text(), expected)

            log = temp / "iptables.log"
            previous_call_count = len(log.read_text().splitlines())
            result = subprocess.run(
                ["bash", str(script), "start"],
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            restart_calls = log.read_text().splitlines()[previous_call_count:]
            guard = (
                "-w -I DOCKER-USER 1 -i eth0 -p tcp --dport 443 --syn "
                "-m comment --comment telemt-geo-fail-closed "
                "-j REJECT --reject-with tcp-reset"
            )
            geo_delete = (
                "-w -D DOCKER-USER -i eth0 -p tcp --dport 443 --syn "
                "-j TELEMT_GEO_ALLOW"
            )
            self.assertIn(guard, restart_calls)
            self.assertIn(geo_delete, restart_calls)
            self.assertLess(restart_calls.index(guard), restart_calls.index(geo_delete))

            result = subprocess.run(
                ["bash", str(script), "stop"],
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(set_state.joinpath("telemt_ru_ipv4").exists())
            self.assertFalse(jump_state.read_text().strip())

    def test_main_deploy_installs_geo_allow_before_syn_limit(self) -> None:
        result = self.ansible("playbook.yml", "--list-tasks")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Start containers", result.stdout)
        self.assertIn("Install Telemt GeoIP allowlist", result.stdout)
        self.assertIn("Install Telemt SYN limiter", result.stdout)
        self.assertLess(
            result.stdout.index("Start containers"),
            result.stdout.index("Install Telemt GeoIP allowlist"),
        )
        self.assertLess(
            result.stdout.index("Install Telemt GeoIP allowlist"),
            result.stdout.index("Install Telemt SYN limiter"),
        )

    def test_geo_only_rollout_enables_fail_closed_before_download(self) -> None:
        result = self.ansible("telemt-geo-allow.yml", "--list-tasks")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Enable fail-closed Telemt GeoIP allowlist", result.stdout)
        self.assertIn("Download GeoLite2 Country database", result.stdout)
        self.assertIn("Load Russian IPv4 allowlist", result.stdout)
        self.assertLess(
            result.stdout.index("Enable fail-closed Telemt GeoIP allowlist"),
            result.stdout.index("Download GeoLite2 Country database"),
        )
        self.assertLess(
            result.stdout.index("Download GeoLite2 Country database"),
            result.stdout.index("Load Russian IPv4 allowlist"),
        )

    def test_geo_only_and_rollback_playbooks_are_valid_serial_rollouts(self) -> None:
        for name in ("telemt-geo-allow.yml", "telemt-geo-allow-rollback.yml"):
            playbook = (ROOT / name).read_text()
            result = self.ansible(name, "--syntax-check")

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("hosts: mtproto_servers", playbook)
            self.assertIn("serial: 1", playbook)
            self.assertIn("any_errors_fatal: true", playbook)

        rollback_result = self.ansible(
            "telemt-geo-allow-rollback.yml", "--list-tasks"
        )
        self.assertEqual(rollback_result.returncode, 0, rollback_result.stderr)
        self.assertIn("Remove Telemt GeoIP firewall state", rollback_result.stdout)
        self.assertIn("Stop and disable Telemt GeoIP allowlist", rollback_result.stdout)
        self.assertLess(
            rollback_result.stdout.index("Remove Telemt GeoIP firewall state"),
            rollback_result.stdout.index("Stop and disable Telemt GeoIP allowlist"),
        )

    def test_role_uses_pinned_reader_with_database_iteration_support(self) -> None:
        tasks = (
            ROOT / "roles" / "telemt_geo_allow" / "tasks" / "main.yml"
        ).read_text()

        self.assertIn("maxminddb==", tasks)
        self.assertIn("/opt/telemt-geo-allow/venv/bin/python", tasks)
        self.assertNotIn("python3-maxminddb", tasks)

    def test_syn_limiter_is_ordered_after_geo_allow(self) -> None:
        syn_script = (
            ROOT / "roles" / "telemt_syn_limit" / "files" / "telemt-syn-limit"
        )
        syn_unit = (
            ROOT
            / "roles"
            / "telemt_syn_limit"
            / "templates"
            / "telemt-syn-limit.service.j2"
        ).read_text()

        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            log = temp / "iptables.log"
            fake_iptables = temp / "iptables"
            fake_iptables.write_text(
                textwrap.dedent(
                    """#!/usr/bin/env bash
                    set -euo pipefail
                    printf '%s\\n' "$*" >> "$IPTABLES_LOG"
                    if [[ "${2:-}" == "-S" && "${3:-}" == "DOCKER-USER" ]]; then
                        printf '%s\\n' '-N DOCKER-USER'
                        printf '%s\\n' '-A DOCKER-USER -i eth0 -p tcp --dport 443 --syn -j TELEMT_GEO_ALLOW'
                        printf '%s\\n' '-A DOCKER-USER -j RETURN'
                    elif [[ "${2:-}" == "-F" || "${2:-}" == "-X" ]]; then
                        exit 1
                    fi
                    """
                )
            )
            fake_iptables.chmod(0o755)
            env = os.environ.copy()
            env["PATH"] = f"{temp}:{env['PATH']}"
            env["IPTABLES_LOG"] = str(log)
            env["TELEMT_SYN_INTERFACE"] = "eth0"

            result = subprocess.run(
                ["bash", str(syn_script), "start"],
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(
                "-w -I DOCKER-USER 2 -i eth0 -p tcp --dport 443 --syn "
                "-j TELEMT_SYN_LIMIT",
                log.read_text(),
            )
            self.assertIn("telemt-geo-allow.service", syn_unit)


if __name__ == "__main__":
    unittest.main()
