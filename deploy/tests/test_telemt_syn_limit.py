from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class TelemtSynLimitDeployTests(unittest.TestCase):
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

    def test_main_deploy_runs_limiter_after_docker_on_one_host_at_a_time(self) -> None:
        playbook = (ROOT / "playbook.yml").read_text()
        result = self.ansible("playbook.yml", "--list-tasks")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("serial: 1", playbook)
        self.assertIn("any_errors_fatal: true", playbook)
        self.assertIn("Start containers", result.stdout)
        self.assertIn("Install Telemt SYN limiter", result.stdout)
        self.assertLess(
            result.stdout.index("Start containers"),
            result.stdout.index("Install Telemt SYN limiter"),
        )

    def test_limiter_only_and_rollback_playbooks_are_valid_serial_rollouts(self) -> None:
        for name in ("telemt-syn-limit.yml", "telemt-syn-limit-rollback.yml"):
            playbook = (ROOT / name).read_text()
            result = self.ansible(name, "--syntax-check")

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("hosts: mtproto_servers", playbook)
            self.assertIn("serial: 1", playbook)
            self.assertIn("any_errors_fatal: true", playbook)

        rollback = (ROOT / "telemt-syn-limit-rollback.yml").read_text()
        self.assertIn("telemt-syn-limit.service", rollback)
        self.assertIn("state: stopped", rollback)
        self.assertIn("enabled: false", rollback)

    def test_firewall_script_applies_idempotently_and_removes_its_jump(self) -> None:
        script = ROOT / "roles" / "telemt_syn_limit" / "files" / "telemt-syn-limit"

        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            fake_iptables = temp / "iptables"
            log = temp / "iptables.log"
            jump_state = temp / "jump-present"
            chain_state = temp / "chain-present"
            rules_state = temp / "chain-rules"
            fake_iptables.write_text(
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
            if [[ -f "$IPTABLES_JUMP_STATE" ]]; then
                while IFS= read -r rule; do
                    [[ -n "$rule" ]] && printf '%s\\n' "-A DOCKER-USER $rule"
                done < "$IPTABLES_JUMP_STATE"
            fi
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
        [[ "$chain" == "DOCKER-USER" ]]
        grep -Fxq -- "$rule" "$IPTABLES_JUMP_STATE"
        awk -v target="$rule" '
            BEGIN { removed = 0 }
            !removed && $0 == target { removed = 1; next }
            { print }
        ' "$IPTABLES_JUMP_STATE" > "$IPTABLES_JUMP_STATE.tmp"
        mv "$IPTABLES_JUMP_STATE.tmp" "$IPTABLES_JUMP_STATE"
        ;;
    -N)
        if [[ -f "$IPTABLES_CHAIN_STATE" ]]; then
            exit 1
        fi
        touch "$IPTABLES_CHAIN_STATE"
        : > "$IPTABLES_RULES_STATE"
        ;;
    -F)
        [[ -f "$IPTABLES_CHAIN_STATE" ]]
        : > "$IPTABLES_RULES_STATE"
        ;;
    -X)
        [[ -f "$IPTABLES_CHAIN_STATE" ]]
        if grep -q -- '-j TELEMT_SYN_LIMIT' "$IPTABLES_JUMP_STATE" 2>/dev/null; then
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
            fake_iptables.chmod(0o755)

            env = os.environ.copy()
            env["PATH"] = f"{temp}:{env['PATH']}"
            env["IPTABLES_LOG"] = str(log)
            env["IPTABLES_JUMP_STATE"] = str(jump_state)
            env["IPTABLES_CHAIN_STATE"] = str(chain_state)
            env["IPTABLES_RULES_STATE"] = str(rules_state)
            env["TELEMT_SYN_INTERFACE"] = "eth0"

            for _ in range(2):
                result = subprocess.run(
                    ["bash", str(script), "start"],
                    env=env,
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(
                    result.returncode,
                    0,
                    f"{result.stderr}\niptables calls:\n{log.read_text()}",
                )
                self.assertTrue(jump_state.exists())

            env["TELEMT_SYN_INTERFACE"] = "eth1"
            env["TELEMT_SYN_PORT"] = "8443"
            result = subprocess.run(
                ["bash", str(script), "start"],
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                jump_state.read_text().splitlines(),
                ["-i eth1 -p tcp --dport 8443 --syn -j TELEMT_SYN_LIMIT"],
            )

            result = subprocess.run(
                ["bash", str(script), "check"],
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

            with jump_state.open("a") as state:
                state.write(
                    "-i eth1 -p tcp --dport 8443 --syn -j TELEMT_SYN_LIMIT\n"
                )
            result = subprocess.run(
                ["bash", str(script), "check"],
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)

            result = subprocess.run(
                ["bash", str(script), "start"],
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            with rules_state.open("a") as state:
                state.write("-p tcp --dport 22 -j RETURN\n")
            result = subprocess.run(
                ["bash", str(script), "check"],
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)

            result = subprocess.run(
                ["bash", str(script), "start"],
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

            jump_state.unlink()
            chain_state.unlink()
            rules_state.unlink()
            result = subprocess.run(
                ["bash", str(script), "check"],
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)

            result = subprocess.run(
                ["bash", str(script), "start"],
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

            result = subprocess.run(
                ["bash", str(script), "stop"],
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(jump_state.exists() and jump_state.read_text().strip())

            calls = log.read_text()
            self.assertIn("-w -nL DOCKER-USER", calls)
            self.assertIn("--hashlimit-mode srcip", calls)
            self.assertIn("--hashlimit-upto 54/minute", calls)
            self.assertIn("--hashlimit-burst 5", calls)
            self.assertIn("-j REJECT --reject-with tcp-reset", calls)
            self.assertIn("-I DOCKER-USER 1 -i eth0 -p tcp --dport 443 --syn", calls)
            self.assertIn("-D DOCKER-USER -i eth0 -p tcp --dport 443 --syn", calls)

    def test_role_reapplies_missing_firewall_state(self) -> None:
        tasks = (
            ROOT / "roles" / "telemt_syn_limit" / "tasks" / "main.yml"
        ).read_text()

        self.assertIn("Check Telemt SYN limiter rules", tasks)
        self.assertIn("telemt_syn_limit_rules.rc", tasks)
        self.assertIn("TELEMT_SYN_INTERFACE", tasks)
        self.assertIn("TELEMT_SYN_PORT", tasks)
        self.assertIn("TELEMT_SYN_RATE", tasks)
        self.assertIn("TELEMT_SYN_BURST", tasks)
        self.assertIn("telemt_syn_limit_script.changed", tasks)
        self.assertIn("telemt_syn_limit_unit.changed", tasks)
        self.assertIn("'restarted' if", tasks)
        self.assertIn("else 'started'", tasks)
        self.assertNotIn("notify:", tasks)


if __name__ == "__main__":
    unittest.main()
