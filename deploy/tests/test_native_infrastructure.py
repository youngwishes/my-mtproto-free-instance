from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import tomllib
import unittest

DEPLOY_DIR = Path(__file__).resolve().parents[1]
ROLE_DIR = DEPLOY_DIR / "roles" / "telemt_native"


def run_command(*command: str) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as temp_dir:
        env = os.environ.copy()
        env["ANSIBLE_LOCAL_TEMP"] = temp_dir
        env["ANSIBLE_REMOTE_TEMP"] = temp_dir
        return subprocess.run(
            command,
            cwd=DEPLOY_DIR,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )


class NativeInfrastructureTests(unittest.TestCase):
    def test_inventory_does_not_target_the_deleted_server(self) -> None:
        result = run_command(
            "ansible-inventory",
            "-i",
            str(DEPLOY_DIR / "inventory.ini"),
            "--list",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        inventory = json.loads(result.stdout)
        self.assertIn("telemt_servers", inventory)
        hosts = inventory["telemt_servers"]["hosts"]
        self.assertEqual(hosts, ["telemt1"])
        hostvars = inventory["_meta"]["hostvars"]["telemt1"]
        self.assertEqual(hostvars["ansible_host"], "REPLACE_WITH_NEW_SERVER_IP")
        self.assertEqual(hostvars["ansible_user"], "root")

    def test_inventory_provides_one_encrypted_shared_secret(self) -> None:
        result = run_command(
            "ansible-inventory",
            "-i",
            "node1,node2,",
            "--list",
            "--extra-vars",
            "@group_vars/all/vault.yml",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        inventory = json.loads(result.stdout)
        hostvars = inventory["_meta"]["hostvars"]
        self.assertEqual(set(hostvars), {"node1", "node2"})
        vaulted_values = {
            json.dumps(variables.get("vault_telemt_secret"), sort_keys=True)
            for variables in hostvars.values()
        }
        self.assertEqual(len(vaulted_values), 1)
        self.assertIn("__ansible_vault", vaulted_values.pop())

        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            secret_file = temp / "secret"
            decrypt_playbook = temp / "decrypt-vault.yml"
            decrypt_playbook.write_text(
                "---\n"
                "- name: Verify the shared Telemt secret\n"
                "  hosts: localhost\n"
                "  connection: local\n"
                "  gather_facts: false\n"
                "  vars_files:\n"
                f"    - {DEPLOY_DIR / 'group_vars' / 'all' / 'vault.yml'}\n"
                "  tasks:\n"
                "    - name: Validate the decrypted secret\n"
                "      ansible.builtin.assert:\n"
                "        that:\n"
                "          - vault_telemt_secret is match('^[0-9a-f]{32}$')\n"
                "      no_log: true\n"
                "    - name: Expose the secret only inside the temporary test directory\n"
                "      ansible.builtin.copy:\n"
                "        content: '{{ vault_telemt_secret }}'\n"
                f"        dest: {secret_file}\n"
                "        mode: '0600'\n"
                "      no_log: true\n"
            )
            decrypted = run_command(
                "ansible-playbook",
                "-i",
                "localhost,",
                str(decrypt_playbook),
            )
            self.assertEqual(decrypted.returncode, 0, decrypted.stderr)
            secret = secret_file.read_text()
            self.assertIsNotNone(re.fullmatch(r"[0-9a-f]{32}", secret))

            tracked = run_command(
                "git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"
            )
            self.assertEqual(tracked.returncode, 0, tracked.stderr)
            for relative_path in tracked.stdout.split("\0"):
                if not relative_path:
                    continue
                candidate = DEPLOY_DIR / relative_path
                if not candidate.is_file():
                    continue
                contents = candidate.read_bytes()
                if secret.encode() in contents:
                    self.fail(f"plaintext Telemt secret found in {relative_path}")

    def test_native_playbook_has_valid_ansible_syntax(self) -> None:
        result = run_command(
            "ansible-playbook",
            "-i",
            str(DEPLOY_DIR / "inventory.ini"),
            str(DEPLOY_DIR / "playbook.yml"),
            "--syntax-check",
        )

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rendered_config_is_self_masked_and_uses_builtin_synlimit(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            destination = temp / "telemt.toml"
            renderer = temp / "render.py"
            renderer.write_text(
                "from pathlib import Path\n"
                "import sys\n"
                "from jinja2 import Environment, FileSystemLoader, StrictUndefined\n"
                "template_path = Path(sys.argv[1])\n"
                "environment = Environment(\n"
                "    loader=FileSystemLoader(template_path.parent),\n"
                "    undefined=StrictUndefined,\n"
                "    autoescape=False,\n"
                ")\n"
                "rendered = environment.get_template(template_path.name).render(\n"
                "    telemt_domain='www.example.com',\n"
                "    telemt_secret='0123456789abcdef0123456789abcdef',\n"
                "    telemt_ad_tag='',\n"
                "    telemt_state_dir='/var/lib/telemt',\n"
                ")\n"
                "Path(sys.argv[2]).write_text(rendered)\n"
            )
            ansible_playbook = Path(shutil.which("ansible-playbook") or "")
            ansible_python = ansible_playbook.read_text().splitlines()[0][2:]
            result = subprocess.run(
                [
                    ansible_python,
                    str(renderer),
                    str(ROLE_DIR / "templates" / "telemt.toml.j2"),
                    str(destination),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            rendered = destination.read_text()

        config = tomllib.loads(rendered)

        self.assertEqual(
            config["general"]["links"]["public_host"], "www.example.com"
        )
        self.assertEqual(config["censorship"]["tls_domain"], "www.example.com")
        self.assertEqual(config["censorship"]["mask_host"], "127.0.0.1")
        self.assertEqual(config["censorship"]["mask_port"], 8443)
        self.assertEqual(config["censorship"]["unknown_sni_action"], "mask")

        listener = config["server"]["listeners"][0]
        self.assertEqual(config["server"].get("client_mss_bulk"), "1400")
        self.assertEqual(listener["ip"], "0.0.0.0")
        self.assertEqual(listener["synlimit"], "nftables")
        self.assertEqual(listener["synlimit_seconds"], 1)
        self.assertEqual(listener["synlimit_hitcount"], 12)
        self.assertEqual(listener["synlimit_burst"], 24)
        self.assertEqual(listener["client_mss"], "tspu")

        self.assertEqual(
            config["access"]["users"]["free"],
            "0123456789abcdef0123456789abcdef",
        )


if __name__ == "__main__":
    unittest.main()
