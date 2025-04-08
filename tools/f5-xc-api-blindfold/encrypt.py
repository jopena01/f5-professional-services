import os
import subprocess
import base64
import binascii
import yaml
import json
import getpass
import shutil
import tempfile
import tkinter as tk
from tkinter import filedialog

# ----------------------------------------------------------------------
# File names:
# ----------------------------------------------------------------------
SECRETS_YAML = "secrets.yaml"
PUBLIC_KEY_PEM = "pubkey.pem"
BLINDFOLDED_JSON = "blindfolded-secret.json"
POLICY_JSON = "policy.json"

# ----------------------------------------------------------------------
# 1) Decode base64
# ----------------------------------------------------------------------
def decode_b64(encoded_str):
    """
    Safely decode a base64-encoded UTF-8 string.
    
    :param encoded_str: The string that should be decoded from base64.
    :return: Decoded UTF-8 string, or None if invalid.
    """
    try:
        decoded_bytes = base64.b64decode(encoded_str.encode("utf-8"))
        return decoded_bytes.decode("utf-8")  # ASCII/UTF-8 decoding
    except (binascii.Error, UnicodeDecodeError):
        # Malformed base64 or non‐UTF‐8 content
        print(f"❌ Not valid base64/UTF-8: '{encoded_str[:20]}...'")
        return None

# ----------------------------------------------------------------------
# 2) Prompt user for .p12 path (Tkinter file dialog)
# ----------------------------------------------------------------------
def select_p12_file():
    """
    Prompts the user with a file dialog to pick a .p12 file.
    Loops until a valid file is selected or user cancels.

    :return: The path to the selected .p12 file (str), or None if canceled.
    """
    root = tk.Tk()
    root.withdraw()

    while True:
        print("📁 A file dialog has opened. Please select your .p12 file.")
        file_path = filedialog.askopenfilename(
            title="Select your F5 XC .p12 credential file",
            filetypes=[("PKCS12 Files", "*.p12"), ("All Files", "*.*")]
        )
        if not file_path:
            print("No file selected. Press CTRL+C to quit or try again...\n")
            continue
        if not file_path.lower().endswith(".p12"):
            print(f"❌ The selected file '{file_path}' is not a .p12. Try again.\n")
            continue
        if not os.path.exists(file_path):
            print(f"❌ File not found: {file_path}\n")
            continue

        root.destroy()
        return file_path

# ----------------------------------------------------------------------
# 3) Fetch fresh pubkey.pem with vesctl, using .p12 credentials
# ----------------------------------------------------------------------
def fetch_public_key(p12_path, p12_password):
    """
    Run vesctl to retrieve the public key and overwrite pubkey.pem.
    Ensures vesctl sees the provided .p12 bundle and password.

    :param p12_path: The path to the .p12 file (str)
    :param p12_password: The .p12 password (str)
    :return: True if success; False otherwise.
    """
    os.environ["VES_P12_PASSWORD"] = p12_password
    print(f"⏳ Fetching fresh public key -> {PUBLIC_KEY_PEM} ...")
    try:
        proc = subprocess.run(
            [
                "vesctl", "request", "secrets", "get-public-key",
                "--p12-bundle", p12_path
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        with open(PUBLIC_KEY_PEM, "w", encoding="utf-8") as f:
            f.write(proc.stdout)
        print(f"✅ Wrote new public key to {PUBLIC_KEY_PEM}\n")
        return True
    except subprocess.CalledProcessError as e:
        print("❌ Failed to fetch public key.\n")
        print("VESCTL stderr:", e.stderr)
        return False

# ----------------------------------------------------------------------
# 4) Fetch fresh policy.json with vesctl
# ----------------------------------------------------------------------
def fetch_policy_document(p12_path, namespace, name, p12_password):
    """
    Calls `vesctl request secrets get-policy-document` to fetch a fresh policy.json.
    If the .p12 password is wrong, show a short message and return False.

    :param p12_path: Path to the .p12 file (str)
    :param namespace: Namespace to request the policy from (str)
    :param name: Name of the policy (str)
    :param p12_password: .p12 password (str)
    :return: True if successful; False otherwise.
    """
    # Ensure environment var so vesctl sees it
    os.environ["VES_P12_PASSWORD"] = p12_password

    print(f"⏳ Fetching fresh policy document -> {POLICY_JSON} ...")
    try:
        proc = subprocess.run(
            [
                "vesctl", "request", "secrets", "get-policy-document",
                "--namespace", namespace,
                "--name", name,
                "--p12-bundle", p12_path
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        with open(POLICY_JSON, "w", encoding="utf-8") as f:
            f.write(proc.stdout)
        print(f"✅ Wrote new policy document to {POLICY_JSON}\n")
        return True
    except subprocess.CalledProcessError as e:
        stderr_lower = e.stderr.lower()
        if "pkcs12: decryption password incorrect" in stderr_lower:
            print("❌ The provided .p12 password is incorrect. Please re-run and try again.\n")
        else:
            print("❌ Failed to fetch policy document (vesctl error).")
            print("VESCTL stderr:", e.stderr)
        return False

# ----------------------------------------------------------------------
# 5) Encrypt plaintext via vesctl
# ----------------------------------------------------------------------
def encrypt_with_vesctl(plaintext):
    """
    Encrypts the given plaintext using vesctl with the fetched policy document
    and public key.

    :param plaintext: The plaintext string to encrypt (str)
    :return: Base64-encoded ciphertext (str), or None if encryption fails.
    """
    # Write the plaintext to a temp file
    with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp:
        tmp.write(plaintext)
        tmp.flush()
        tmp_path = tmp.name

    try:
        proc = subprocess.run(
            [
                "vesctl", "request", "secrets", "encrypt",
                "--policy-document", POLICY_JSON,
                "--public-key", PUBLIC_KEY_PEM,
                tmp_path
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        # Typically the final line of stdout is the base64 cipher
        cipher_b64 = proc.stdout.strip().splitlines()[-1]
        return cipher_b64
    except subprocess.CalledProcessError as e:
        print("❌ Encryption failed.\n")
        print("VESCTL stderr:", e.stderr)
        return None
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

# ----------------------------------------------------------------------
# 6) Validate All Keys 
# ----------------------------------------------------------------------
def decrypt_and_validate_all(p12_bundle_path):
    """
    Verifies that each key's encrypted data in blindfolded-secret.json
    is valid and recognized by the F5 XC policy (using vesctl).

    :param p12_bundle_path: Path to the .p12 credential bundle (str)
    :return: None
    """
    print("\n Validating each encrypted key by attempting decryption...\n")
    try:
        with open(BLINDFOLDED_JSON, "r", encoding="utf-8") as f:
            bundle = json.load(f)
    except Exception as e:
        print(f"❌ Failed to load {BLINDFOLDED_JSON}: {e}")
        return

    secret_content = bundle.get("policy", {}).get("secret_content", {})
    for key, secret_info in secret_content.items():
        print(f"   Verifying encrypted secret for key: '{key}'")
        location_str = secret_info.get("blindfold_secret_info", {}).get("location", "")
        prefix = "string:///'"
        if location_str.startswith(prefix):
            base64_str = location_str[len(prefix):].rstrip("'")
        else:
            base64_str = location_str

        tmp_filename = None
        try:
            # Write the base64 ciphertext to a temp file
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp_file:
                tmp_file.write(base64_str)
                tmp_file.flush()
                tmp_filename = tmp_file.name

            subprocess.run(
                [
                    "vesctl",
                    "request",
                    "secrets",
                    "secret-info",
                    tmp_filename,
                    "--p12-bundle",
                    p12_bundle_path
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
                text=True
            )
            # If vesctl ran without error, we consider it valid
            print(f"   ✅ The ciphertext for key '{key}' is valid and recognized by F5 XC policy.\n")

        except subprocess.CalledProcessError as e:
            print(f"   ❌ Decryption verification failed for key '{key}'.")
            print("   vesctl stderr:", e.stderr, "\n")
        except Exception as ex:
            print(f"   ❌ Error processing key '{key}': {ex}\n")
        finally:
            if tmp_filename and os.path.exists(tmp_filename):
                os.remove(tmp_filename)

# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------
def main():
    print("==========================================")
    print("  🔐 F5 XC API Secrets Blindfold Tool   ")
    print("==========================================\n")

    # 1) .p12 path
    p12_path = select_p12_file()
    if not p12_path:
        print("❌ No .p12 file selected. Aborting.")
        return

    # 2) .p12 password
    while True:
        pw1 = getpass.getpass("Enter .p12 password: ")
        pw2 = getpass.getpass("Confirm password: ")
        if pw1 != pw2:
            print("❌ Passwords do not match. Try again.\n")
        elif not pw1:
            print("❌ Password cannot be empty.\n")
        else:
            break

    # 2.5) Prompt user for the NAMESPACE and POLICY NAME (case-sensitive)
    print("\nPlease specify the namespace and policy name to fetch.")
    print("These are case sensitive and must match exactly, e.g.:")
    print("   Namespace examples: 'default', 'shared'")
    print("   Policy name examples: 'alert-notifier', 'my-policy'")
    namespace = input("Namespace: ").strip()
    policy_name = input("Policy Name: ").strip()
    if not namespace or not policy_name:
        print("❌ Namespace or Policy Name cannot be empty. Aborting.")
        return

    # 3) Always fetch new pubkey.pem with .p12 credentials
    if not fetch_public_key(p12_path, pw1):
        return

    # 4) Always fetch new policy.json using the user inputs
    if not fetch_policy_document(p12_path, namespace, policy_name, pw1):
        return

    # 5) Check secrets.yaml
    if not os.path.exists(SECRETS_YAML):
        print(f"❌ {SECRETS_YAML} not found. Aborting.")
        return

    # 6) Load secrets.yaml => decode => encrypt => build final JSON
    try:
        with open(SECRETS_YAML, "r", encoding="utf-8") as f:
            secret_yaml = yaml.safe_load(f)
    except Exception as e:
        print(f"❌ Error loading {SECRETS_YAML}: {e}")
        return

    data_fields = secret_yaml.get("data", {})
    if not data_fields:
        print(f"⚠️  No data fields found in {SECRETS_YAML}. Nothing to encrypt.")
        return

    name = secret_yaml["metadata"]["name"]
    namespace_in_yaml = secret_yaml["metadata"]["namespace"]
    secret_content = {}

    print(f"\n🔐 Processing secrets from {SECRETS_YAML}...\n")

    for key, val_b64 in data_fields.items():
        decoded_value = decode_b64(val_b64)
        if decoded_value is None:
            print(f"   ⚠️  Skipping key '{key}' due to invalid base64.")
            continue

        cipher_b64 = encrypt_with_vesctl(decoded_value)
        if cipher_b64:
            secret_content[key] = {
                "blindfold_secret_info": {
                    "location": f"string:///'{cipher_b64}'"
                }
            }
            print(f"   ✅ Encrypted key '{key}'")
        else:
            print(f"   ❌ Skipping key '{key}' due to encryption failure.\n")

    # 7) Write final blindfolded-secret.json
    final_bundle = {
        "secret_name": name,
        "policy": {
            "name": name,
            "namespace": namespace_in_yaml,
            "secret_content": secret_content
        }
    }
    with open(BLINDFOLDED_JSON, "w", encoding="utf-8") as f:
        json.dump(final_bundle, f, indent=2)

    print(f"\n✅ Wrote blindfolded bundle -> {BLINDFOLDED_JSON}")

    # 8) Optional: Decrypt & Validate
    decrypt_and_validate_all(p12_path)

    print("All done!\n")

if __name__ == "__main__":
    main()
