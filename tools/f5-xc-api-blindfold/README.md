# F5 XC Blindfold Tool

## Introduction
**For**: Preparing blindfolded secrets for the F5 Distributed Cloud (F5 XC) Platform.  
**Description**: Python-based script that takes a Kubernetes Secret YAML, decrypts it locally, re-encrypts each field using a retrieved F5 XC public key and policy, and outputs a `blindfolded-secret.json` bundle suitable for deployment via the F5 XC API.

---

## Instructions

1. **Install dependencies**  
   Ensure the following are available:
   - Python 3.7+
   - `vesctl` CLI (F5 Distributed Cloud CLI)
   - `openssl`
   - `tkinter` (for GUI file picker)

2. **Download the script**  
   Save the Python script locally (e.g., `blindfold-xc-tool.py`).

3. **Prepare F5 XC credentials**
   - Log in to the [F5 XC Console](https://console.ves.volterra.io).
   - Go to **Personal Management > Credentials**.
   - Generate and download a `.p12` file for authentication.
   - Keep track of the password used to create it.

4. **Prepare your Kubernetes Secret YAML**
   - Ensure your secret is in the standard format with base64-encoded values.
   - Save the file as `secrets.yaml` in the same directory as the script.

5. **Run the script**
   - Launch the script via terminal or Python IDE.
   - A GUI will prompt you to select your `.p12` file.
   - Enter your `.p12` password.
   - Enter the correct **namespace** and **policy name** matching your F5 XC configuration.

6. **Output**
   - The script will:
     - Fetch a fresh public key and policy document using your credentials.
     - Decode and re-encrypt all key-value pairs from `secrets.yaml`.
     - Generate `blindfolded-secret.json`, which contains the encrypted secrets in the expected API format.
     - Optionally validate each field by attempting to decrypt via `vesctl`.

---

## Output Files

| File Name               | Description                                     |
|------------------------|-------------------------------------------------|
| `pubkey.pem`           | Fetched F5 XC public key                        |
| `policy.json`          | Fetched blindfold policy document               |
| `blindfolded-secret.json` | Final bundle ready for API deployment         |
| `secrets.yaml`         | Your original Kubernetes secret input (required) |

---

## Use Case

Use this tool when deploying blindfolded secrets via F5 XC APIs (e.g., for HTTPS load balancers, secure credential injection, or secure configuration workflows).

---

## Security Tip

This tool never sends secrets over the network. All encryption happens locally using F5-provided credentials and public key.

---

## Need Help?

Contact your F5 support team or visit [docs.cloud.f5.com](https://docs.cloud.f5.com) for more info on secret encryption policies and deployment via API.

