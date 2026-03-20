# MiniDM

**An open-source, self-hosted Mobile Device Management (MDM) solution for Windows 11.**

MiniDM is a lightweight but powerful endpoint management platform. It combines a high-concurrency Node.js server with a highly privileged, resilient C# .NET background agent. Designed for IT admins, homelabbers, and MSPs who want simple app and policy deployment for endpoints without paying exorbitant per-month subscription fees.


## Key Features

* **WinGet "Manifest-as-a-Service" Brain:** The server actively crawls GitHub WinGet manifests, extracts vendor CDNs and SHA-256 hashes, and intelligently generates context-aware silent install flags based on the packaging engine (MSI, Inno, Nullsoft, etc.).
* **Ironclad Execution Sandbox:** The Windows Agent forces OS-level window suppression to prevent Local Privilege Escalation (LPE) via rogue installer GUIs. A built-in 15-minute deadman's switch kills hanging processes to prevent queue lockups.
* **Offline Caching & Pre-Login Execution:** Deploy massive CAD or Adobe payloads in the background while users work. The agent securely caches the verified installers and executes them automatically upon the next system startup.
* **ADMX / ADML Policy Engine:** Full XML parsing of Microsoft Group Policy templates into structured JSON for granular, system-wide registry enforcement.
* **Trust On First Use (TOFU) Security:** Dynamic enrollment keys with RSA-2048 key pair generation. Every payload is cryptographically signed by the server and verified by the agent before execution.
* **Unified Dashboard Analytics:** A responsive, dark-mode ready UI featuring real-time visual telemetry (via Chart.js) and fleet status tracking.

---

## Architecture

MiniDM is split into two core components:

1. **The Server (`/server`):** A Node.js backend using Express and a persistent SQLite database. It serves the admin dashboard, manages hierarchical device groups, queues deployment tasks, and acts as the central API for agent check-ins.
2. **The Agent (`/agent`):** A C# .NET 10 application that runs as a highly privileged local service. It polls the server, validates cryptographic signatures, enforces registry policies, and reports execution telemetry (exit codes) back to the server.

---

## Getting Started: The Server

### Prerequisites
* [Node.js](https://nodejs.org/) (v18+)
* SQLite3

### Installation

1. Clone the repository:
   git clone https://github.com/minidm-org/minidm.git
   cd MiniDM/server

2. Install dependencies:
   npm install

3. Configure your environment:
   Copy the example environment file and fill in your secure secrets.
   cp .env.example .env
   *Make sure you define your SESSION_SECRET and your GITHUB_API_TOKEN (for the WinGet crawler).*

4. Start the server:
   npm start
   
   The dashboard will be available at http://your_server:6112/

   Note: For production environments it is advised to configure the service behind a reverse proxy with SSL!

   Default login is: admin / password123%

---

## Getting Started: The Agent

The C# Agent is designed to be compiled as a windows background service, but can also be compiled as a console app if desired.

Important: To install, the Agent requires that the Host and Enrollment key are configured in the registry first! You obtain these from your server instance.

## Compilation

1. Navigate to the agent directory:
   cd ../agent

2. Publish the executable:
   dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true

3. Retrieve your compiled agent from `bin\Release\net10.0\win-x64\publish\MiniDMAgent.exe`. 

### Deployment

Administrators can dynamically generate an enrollment script directly from the MiniDM Dashboard (under the **Devices** tab). This `.ps1` script will write the active Enrollment Key and Server URL to `HKLM\SOFTWARE\MiniDM` - These keys are destroyed upon successful enrollment to prevent scraping the server address.

---

## Contributing

Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.


## License

Distributed under GPLv3 license. See `LICENSE` for more information.
