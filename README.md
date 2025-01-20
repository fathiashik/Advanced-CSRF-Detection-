# Advanced HTTP CSRF Detection Script

**Author:** Ashik Abdul Rasheed

## Overview

This repository houses an advanced Nmap script designed for detecting Cross-Site Request Forgery (CSRF) vulnerabilities in web applications. The script leverages cutting-edge technologies, including Machine Learning for anomaly detection and Blockchain for secure data storage.

## Features

- **Machine Learning:** Utilizes machine learning models to identify anomalies within form tokens, highlighting potential CSRF vulnerabilities.
- **Blockchain:** Ensures the integrity and security of findings by storing them on a blockchain ledger.
- **Protocol Compatibility:** Compatible with both HTTP and HTTPS protocols.

## Installation

### Prerequisites

- Ensure [Nmap](https://nmap.org/download.html) is installed on your system.
- Verify the availability of Lua modules `machine_learning` and `blockchain` within your scripting environment.

### Installation Steps

1. Clone the repository:

    ```bash
    git clone https://github.com/fathiashik/csrf-detection-script.git
    cd csrf-detection-script
    ```

2. Save the script as `advanced-http-csrf-ashik.nse`.

## Usage

### Running the Script

Execute the script by running the following command:

```bash
nmap -p 80,443 --script advanced-http-csrf-ashik <target>
