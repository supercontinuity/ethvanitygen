# Ethereum Vanity Address Generator

This application generates valid Ethereum wallet addresses with custom prefixes and/or suffixes using parallel processing. It provides a graphical user interface (GUI) for easy configuration and monitoring of the generation process.

---

## Prerequisites

### 1. Install Python
Ensure Python 3.8 or higher is installed on your system. You can check your Python version by running:
```bash
python --version
```
If Python is not installed, download and install it from the [official Python website](https://www.python.org/downloads/).

### 2. Install Python Dependencies
Install the required Python libraries by running:
```bash
pip install -r requirements.txt
```

### Dependencies in `requirements.txt`:
- `eth-account`: For Ethereum wallet address generation.
- `eth-utils`: Utility functions for Ethereum.
- `tkinter`: For the graphical user interface (pre-installed with Python).

---

## Usage

1. Run the application:
```bash
python main.py
```

2. Use the GUI to configure the vanity address generation:
   - **Prefix:** Desired starting characters (e.g., `0xABC`).
   - **Suffix:** Desired ending characters (e.g., `DEF`).
   - **Count:** Number of wallets to generate.
   - **Threads:** Number of CPU threads to use.

3. Monitor the progress in the console and view generated wallets in the interface.

4. Wallets and private keys are displayed and can be saved securely as needed.

---

https://t.me/supercontinuity

