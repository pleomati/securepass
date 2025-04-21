# SecurePass Manager

![Application Screenshot](spass.png) <!-- Add a screenshot if available -->

Modern password manager with encryption, saving data locally in encrypted form.

## Functions
- Strong password generation
- Data encryption with master password
- Storage of logins and passwords
- Possibility of editing and deleting entries
- Function of copying logins and passwords to the clipboard
- Backup creation

## System requirements
- Python 3.8+
- Windows/Linux/macOS

## Installation

1. clone the repository or download the files:

Translated with DeepL.com (free version)
   ```bash
   git clone https://github.com/pleomati/SecurePass.git
   cd SecurePass

2.Install required dependencies:

   ```bash
   pip install -r requirements.txt

3.Run program:

   ```bash
   python securepass.py

Compiling to an executable file
To compile the program into a stand-alone .exe file (Windows):
Requirements for compilation:
    ```bash
    pip install nuitka

    ```bash
    python -m nuitka --standalone --onefile --windows-disable-console --windows-icon-from-ico=icon.ico --enable-plugin=tk-inter -- include-package=pandas --output-dir=build securepass.py

Install required dependencies:Security
The programme uses an encryption algorithm dependent on the master password

Data is stored locally in the file data.csv

Remember: If you lose your master password, it is not possible to recover the data!

