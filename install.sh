#!/usr/bin/env bash

# Professor OSINT - One Click Installer for macOS & Linux

set -e

echo -e "\033[1;36m====================================================\033[0m"
echo -e "\033[1;36m       Professor OSINT - Installation Script        \033[0m"
echo -e "\033[1;36m====================================================\033[0m"

# Ensure we're running from the project directory
if [ ! -f "professor_osint.py" ]; then
    echo -e "\033[0;31m[!] Error: Please run this script from the Databreach-Finder directory.\033[0m"
    exit 1
fi

# Check for Python 3
if command -v python3 &>/dev/null; then
    PYTHON_CMD="python3"
elif command -v python &>/dev/null && python --version | grep -q "Python 3"; then
    PYTHON_CMD="python"
else
    echo -e "\033[0;31m[!] Error: Python 3 is not installed. Please install Python 3.8+ and try again.\033[0m"
    exit 1
fi

echo -e "\033[1;34m[*] Found Python 3 ($PYTHON_CMD)\033[0m"

# Installation Directories
INSTALL_DIR="$HOME/.professor_osint"
VENV_DIR="$INSTALL_DIR/venv"
BIN_DIR="$HOME/.local/bin"

echo -e "\033[1;34m[*] Installing Professor OSINT to $INSTALL_DIR...\033[0m"

# Create directories
mkdir -p "$INSTALL_DIR"
mkdir -p "$BIN_DIR"

# Copy files
cp -r ./* "$INSTALL_DIR/"

# Setup Virtual Environment
echo -e "\033[1;34m[*] Creating Virtual Environment...\033[0m"
$PYTHON_CMD -m venv "$VENV_DIR"

echo -e "\033[1;34m[*] Installing Dependencies...\033[0m"
source "$VENV_DIR/bin/activate"
pip install --upgrade pip --quiet
pip install -r "$INSTALL_DIR/requirements.txt" --quiet
deactivate

# Create wrapper script
WRAPPER_SCRIPT="$BIN_DIR/professor-osint"
echo -e "\033[1;34m[*] Creating global command 'professor-osint'...\033[0m"

cat << EOF > "$WRAPPER_SCRIPT"
#!/usr/bin/env bash
source "$VENV_DIR/bin/activate"
python "$INSTALL_DIR/professor_osint.py" "\$@"
deactivate
EOF

chmod +x "$WRAPPER_SCRIPT"

echo -e "\033[1;32m====================================================\033[0m"
echo -e "\033[1;32m   Installation Successful! \033[0m"
echo -e "\033[1;32m====================================================\033[0m"
echo -e "\033[1;37mYou can now run the tool from anywhere using the command:\033[0m"
echo -e "\n    \033[1;33mprofessor-osint --help\033[0m\n"

# Check if ~/.local/bin is in PATH
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    echo -e "\033[1;31m[!] NOTE: $HOME/.local/bin is not in your PATH.\033[0m"
    echo -e "\033[1;37mPlease add the following line to your ~/.bashrc or ~/.zshrc:\033[0m"
    echo -e "\033[1;33mexport PATH=\"\$HOME/.local/bin:\$PATH\"\033[0m"
fi
