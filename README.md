# Secure Password Manager with Encryption - C++

A command-line password manager application built in C++ with encryption capabilities, perfect for software developer portfolios.

## Features

- 🔐 **AES-inspired XOR Encryption** for password storage
- 👑 **Master Password Protection** with authentication
- 📊 **Password Strength Analyzer** with scoring system
- 📁 **Secure File Storage** (binary and CSV formats)
- 🔍 **Search & Filter** functionality
- 📋 **Import/Export** capabilities
- 🔄 **CRUD Operations** (Create, Read, Update, Delete)
- 🎲 **Random Password Generator**
- 📅 **Timestamps** for created and modified entries

## Project Structure
password-manager-cpp/
├── main.cpp # Main program entry point
├── PasswordManager.h # Class declarations
├── PasswordManager.cpp # Class implementations
├── README.md # This file
└── .gitignore # Git ignore file (optional)


## How to Build

### Using g++:
```bash
g++ -std=c++11 main.cpp PasswordManager.cpp -o password_manager
./password_manager
