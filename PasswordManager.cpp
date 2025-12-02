#include "PasswordManager.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <algorithm>
#include <cctype>
#include <random>

// Simple XOR encryption for demonstration
// In a real application, use AES or similar
std::string PasswordManager::simpleXOREncrypt(const std::string& text, const std::string& key) const {
    std::string result = text;
    for (size_t i = 0; i < text.length(); ++i) {
        result[i] = text[i] ^ key[i % key.length()];
    }
    return result;
}

std::string PasswordManager::simpleXORDecrypt(const std::string& text, const std::string& key) const {
    // XOR decryption is the same as encryption
    return simpleXOREncrypt(text, key);
}

PasswordManager::PasswordManager() : nextId(1) {
    // Default master password hash (demo: "admin123")
    masterPasswordHash = "240be518fabd2724ddb6f04eeb1da5967448d7e8"; // SHA1 of "admin123"
    initializeEncryptionKey();
}

void PasswordManager::initializeEncryptionKey() {
    // Generate a simple encryption key
    // In production, use proper key derivation
    encryptionKey = "MySecretEncryptionKey123!";
}

std::string PasswordManager::encrypt(const std::string& text) {
    return simpleXOREncrypt(text, encryptionKey);
}

std::string PasswordManager::decrypt(const std::string& encryptedText) {
    return simpleXORDecrypt(encryptedText, encryptionKey);
}

std::string PasswordManager::decryptForDisplay(const std::string& encryptedText) const {
    return simpleXORDecrypt(encryptedText, encryptionKey);
}

std::string PasswordManager::hashPassword(const std::string& password) {
    // Simple hash for demonstration
    // In production, use bcrypt, scrypt, or Argon2
    unsigned long hash = 5381;
    for (char c : password) {
        hash = ((hash << 5) + hash) + c;
    }
    
    std::stringstream ss;
    ss << std::hex << hash;
    return ss.str();
}

void PasswordManager::addEntry(const std::string& website, const std::string& username, 
                               const std::string& password, const std::string& notes) {
    if (!authenticate()) {
        std::cout << "Authentication failed!\n";
        return;
    }
    
    PasswordEntry entry;
    entry.id = nextId++;
    entry.website = website;
    entry.username = username;
    entry.encryptedPassword = encrypt(password);
    entry.notes = notes;
    entry.dateCreated = getCurrentTime();
    entry.lastModified = entry.dateCreated;
    
    entries.push_back(entry);
    std::cout << "Entry added successfully! ID: " << entry.id << "\n";
    
    // Auto-save
    saveToFile();
}

// Helper function to display individual entry
void PasswordManager::displayEntry(const PasswordEntry& entry, bool showPassword) const {
    std::cout << "\nID: " << entry.id << "\n";
    std::cout << "Website: " << entry.website << "\n";
    std::cout << "Username: " << entry.username << "\n";
    if (showPassword) {
        std::cout << "Password: " << decryptForDisplay(entry.encryptedPassword) << "\n";
    } else {
        std::cout << "Password: " << "••••••••" << "\n";
    }
    if (!entry.notes.empty()) {
        std::cout << "Notes: " << entry.notes << "\n";
    }
    std::cout << "Created: " << entry.dateCreated << "\n";
    std::cout << "Modified: " << entry.lastModified << "\n";
    std::cout << std::string(40, '-') << "\n";
}

void PasswordManager::displayAllEntries(bool showPasswords) {
    if (!authenticate()) {
        std::cout << "Authentication failed!\n";
        return;
    }
    
    if (entries.empty()) {
        std::cout << "No password entries found.\n";
        return;
    }
    
    std::cout << "\n=== ALL PASSWORD ENTRIES ===\n";
    std::cout << std::left << std::setw(5) << "ID" 
              << std::setw(20) << "Website" 
              << std::setw(25) << "Username" 
              << std::setw(30) << "Password"
              << std::setw(15) << "Last Modified" << "\n";
    std::cout << std::string(95, '-') << "\n";
    
    for (const auto& entry : entries) {
        std::string displayPassword;
        if (showPasswords) {
            displayPassword = decryptForDisplay(entry.encryptedPassword);
        } else {
            displayPassword = "••••••••";
        }
        
        std::cout << std::left << std::setw(5) << entry.id
                  << std::setw(20) << (entry.website.length() > 18 ? 
                      entry.website.substr(0, 15) + "..." : entry.website)
                  << std::setw(25) << (entry.username.length() > 23 ? 
                      entry.username.substr(0, 20) + "..." : entry.username)
                  << std::setw(30) << displayPassword
                  << std::setw(15) << (entry.lastModified.length() > 10 ? 
                      entry.lastModified.substr(0, 10) : entry.lastModified) << "\n";
    }
    
    if (showPasswords) {
        std::cout << "\nWarning: Passwords are displayed in plain text!\n";
    }
}

void PasswordManager::searchEntry(const std::string& searchTerm) {
    if (!authenticate()) {
        std::cout << "Authentication failed!\n";
        return;
    }
    
    std::vector<PasswordEntry> results;
    
    for (const auto& entry : entries) {
        if (entry.website.find(searchTerm) != std::string::npos ||
            entry.username.find(searchTerm) != std::string::npos ||
            entry.notes.find(searchTerm) != std::string::npos) {
            results.push_back(entry);
        }
    }
    
    if (results.empty()) {
        std::cout << "No entries found for: " << searchTerm << "\n";
        return;
    }
    
    std::cout << "\n=== SEARCH RESULTS (" << results.size() << " found) ===\n";
    
    // Ask if user wants to see passwords
    char showPasswords;
    std::cout << "Show passwords? (y/n): ";
    std::cin >> showPasswords;
    std::cin.ignore();
    
    bool displayPasswords = (showPasswords == 'y' || showPasswords == 'Y');
    
    for (const auto& entry : results) {
        displayEntry(entry, displayPasswords);
    }
}

void PasswordManager::updateEntry(int id, const std::string& website, 
                                  const std::string& username, const std::string& password,
                                  const std::string& notes) {
    if (!authenticate()) {
        std::cout << "Authentication failed!\n";
        return;
    }
    
    for (auto& entry : entries) {
        if (entry.id == id) {
            entry.website = website;
            entry.username = username;
            entry.encryptedPassword = encrypt(password);
            entry.notes = notes;
            entry.lastModified = getCurrentTime();
            
            std::cout << "Entry updated successfully!\n";
            saveToFile();
            return;
        }
    }
    
    std::cout << "Entry with ID " << id << " not found!\n";
}

void PasswordManager::deleteEntry(int id) {
    if (!authenticate()) {
        std::cout << "Authentication failed!\n";
        return;
    }
    
    auto it = std::remove_if(entries.begin(), entries.end(),
        [id](const PasswordEntry& entry) { return entry.id == id; });
    
    if (it != entries.end()) {
        entries.erase(it, entries.end());
        std::cout << "Entry deleted successfully!\n";
        saveToFile();
    } else {
        std::cout << "Entry with ID " << id << " not found!\n";
    }
}

bool PasswordManager::authenticate() {
    std::string password;
    std::cout << "Enter master password: ";
    std::getline(std::cin, password);
    
    std::string inputHash = hashPassword(password);
    if (inputHash == masterPasswordHash) {
        std::cout << "Authentication successful!\n";
        return true;
    } else {
        std::cout << "Authentication failed!\n";
        return false;
    }
}

bool PasswordManager::verifyMasterPassword() {
    // This is a private helper that doesn't prompt
    // Used internally when we already have the password
    return true; // Simplified for this example
}

void PasswordManager::changeMasterPassword() {
    std::string currentPassword, newPassword, confirmPassword;
    
    std::cout << "Enter current master password: ";
    std::getline(std::cin, currentPassword);
    
    if (hashPassword(currentPassword) != masterPasswordHash) {
        std::cout << "Incorrect current password!\n";
        return;
    }
    
    std::cout << "Enter new master password: ";
    std::getline(std::cin, newPassword);
    
    std::cout << "Confirm new master password: ";
    std::getline(std::cin, confirmPassword);
    
    if (newPassword != confirmPassword) {
        std::cout << "Passwords don't match!\n";
        return;
    }
    
    if (newPassword.length() < 8) {
        std::cout << "Password must be at least 8 characters!\n";
        return;
    }
    
    masterPasswordHash = hashPassword(newPassword);
    generateEncryptionKeyFromPassword(newPassword);
    
    // Re-encrypt all passwords with new key
    for (auto& entry : entries) {
        std::string decrypted = decrypt(entry.encryptedPassword);
        entry.encryptedPassword = encrypt(decrypted);
    }
    
    std::cout << "Master password changed successfully!\n";
    saveToFile();
}

void PasswordManager::generateEncryptionKeyFromPassword(const std::string& password) {
    // Simple key derivation - use proper KDF in production
    encryptionKey = password + "S@ltValue123!";
}

int PasswordManager::calculatePasswordScore(const std::string& password) const {
    int score = 0;
    
    // Length check
    if (password.length() >= 8) score += 2;
    if (password.length() >= 12) score += 2;
    if (password.length() >= 16) score += 3;
    
    // Character variety
    bool hasUpper = false, hasLower = false, hasDigit = false, hasSpecial = false;
    
    for (char c : password) {
        if (isupper(c)) hasUpper = true;
        else if (islower(c)) hasLower = true;
        else if (isdigit(c)) hasDigit = true;
        else hasSpecial = true;
    }
    
    if (hasUpper && hasLower) score += 2;
    if (hasDigit) score += 2;
    if (hasSpecial) score += 3;
    
    return std::min(score, 10); // Cap at 10
}

void PasswordManager::checkPasswordStrength(const std::string& password) const {
    int score = calculatePasswordScore(password);
    
    std::cout << "\n=== PASSWORD STRENGTH ANALYSIS ===\n";
    std::cout << "Length: " << password.length() << " characters\n";
    
    std::cout << "Strength: ";
    if (score <= 3) {
        std::cout << "Very Weak (red)\n";
        std::cout << "Recommendation: Use at least 8 characters with mixed case and numbers\n";
    } else if (score <= 5) {
        std::cout << "Weak (orange)\n";
        std::cout << "Recommendation: Add special characters and increase length\n";
    } else if (score <= 7) {
        std::cout << "Good (yellow)\n";
        std::cout << "Recommendation: Increase length for better security\n";
    } else if (score <= 9) {
        std::cout << "Strong (light green)\n";
    } else {
        std::cout << "Excellent (green)\n";
    }
    
    std::cout << "Score: " << score << "/10\n";
    
    // Generate a strong password suggestion
    std::cout << "\nStrong password suggestion: ";
    std::string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<> distribution(0, chars.length() - 1);
    
    std::string suggestion;
    for (int i = 0; i < 16; ++i) {
        suggestion += chars[distribution(generator)];
    }
    std::cout << suggestion << "\n";
}

std::string PasswordManager::getCurrentTime() const {
    std::time_t now = std::time(nullptr);
    std::tm* timeinfo = std::localtime(&now);
    
    char buffer[80];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
    return std::string(buffer);
}

void PasswordManager::saveToFile(const std::string& filename) {
    if (!authenticate()) {
        std::cout << "Authentication failed! Cannot save.\n";
        return;
    }
    
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        std::cout << "Error saving to file!\n";
        return;
    }
    
    // Save number of entries
    size_t count = entries.size();
    file.write(reinterpret_cast<char*>(&count), sizeof(count));
    
    // Save each entry
    for (const auto& entry : entries) {
        size_t len;
        
        len = entry.website.length();
        file.write(reinterpret_cast<char*>(&len), sizeof(len));
        file.write(entry.website.c_str(), len);
        
        len = entry.username.length();
        file.write(reinterpret_cast<char*>(&len), sizeof(len));
        file.write(entry.username.c_str(), len);
        
        len = entry.encryptedPassword.length();
        file.write(reinterpret_cast<char*>(&len), sizeof(len));
        file.write(entry.encryptedPassword.c_str(), len);
        
        len = entry.notes.length();
        file.write(reinterpret_cast<char*>(&len), sizeof(len));
        file.write(entry.notes.c_str(), len);
        
        file.write(reinterpret_cast<const char*>(&entry.id), sizeof(entry.id));
    }
    
    std::cout << "Data saved to " << filename << "\n";
    file.close();
}

void PasswordManager::loadFromFile(const std::string& filename) {
    if (!authenticate()) {
        std::cout << "Authentication failed! Cannot load.\n";
        return;
    }
    
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cout << "No existing data file found. Starting fresh.\n";
        return;
    }
    
    entries.clear();
    
    size_t count;
    file.read(reinterpret_cast<char*>(&count), sizeof(count));
    
    for (size_t i = 0; i < count; ++i) {
        PasswordEntry entry;
        size_t len;
        
        file.read(reinterpret_cast<char*>(&len), sizeof(len));
        entry.website.resize(len);
        file.read(&entry.website[0], len);
        
        file.read(reinterpret_cast<char*>(&len), sizeof(len));
        entry.username.resize(len);
        file.read(&entry.username[0], len);
        
        file.read(reinterpret_cast<char*>(&len), sizeof(len));
        entry.encryptedPassword.resize(len);
        file.read(&entry.encryptedPassword[0], len);
        
        file.read(reinterpret_cast<char*>(&len), sizeof(len));
        entry.notes.resize(len);
        file.read(&entry.notes[0], len);
        
        file.read(reinterpret_cast<char*>(&entry.id), sizeof(entry.id));
        
        if (entry.id >= nextId) {
            nextId = entry.id + 1;
        }
        
        entry.dateCreated = getCurrentTime();
        entry.lastModified = getCurrentTime();
        
        entries.push_back(entry);
    }
    
    std::cout << "Loaded " << entries.size() << " entries from " << filename << "\n";
    file.close();
}

void PasswordManager::exportToFile(const std::string& filename) {
    if (!authenticate()) {
        std::cout << "Authentication failed!\n";
        return;
    }
    
    std::ofstream file(filename);
    if (!file) {
        std::cout << "Error creating export file!\n";
        return;
    }
    
    file << "ID,Website,Username,Password,Notes,Date Created,Last Modified\n";
    
    for (const auto& entry : entries) {
        file << entry.id << ","
             << entry.website << ","
             << entry.username << ","
             << decryptForDisplay(entry.encryptedPassword) << ","
             << "\"" << entry.notes << "\","
             << entry.dateCreated << ","
             << entry.lastModified << "\n";
    }
    
    std::cout << "Data exported to " << filename << "\n";
    file.close();
}

void PasswordManager::importFromFile(const std::string& filename) {
    if (!authenticate()) {
        std::cout << "Authentication failed!\n";
        return;
    }
    
    std::ifstream file(filename);
    if (!file) {
        std::cout << "Error opening import file!\n";
        return;
    }
    
    std::string line;
    std::getline(file, line); // Skip header
    
    int importedCount = 0;
    while (std::getline(file, line)) {
        std::stringstream ss(line);
        std::string token;
        std::vector<std::string> tokens;
        
        // Handle quoted fields
        bool inQuotes = false;
        std::string field;
        
        for (char c : line) {
            if (c == '"') {
                inQuotes = !inQuotes;
            } else if (c == ',' && !inQuotes) {
                tokens.push_back(field);
                field.clear();
            } else {
                field += c;
            }
        }
        tokens.push_back(field); // Last field
        
        if (tokens.size() >= 4) {
            // Clean up quotes from notes field
            std::string notes = tokens.size() > 4 ? tokens[4] : "";
            if (!notes.empty() && notes.front() == '"' && notes.back() == '"') {
                notes = notes.substr(1, notes.length() - 2);
            }
            
            addEntry(tokens[1], tokens[2], tokens[3], notes);
            importedCount++;
        }
    }
    
    std::cout << "Imported " << importedCount << " entries from " << filename << "\n";
    file.close();
}

void PasswordManager::generateRandomPassword(int length) {
    std::string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<> distribution(0, chars.length() - 1);
    
    std::string password;
    for (int i = 0; i < length; ++i) {
        password += chars[distribution(generator)];
    }
    
    std::cout << "Generated password: " << password << "\n";
    checkPasswordStrength(password);
}