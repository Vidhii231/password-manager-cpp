#ifndef PASSWORDMANAGER_H
#define PASSWORDMANAGER_H

#include <string>
#include <vector>

struct PasswordEntry {
    int id;
    std::string website;
    std::string username;
    std::string encryptedPassword;
    std::string notes;
    std::string dateCreated;
    std::string lastModified;
};

class PasswordManager {
private:
    std::vector<PasswordEntry> entries;
    std::string masterPasswordHash;
    std::string encryptionKey;
    int nextId;
    
    // Encryption methods
    std::string encrypt(const std::string& text);
    std::string decrypt(const std::string& encryptedText);
    std::string decryptForDisplay(const std::string& encryptedText) const;  // Added const version
    
    // Hash function
    std::string hashPassword(const std::string& password);
    
    // Helper methods
    void initializeEncryptionKey();
    bool verifyMasterPassword();
    void generateEncryptionKeyFromPassword(const std::string& password);
    
public:
    PasswordManager();
    
    // Core functionality
    void addEntry(const std::string& website, const std::string& username, 
                  const std::string& password, const std::string& notes = "");
    void displayAllEntries(bool showPasswords = false);
    void searchEntry(const std::string& searchTerm);
    void updateEntry(int id, const std::string& website, 
                     const std::string& username, const std::string& password,
                     const std::string& notes = "");
    void deleteEntry(int id);
    
    // Security features
    void changeMasterPassword();
    bool authenticate();
    void checkPasswordStrength(const std::string& password) const;
    
    // File operations
    void saveToFile(const std::string& filename = "passwords.dat");
    void loadFromFile(const std::string& filename = "passwords.dat");
    void exportToFile(const std::string& filename = "passwords_export.csv");
    void importFromFile(const std::string& filename = "passwords_import.csv");
    
    // Utility
    void generateRandomPassword(int length = 16);
    std::string getCurrentTime() const;
    
private:
    // Encryption implementation (XOR-based for simplicity)
    std::string simpleXOREncrypt(const std::string& text, const std::string& key) const;  // Made const
    std::string simpleXORDecrypt(const std::string& text, const std::string& key) const;  // Made const
    
    // Password strength checker
    int calculatePasswordScore(const std::string& password) const;
    
    // Helper to display entry with optional password decryption
    void displayEntry(const PasswordEntry& entry, bool showPassword = false) const;
};

#endif