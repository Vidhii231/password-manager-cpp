#include <iostream>
#include <vector>
#include <fstream>
#include <sstream>
#include <iomanip>
#include "PasswordManager.h"

void displayMenu() {
    std::cout << "\n=== SECURE PASSWORD MANAGER ===\n";
    std::cout << "1. Add Password Entry\n";
    std::cout << "2. View All Entries (summary)\n";
    std::cout << "3. View All Entries (with passwords)\n";
    std::cout << "4. Search Entry\n";
    std::cout << "5. Update Entry\n";
    std::cout << "6. Delete Entry\n";
    std::cout << "7. Change Master Password\n";
    std::cout << "8. Export to File\n";
    std::cout << "9. Import from File\n";
    std::cout << "10. Password Strength Checker\n";
    std::cout << "11. Generate Random Password\n";
    std::cout << "0. Exit\n";
    std::cout << "Choose an option: ";
}

int main() {
    PasswordManager pm;
    
    // Try to load existing data
    pm.loadFromFile();
    
    int choice;
    do {
        displayMenu();
        std::cin >> choice;
        std::cin.ignore();
        
        switch(choice) {
            case 1: {
                std::string website, username, password;
                std::cout << "Enter website: ";
                std::getline(std::cin, website);
                std::cout << "Enter username: ";
                std::getline(std::cin, username);
                std::cout << "Enter password: ";
                std::getline(std::cin, password);
                pm.addEntry(website, username, password);
                break;
            }
            case 2:
                pm.displayAllEntries(false); // Summary view
                break;
            case 3:
                pm.displayAllEntries(true); // Show passwords
                break;
            case 4: {
                std::string searchTerm;
                std::cout << "Enter website or username to search: ";
                std::getline(std::cin, searchTerm);
                pm.searchEntry(searchTerm);
                break;
            }
            case 5: {
                int id;
                std::string website, username, password, notes;
                std::cout << "Enter entry ID to update: ";
                std::cin >> id;
                std::cin.ignore();
                std::cout << "Enter new website: ";
                std::getline(std::cin, website);
                std::cout << "Enter new username: ";
                std::getline(std::cin, username);
                std::cout << "Enter new password: ";
                std::getline(std::cin, password);
                std::cout << "Enter new notes (optional): ";
                std::getline(std::cin, notes);
                pm.updateEntry(id, website, username, password, notes);
                break;
            }
            case 6: {
                int id;
                std::cout << "Enter entry ID to delete: ";
                std::cin >> id;
                pm.deleteEntry(id);
                break;
            }
            case 7:
                pm.changeMasterPassword();
                break;
            case 8:
                pm.exportToFile();
                break;
            case 9:
                pm.importFromFile();
                break;
            case 10: {
                std::string password;
                std::cout << "Enter password to check strength: ";
                std::getline(std::cin, password);
                pm.checkPasswordStrength(password);
                break;
            }
            case 11: {
                int length;
                std::cout << "Enter password length (default 16): ";
                std::string input;
                std::getline(std::cin, input);
                if (input.empty()) {
                    length = 16;
                } else {
                    length = std::stoi(input);
                }
                pm.generateRandomPassword(length);
                break;
            }
            case 0:
                std::cout << "Saving data and exiting...\n";
                pm.saveToFile();
                break;
            default:
                std::cout << "Invalid choice! Try again.\n";
        }
    } while(choice != 0);
    
    return 0;
}