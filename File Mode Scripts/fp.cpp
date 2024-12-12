/*
  File permission granter. Will change file permission mode for all specified files to rwx for the respective categories.
  Copyright (C) 2024  Aristotle Daskaleas

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
// This program is designed to recursively grant all permissions for specified files

#include <iostream>
#include <vector>
#include <string>
#include <filesystem>
#include <sys/stat.h>
#include <cstdlib>
#include <unistd.h>
#include <unordered_map>
#include <functional>

namespace fs = std::filesystem; // Opens a namespace for easy access
bool verbose = false; // Flag to specify verbosity (essentially every output message)
bool switchMode = false; // Denotes whether to modify own categorical permissions or all descending categorical permissions as well
int mode = 0; // Integer to determine file mode operation (e.g., ugo+rwx vs u+rwx)

void modifyPermissions(const fs::path &filePath);
std::vector<fs::path> parseArguments(int argc, char *argv[]);

std::unordered_map<std::string, std::function<void()>> flagActions = {
    {"v", []() { verbose = true; }},
    {"verbose", []() { verbose = true; }},
    {"a", []() { switchMode = true; }},
    {"all-groups", []() { switchMode = true; }}
};

int main(int argc, char *argv[]) {
    try {
        std::vector<fs::path> filePaths = parseArguments(argc, argv); // Initializes vector to store file paths

        if (filePaths.empty()) {
            std::cerr << "Usage: " << argv[0] << " [-v|--verbose] [-a|--all-groups] <file1> [directory2]...\n"
                  << "This program modifies file permissions to grant full access "
                  << "based on user/group/other ownership or all sections defined by '-a'.\n"
                  << "Directories are immediately and recursively processed." << std::endl;
#ifndef _WIN32          
            return EXIT_FAILURE + 1;
#else
            return EXIT_FAILURE;
#endif
        }
        for (const auto &filePath : filePaths) {
            if (!fs::exists(filePath)) {
                std::cerr << "Error: File or directory '" << filePath.string()
                          << "' does not exist." << std::endl;
                continue;
            }

            if (fs::is_directory(filePath)) {
                if (verbose) { std::cout << "Processing directory: " << filePath.string() << std::endl; }

                for (const auto &entry : fs::recursive_directory_iterator(filePath)) {
                    if (fs::is_regular_file(entry.path())) {
                        modifyPermissions(entry.path());
                    }
                }
            } else if (fs::is_regular_file(filePath)) {
                if (verbose) { std::cout << "Processing file: " << filePath.string() << std::endl; }
                modifyPermissions(filePath);
            } else {
                if (verbose) { std::cerr << "Skipping unsupported file: " << filePath.string() << std::endl; }
            }
        }
    } catch (const std::invalid_argument &ex) {
        std::cerr << ex.what() << std::endl;
        return EXIT_FAILURE;
    } catch (const std::exception &ex) {
        std::cerr << "An error occurred: " << ex.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

std::vector<fs::path> parseArguments(int argc, char *argv[]) {
    std::vector<fs::path> filePaths;

    for (int i = 1; i < argc; ++i) { // Iterates through arguments
        std::string arg = argv[i]; // Sets the current argument to a string

        if (arg[0] == '-' && arg[1] != '-') {
            if (arg.substr(1).length() == 0) { throw std::invalid_argument("A flag must be specified. (-)"); }
            for (size_t j = 1; j < arg.length(); ++j) {
                std::string shortFlag(1, arg[j]);
                if (flagActions.find(shortFlag) != flagActions.end()) {
                    flagActions[shortFlag]();
                } else {
                    throw std::invalid_argument("Invalid flag: -" + shortFlag);
                }
            }
        } else if (arg[0] == '-' && arg[1] == '-') {
            std::string longOption = arg.substr(2);
            if (longOption.length() == 0) { throw std::invalid_argument("A flag must be specified. (--)"); }
            if (flagActions.find(longOption) != flagActions.end()) {
                flagActions[longOption]();
            } else {
                throw std::invalid_argument("Invalid flag: --" + longOption);
            }
        } else {
            filePaths.emplace_back(argv[i]);
        }
    }
    return filePaths;
}

void modifyPermissions(const fs::path &filePath) { // Function to add full permissions
    struct stat fileStat; // Makes a stat structure

    if (stat(filePath.c_str(), &fileStat) == -1) { // Retrieves the stat of the file
        perror("\tFailed to retrieve file information");
        return;
    }

    uid_t euid = geteuid(); // Gets effective user id
    gid_t egid = getegid(); // Gets effective group id
    bool isUser = false; // Boolean to store the determination of whether the effective UID of the script runner matches that of the file
    bool isGroup = false; // Boolean to store the determination of whether the effective GID of the script runner matches that of the file

    mode_t setBit = 0; // Initializes a file mode bit

    // Determine applicable permission bit
    if (euid == fileStat.st_uid) { // Compares effective user id to file's user id
        setBit = switchMode ? S_IRWXU | S_IRWXG | S_IRWXO : S_IRWXU;
        isUser = true;
        mode = switchMode ? 3 : 1;
    } else if (egid == fileStat.st_gid) { // Compares effective group id to file's group id
        setBit = switchMode ? S_IRWXG | S_IRWXO : S_IRWXG;
        isGroup = true;
        mode = switchMode ? 4 : 2;
    } else { // If neither are a match
        setBit = S_IRWXO;
    }

    // Ensure script is not run as root unless root owns the files
    if (euid == 0 && fileStat.st_uid != 0) {
        std::cerr << "\tCannot modify file '" << filePath.string()
                  << "' as root unless root owns it." << std::endl;
        return;
    }
    if (egid == 0 && fileStat.st_gid != 0) {
        std::cerr << "\tCannot modify file '" << filePath.string()
                  << "' as root unless root owns it." << std::endl;
        return;
    }

    // Ensures the file doesn't already have the requested permissions mask
    if (!switchMode) {
        mode_t relevantBits = isUser ? S_IRWXU : (isGroup ? S_IRWXG : S_IRWXO); // Filters bits to the determined respective bits
        mode_t maskedCurrentMode = fileStat.st_mode & relevantBits; // Filters the specific permission and masks the rest

        if ((maskedCurrentMode & setBit) == setBit) { // ANDs setBit over the filtered mode and compares it to setBit (effectively seeing if they match)
            if (verbose) {
                std::cerr << "\tCannot add permissions to file '" << filePath.string()
                          << "' as the permissions are already set." << std::endl;
            }
            return;
        }
    } else { // If setting all descending categorical groups
        mode_t relevantBits = isUser ? S_IRWXU | S_IRWXG | S_IRWXO : (isGroup ? S_IRWXG | S_IRWXO : S_IRWXO);
        mode_t maskedCurrentMode = fileStat.st_mode & relevantBits;

        if ((maskedCurrentMode & setBit) == setBit && (maskedCurrentMode | setBit) == setBit ) { // Compares the bitwise AND and OR of the mask and the setBit
            if (verbose) {
                std::cerr << "\tCannot add permissions to file '" << filePath.string()
                          << "' as the permissions are already set." << std::endl;
            }
            return;
        }
    }
    
    // Update permissions to add the bit
    mode_t newPermissions = fileStat.st_mode | setBit;  // Ensures the new respective bit is spliced into the file mode
    if (chmod(filePath.c_str(), newPermissions) == -1) { // Update file mode with added bit
        perror("\tFailed to update permissions");
    } else {
        std::string modeStr; // Initializes string to store the symbolic representation of the performed file mode operation
        switch (mode) { // Determines operation based off of the mode integer which dynamically changes based off the script runner and their options
            case 0:
                modeStr = "o+rwx"; break; // 007
            case 1:
                modeStr = "u+rwx"; break; // 700
            case 2:
                modeStr = "g+rwx"; break; // 070
            case 3:
                modeStr = "ugo+rwx"; break; // 777
            case 4:
                modeStr = "go+rwx"; break; // 077
        }
        if (verbose) { std::cout << "\tAdded permissions for file '" << filePath.string() << "' (" << modeStr << ")" << std::endl; }
    }
}