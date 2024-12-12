/*
  File execute permission granter (or denier). Will add (or remove) file permission mode 'x' for all specified files for the respective categories.
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
// This program is designed to recursively add execute permissions for specified files

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
bool switchEffect = false; // Specifies if permissions will be granted (default) or stripped (true) (+x -> -x)
int mode = 0; // Integer to determine file mode operation (e.g., u-x vs o+x)

void modifyPermissions(const fs::path &filePath);
std::vector<fs::path> parseArguments(int argc, char *argv[]);

std::unordered_map<std::string, std::function<void()>> flagActions = {
    {"v", []() { verbose = true; }},
    {"verbose", []() { verbose = true; }},
    {"s", []() { switchEffect = true; }},
    {"switch-effect", []() { switchEffect = true; }}
};

int main(int argc, char *argv[]) {
    try {
        std::vector<fs::path> filePaths = parseArguments(argc, argv); // Initializes vector to store file paths

        if (filePaths.empty()) {
            std::cerr << "Usage: " << argv[0] << " [-v|--verbose] [-s|--switch-effect] <file1> [directory2]...\n"
                  << "This program modifies file permissions to grant execute access "
                  << "based on user/group/other ownership.\nDirectories are "
                  << "immediately and recursively processed." << std::endl;
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

void modifyPermissions(const fs::path &filePath) { // Function to add execute permissions
    struct stat fileStat; // Makes a stat structure

    if (stat(filePath.c_str(), &fileStat) == -1) { // Retrieves the stat of the file
        perror("\tFailed to retrieve file information");
        return;
    }

    uid_t euid = geteuid(); // Gets effective user id
    gid_t egid = getegid(); // Gets effective group id

    mode_t setBit = 0; // Initializes a file mode bit

    // Determine applicable permission bit
    if (euid == fileStat.st_uid) { // Compares effective user id to file's user id
        setBit = S_IXUSR;
        mode = 1;
    } else if (egid == fileStat.st_gid) { // Compares effective group id to file's group id
        setBit = S_IXGRP;
        mode = 2;
    } else { // If neither are a match
        setBit = S_IXOTH;
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

    // Check if the execute permission is already set
    if (!switchEffect) {   
        if ((fileStat.st_mode & setBit) == setBit) {
            if (verbose) { std::cerr << "\tFile '" << filePath.string()
                    << "' already has the necessary execute permission." << std::endl; }
            return;
        }
    } else {
        if ((fileStat.st_mode & setBit) == 0) {
            if (verbose) { std::cerr << "\tFile '" << filePath.string()
                    << "' already has the necessary execute permission." << std::endl; }
            return;
        }
    }

    // Update permissions to add execute bit
    mode_t newPermissions; 
    if (!switchEffect) { newPermissions = fileStat.st_mode | setBit; } // Ensures the new respective bit is spliced into the file mode
        else { newPermissions = fileStat.st_mode & ~setBit; } // or the negated version moved into the mode
    if (chmod(filePath.c_str(), newPermissions) == -1) { // Update file mode with added bit
        perror("\tFailed to update permissions");
    } else {
        std::string modeStr; // Initializes string to store the symbolic representation of the performed file mode operation
        switch (mode) { // Determines operation based off of the mode integer which dynamically changes based off the script runner and their options
            case 0:
                modeStr = switchEffect ? "o-x" : "o+x"; break; // 001
            case 1:
                modeStr = switchEffect ? "u-x" : "u+x"; break; // 100
            case 2:
                modeStr = switchEffect ? "g-x" : "g+x"; break; // 010
        }
        if (verbose) { std::cout << (switchEffect ? "\tRemoved" : "\tAdded") << " execute permissions for file '" << filePath.string() << "' (" << modeStr << ")" << std::endl; }
    }
}