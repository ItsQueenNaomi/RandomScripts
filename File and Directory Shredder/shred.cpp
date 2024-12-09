/*
  File and directory shredder. It shreds files and directories specified on the command line.
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
/*
File and Directory Shredder
Version: 8
Author: Aristotle Daskaleas (2024)
Changelog (since v1):
    -> Removed multithreading due to file handling conflicts
    -> Added better encryption for secure mode
    -> Commented out redundant functions and debugging code
    -> Nearly prepared for distribution (probs not tho XD)
    -> Added a more efficient secure mode overwriting (to make file size not increase dramatically)
    -> Improved logging function with predefined log levels and making verbosity work
    -> Cleaned up code
    -> Unused code is now gone (bye, we won't miss you)
    -> Improved help dialogue to be more efficient, professional, and visible on small terminals (man page format)
    -> Added OS-specfic function to determine optimal block size to overwrite
    -> Make functions only accept required arguments (i.e., no bools since they're global)
    -> Improved verification for shredding and improved logging
    -> Added '-i'nternal (not advertised) flag to print some development information [useful for debugging]
    -> Added excessive comments to appease any readers and the coding gods
    -> Added more comments and made it so it prints the end time regardless of verbosity
    -> Modified flag handling function ('-n') so numbers can be specified in the middle of flags (e.g., -kvn50sf instead of requiring -kvsfn50)
    -> Added a metadata handler for files, which hopefully further percludes data recovery.
    -> Improved metadata handler
    -> Refractored code. main() is now basically the first function, and it might be easier to read now, I don't know
    -> Added a syncFile() function to maintain cross-compatibility.
    -> Added hashing for verification for systems with OpenSSL
    -> Improved error handling and logging
    -> Implemented and improved errorExit() function
    -> Removed redundant declaration for verificationFailed
    -> Added more comments (namely for the new code I forgot to comment)
    -> Added compilation flag section for easy reference, to streamline compliation
    -> Added write permission checking function
    -> Improved OpenSSL functions (moved away from the depreciated functions)
    -> Added force delete flag and changed flag denotation for "follow_symlinks"
    -> Added permission checking and changing
    -> Improved permission checking and changing with extended attributes
    -> Fixed a bug pertaining to incorrectly reporting that the file failed to delete
    -> Simplified some variables
To-do:
    -> Nothing.

Current full compilation flag: -std=c++20 -DOPENSSL_FOUND -L/path/to/openssl/lib -I/path/to/openssl/include -lssl -lcrypto
*/
#include <iostream>     // For console logging
#include <fstream>      // For file operations (writing)
#include <iomanip>      // For formatting log files
#include <filesystem>   // For file/directory operations (stats)
#include <random>       // For generating random data
#include <chrono>       // For time measurements
#include <string>       // For string manipulation
#include <mutex>        // For secure file name generation
#include <vector>       // For buffer storage
#include <cstring>      // For std::memcpy
#include <thread>       // For sleeping (std::this_thread::sleep_for)
#include <algorithm>    // For std::transform
#include <stdexcept>    // For exceptions
#include <cstdlib>      // For environment variables

#ifdef __linux__
#include <sys/statvfs.h>  // For block size retrieval
#include <unistd.h>       // POSIX operations
#include <sys/stat.h>     // File information
#include <sys/xattr.h>    // Linux extended attributes
#endif

#ifdef _WIN32
#include <windows.h>      // Windows library that allows for block size retrieval
#include <winbase.h>      // For file deletion
#include <aclAPI.h>       // For file permissions
#include <sddl.h>         // For security descriptor strings
#endif

#ifdef __APPLE__
#include <sys/sysctl.h>   // System info
#include <sys/mount.h>    // File system info
#include <unistd.h>       // POSIX operations
#include <sys/stat.h>     // File information
#include <sys/xattr.h>    // macOS extended attributes
#endif

#ifdef OPENSSL_FOUND
#include <openssl/evp.h> // For hashing
#endif

namespace fs = std::filesystem; // Makes linking commands from the 'std::filesystem' easier

// Declarations (defaults)
int overwriteCount = 3; // integer to indicate number of passes to shred the file
bool recursive = false; // boolean to indicate whether directories are shredded or just files
bool keep_files = false; // boolean to indicate whether files are deleted after shredding or not
bool verbose = false; // boolean to indicate verbosity
bool follow_symlinks = false; // boolean to indicate whether symbolic links will be followed or not
bool secure_mode = false; // boolean to indicate shredding mode
bool dry_run = false; // boolean to indicate if any files will actually be shredded
bool verify = true; // boolean to indicate verification after shredding
bool force_delete = false; // boolean to indicate force delete attempt
bool internal = false; // boolean to indicate whether scripting information is revealed

bool failedToRetrievePermissions = false; // Global boolean to indicate if permissions were successfully retrieved
bool bufferSizePrinted = false; // Global boolean to indicate if the buffer size was already printed
bool verificationFailed = false; // Global boolean to determine if verification failed (used in multiple functions)
bool writePermission = false; // Global boolean to determine if the current file being process has write permissions

const std::string validFlags = "nrkvfsdchei"; // Indicated valid program flags

std::mutex fileMutex; // Defines file name generation variable

enum logLevel { // Define valid log levels
    INFO, // Level to inform with verbosity (i.e., every action)
    WARNING, // Level to inform a non-critical error
    ERROR, // Level to indicate core operational errors
    DRY_RUN, // Only used with '-d' (dry_run) flag
    INTERNAL // Only used with '-i' (internal) flag
};

// Prototype declarations for refactoring
#ifdef OPENSSL_FOUND // Only declares these prototypes if compiling with OpenSSL (since it's required)
    int verifyWithHash(const std::string& filePath, const std::vector<char>& expectedData, const int& hash);
    std::string computeSHA256(const std::string& data);
#endif
int overwriteWithRandomData(std::string filePath, std::fstream& file, std::uintmax_t fileSize, int pass = 1);
bool shredFile(const fs::path& filePath);
bool hasWritePermission(const fs::path& path);
bool changePermissions(const std::string &filePath);
void processPath(const fs::path& path);
void syncFile(const fs::path& filePath);
void logMessage(logLevel type, const std::string& message);
void errorExit(int value = 1, std::string message = "", std::string flag = "");
void cleanupMetadata(std::string& filePath);
void help(char* argv[]);
std::vector<std::string> parseArguments(int argc, char* argv[]);
std::uintmax_t getOptimalBlockSize();
std::string generateRandomFileName(size_t length = 32);

bool isRegularFile(const fs::path& file) { return fs::is_regular_file(file); } // Function to check if a path is a regular file

int main(int argc, char* argv[]) {
    std::vector<std::string> fileArgs = parseArguments(argc, argv); // Initialize vector

    auto startT = std::chrono::system_clock::now(); // For start time (printed at start of program)
    auto startTime = std::chrono::high_resolution_clock::now(); // For end time (when it is subtracted later)

    std::time_t start_time_t = std::chrono::system_clock::to_time_t(startT); // Retrieves current time
    std::tm local_tm = *std::localtime(&start_time_t); // Converts it to local time

    if (internal) { // Funny extra feature for people in the know about this flag (outputs parameters, files, and a confirmation)
        // Sets flags to strings for readability
        std::string recursiveStr = (recursive ? "true" : "false");
        std::string keep_filesStr = (keep_files ? "true" : "false");
        std::string follow_symlinksStr = (follow_symlinks ? "true" : "false");
        std::string secure_modeStr = (secure_mode ? "true" : "false");
        std::string dry_runStr = (dry_run ? "true" : "false");
        std::string verifyStr = (verify ? "true" : "false");
        std::string force_deleteStr (force_delete ? "true" : "false");

        // Prints set options
        std::cout << "Parameters ~ Overwrites: " << overwriteCount << ", Recursive: " << recursiveStr << ", Keep_files: " << keep_filesStr << ", Follow_symlinks: " << follow_symlinksStr << ", Secure_mode: " << secure_modeStr << ", Dry_run: " << dry_runStr << ", Verify: " << verifyStr << ", Force: " << force_deleteStr << std::endl;
        std::cout << "Files: " << std::endl;
        for (const auto& filePath : fileArgs) { std::cout << filePath << std::endl; } std::cout << std::endl; // Prints file names
        
        // Prompt to continue the script with the printed options / files
        std::cout << "Continue? (y/N)" << std::endl;
        std::string reply; // Declare reply variable for confirmation
        std::getline(std::cin, reply); // getline may be extra, since input is one character or 2-3 letters (not line)
        std::transform(reply.begin(), reply.end(), reply.begin(), ::tolower); // Transforms case into lowercase
        if (reply == "y") { } else if (reply == "yes") { } else { return 3; } // Unless 'y' or 'yes' is specified, we're done
    }

    std::cout << "Beginning Shred at: " << std::put_time(&local_tm, "%H:%M:%S") << std::endl; // Prints start time to user terminal

    for (const auto& filePath : fileArgs) { // Process each provided path (main function)
        processPath(filePath);
    }

    auto endT = std::chrono::system_clock::now(); // Gets end time (for printing at end)
    auto endTime = std::chrono::high_resolution_clock::now(); // Retrieves time after program has completed
    std::chrono::duration<double> duration = endTime - startTime; // Calculates total run time in seconds

    if (!recursive) { // Will print at the end (if verbose) [runtime statistics]
        logMessage(INFO, "File shredding process completed. " + std::to_string(duration.count()) + " seconds.");
    } else { // Specifies mode
        logMessage(INFO, "Recursive shredding process completed. " + std::to_string(duration.count()) + " seconds.");
    }

    std::time_t EndTime = std::chrono::system_clock::to_time_t(endT); // Converts end time to printable format
    std::tm localEndTime = *std::localtime(&EndTime); // Gets time in local timezone

    std::cout << "Shred completed at: " << std::put_time(&localEndTime, "%H:%M:%S") << std::endl;
    
    return 0; // Success!
}

std::vector<std::string> parseArguments(int argc, char* argv[]) { // Function to parse command line arguments
    std::vector<std::string> fileArgs; // Initialize vector to store files to shred
    char* nMsg = new char[38]; // Initilizes char array to store a commonly used message
    strcpy(nMsg, "Flag '-n' requires a positive integer");
    
    // Parse command-line arguments
    for (int i = 1; i < argc; ++i) { // Iterates over input length
        std::string arg = argv[i]; // Initializes position in argument to iteration

        if (arg[0] == '-') { // Searches for a word starting with a hyphen
            for (size_t j = 1; j < arg.size(); ++j) { // Gets size of word and iterates the individual letter(s)
                char flag = arg[j]; // Splits all letters following a '-'
                if (validFlags.find(flag) != std::string::npos) { // Validates all characters from validFlags
                    // Checks for valid flags and change program's operation accordingly
                    switch (flag) { // Set flag variable to the letter and continue
                        case 'h': help(argv); errorExit(2); // Gets help and exits
                        case 'n': { // Changes overwrite count
                            size_t start = j + 1; // Gets start of number
                            size_t end = start; // To find the end of the number
                            while (end < arg.size() && std::isdigit(arg[end])) {
                                ++end; // Sets end to position of the integer's last character
                            }

                            if (start < end) { // If number is found after n (no space)
                                try {
                                    overwriteCount = std::stoi(arg.substr(start, end - start)); // Extracts integer
                                    j = end - 1; // Move cursor to end of integer
                                } catch (...) {
                                    errorExit(1, nMsg);
                                }
                            } else if (i + 1 < argc) { // If there is a space, look in next argument
                                try {
                                    overwriteCount = std::stoi(argv[++i]); // Increments i and moves to the next argument
                                } catch (...) {
                                    errorExit(1, nMsg);
                                }
                            } else {
                                errorExit(1, nMsg);
                            }
                            break;
                        }
                        case 'r': recursive = true; break;
                        case 'k': keep_files = true; break;
                        case 'v': verbose = true; break;
                        case 'e': follow_symlinks = true; break;
                        case 's': secure_mode = true; break;
                        case 'd': dry_run = true; break;
                        case 'c': verify = false; break;
                        case 'f': force_delete = true; break;
                        case 'i': internal = true; break;
                    }
                } else { // If the character was not validated, deuces
                    delete[] nMsg;
                    std::string flg(1, flag); // Sets 'flg' string to the content of the flag char
                    errorExit(1, "Invalid flag", flg); // Calls the exit with the variables
                }
            }
        } else { // Append all non-flag arguments to the file argument vector
            fileArgs.emplace_back(arg);
        }
    }

    // Check if any files were provided
    if (fileArgs.empty()) { // Suggest help if no
        errorExit(1, "Incorrect usage. Use '-h' for help");
    }
    return fileArgs;
}

void processPath(const fs::path& path) {
    try {
        if (fs::is_symlink(path) && !follow_symlinks) { // Skip symlinks
            logMessage(WARNING, "Skipping symlink '" + path.string() + "'");
            return;
        } else if (fs::is_symlink(path) && follow_symlinks) {
            auto target = fs::read_symlink(path);
            if (!fs::exists(target)) {
                logMessage(WARNING, "Dangling symlink (not followed): '" + path.string() + "'");
                return;
            } else {
                fs::path path = target;
            }
        }

        if (fs::is_directory(path)) {
            if (recursive) { // Processes all files in a directory (recursive required)
                logMessage(INFO, "Entering directory '" + path.string() + "'...");
                for (const auto& entry : fs::recursive_directory_iterator(path, follow_symlinks ? fs::directory_options::follow_directory_symlink : fs::directory_options::none)) {
                    if (fs::is_regular_file(entry)) {
                        shredFile(entry.path());
                    }
                }

                if (!keep_files && fs::is_empty(path) && !dry_run) { // Processes if not keeping files, is a legitimate run, and the directory is empty
                    if (fs::remove(path)) { // Remove directory after after successful deletion of all files
                        logMessage(INFO, "Directory '" + path.string() + "' successfully deleted.");
                    } else {
                        logMessage(ERROR, "Failed to delete directory '" + path.string() + "'");
                    }
                } else { // Directory wasn't deleted: keep files or directory is not empty
                    if (keep_files) { logMessage(WARNING, "Directory '" + path.string() + "' was not deleted (keep_files flag)."); }
                        else if (!fs::is_empty(path) && !dry_run) { logMessage(WARNING, "Directory '" + path.string() + "' is not empty. Skipping deletion."); }
                        else if (dry_run) { logMessage(DRY_RUN, "Directory '" + path.string() + "' would be shredded."); }
                }
            } else { // No recursive = No shredding
                logMessage(WARNING, "'" + path.string() + "' is a directory. Use -r for recursive shredding.");
            }
        } else if (fs::is_regular_file(path)) { // For files to shred individually
            shredFile(path);
        } else { // This file, trash
            logMessage(ERROR, "'" + path.string() + "' is not a valid file or directory.");
        }
    } catch (const fs::filesystem_error& e) { // Expose filesystem errors to the user
        logMessage(ERROR, "Filesystem error: " + std::string(e.what()));
    } catch (const std::runtime_error& e) { // Expose other errors
        logMessage(ERROR, "An error has occured: " + std::string(e.what()));
    } catch (...) {
        logMessage(ERROR, "An unknown error has occured in processPath()");
    }
}

void logMessage(logLevel type, const std::string& message) { // Function to log messages with timestamps
    std::string level;
    if (type == INFO) { level = "INFO"; } // To print the actual word rather than the numerical representation.
    if (type == ERROR) { level = "ERROR"; }
    if (type == WARNING) { level = "WARNING"; }
    if (type == DRY_RUN) { level = "DRY_RUN"; }
    if (type == INTERNAL) { level = "INTERNAL"; }
    if (verbose || internal || type != INFO ) { // Only print WARNING, ERRORS, or DRY_RUN levels (unless verbose)
        auto now = std::chrono::system_clock::now(); // gets current time
        auto time = std::chrono::system_clock::to_time_t(now); // changes time to correct format
        auto tm = *std::localtime(&time); // gets local time
        std::cout << "[" << std::put_time(&tm, "%m-%d-%Y %H:%M:%S") << "] [" << level << "] " << message << std::endl; // logs in format: [MM-DD-YY] [LEVEL] MESSAGE
    }
}

void errorExit(int value, std::string message, std::string flag) { // Function to provide ability to exit program outside of main function
    if (!message.empty() && flag.empty()) {
        logMessage(ERROR, message);
    } else if (!message.empty() && !flag.empty()) {
        logMessage(ERROR, message + " (-" + flag + ")");
    }
    exit(value);
}

std::uintmax_t getOptimalBlockSize() { // This function returns the retrieves blocksize defined in the kernel for the current OS.
#ifdef __linux__
    struct statvfs fsInfo;
    if (statvfs(".", &fsInfo) != 0) {
        logMessage(ERROR, "Error getting block size on Linux.");
        return 4096;  // Default block size if statvfs fails
    }
    return fsInfo.f_frsize;  // f_frsize is the optimal block size
#elif _WIN32
    DWORD sectorsPerCluster, bytesPerSector, numberOfFreeClusters, totalNumberOfClusters;
    if (!GetDiskFreeSpace(".", &sectorsPerCluster, &bytesPerSector, &numberOfFreeClusters, &totalNumberOfClusters)) {
        logMessage(ERROR, "Error getting block size on Windows.");
        return 4096;  // Default block size if GetDiskFreeSpace fails
    }
    return sectorsPerCluster * bytesPerSector;  // This is the block size
#elif __APPLE__
    int blockSize;
    size_t len = sizeof(blockSize);

    if (sysctlbyname("kern.maxfiles", &blockSize, &len, NULL, 0) != 0) {
        logMessage(ERROR, "Error getting block size on MacOS");
        return 4096; // Default block size if sysctl fails
    }
    return blockSize; // blockSize is the optimal block size
#else
    logMessage(INFO, "OS type could not be determined. Using default block size (4096)")
    return 4096;  // Default block size for unsupported platforms
#endif
}

std::string generateRandomFileName(size_t length) {
    static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    static thread_local std::mt19937 generator(std::random_device{}());
    std::uniform_int_distribution<> dist(0, sizeof(charset) - 2);

    std::string randomName;

    for (size_t i = 0; i < length; ++i ) {
        randomName += charset[dist(generator)];
    }
    return randomName;
}

void syncFile(const fs::path& filePath) {
#ifdef _WIN32
    HANDLE hFile = CreateFile(
        filePath.c_str(), // The file
        GENERIC_WRITE, // To flush the file
        0, // Do not share
        NULL, // Default security
        OPEN_EXISTING, // Open the file
        FILE_ATTRIBUTE_NORMAL, // Normal attributes
        NULL); // No template
    if (hFile == INVALID_HANDLE_VALUE) { // Checks if sync was successful
        logMessage(WARNING, "File '" + filePath.string() + "' failed to synchronize.");
        return;
    }
    if (!FlushFileBuffers(hFile)) { // Flushes file
        logMessage(WARNING, "File '" + filePath.string() + "' failed to flush.");
    }
    CloseHandle(hFile);
#else
    FILE* file = fopen(filePath.c_str(), "r"); // Opens the file
    for (int openCount = 0; openCount < 3; ++openCount) {
        if (file) { // Syncs/flushes the file
            fsync(fileno(file));
            fclose(file);
            break;
        }
        file = fopen(filePath.c_str(), "r"); // Attempt to re-open file
        if (openCount == 3) { logMessage(WARNING, "File '" + filePath.string() + "' failed to flush."); break; }
    }
#endif
}

void cleanupMetadata(std::string& filePath) {
#ifdef _WIN32
    if (!DeleteFile((filePath + ":$DATA").c_str());) { // Remove the file's DATA stream
        DWORD lastError = GetLastError();
        logMessage(WARNING, "The file's metadata failed to stripped." + std::to_string(lastError));
    }
#else
    try {
        ssize_t len = listxattr(filePath.c_str(), nullptr, 0, 0); // Retrieves length of attributes
        if (len > 0) { // Iterates through file attributes and removes them
            std::vector<char> attrs(len); // Dynamically allocates attribution size to size of len
            len = listxattr(filePath.c_str(), attrs.data(), attrs.size(), 0); // Gets length again and writes data to attrs variable
            for (ssize_t i = 0; i < len; i += strlen(&attrs[i]) + 1) { // Iterates 'len' times though 'attrs'
                removexattr(filePath.c_str(), &attrs[i], 0); // Remove attr number 'i'
            }
        }
    } catch (...) {
        logMessage(WARNING, "Failed to get and remove file attributes.");
    }
#endif
}

#ifdef OPENSSL_FOUND
    std::string computeSHA256(const std::string& data) { // Gets SHA256 hash
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new(); // Initializes context
        const EVP_MD *md = EVP_sha256(); // Sets mode to SHA256
        unsigned char hash[EVP_MAX_MD_SIZE]; // Buffer for hash
        unsigned int hashLen; // Length for hash

        if (mdctx == nullptr) { // If it failed to initialize
            logMessage(ERROR, "Failed to create OpenSSL EVP context for SHA256.");
            return "";
        }

        if (EVP_DigestInit_ex(mdctx, md, nullptr) != 1) { // Initialize the context with the mode
            EVP_MD_CTX_free(mdctx); // Frees context
            logMessage(ERROR, "Failed to initialize OpenSSL SHA256 context.");
            return "";
        }

        if (EVP_DigestUpdate(mdctx, data.c_str(), data.length()) != 1) { // Updates the hash with data
            EVP_MD_CTX_free(mdctx);
            logMessage(ERROR, "Failed to update OpenSSL SHA256 context.");
            return "";
        }

        if (EVP_DigestFinal_ex(mdctx, hash, &hashLen) != 1) { // Finalizes hash calculation
            EVP_MD_CTX_free(mdctx);
            logMessage(ERROR, "Failed to finalize OpenSSL SHA256 hash.");
            return "";
        }

        EVP_MD_CTX_free(mdctx); // Frees the context

        std::ostringstream hexStream; // Opens output stringstream for hex-formatted hash
        for (unsigned int i = 0; i < hashLen; ++i) {  // Iterates through the hash and formats as hex
            hexStream << std::setw(2) << std::setfill('0') << std::hex << (int)hash[i];
        }

        return hexStream.str();
    }

    int verifyWithHash(const std::string& filePath, const std::vector<char>& expectedData, const int& pass) {
        std::ifstream file(filePath, std::ios::binary); // Opens input (binary) stream for file (rb)
        if (!file.is_open()) { // If the file doesn't open
            logMessage(ERROR, "File " + filePath + "failed to open for hashing. Attempting fallback..");
            return 1; // Triggers fallback initiation for calling function
        }
        std::string fileContent((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>()); // Retrieves files contents
        file.close(); // Closes file

        std::string fileHash = computeSHA256(fileContent); // Calculates hash from file data
        std::string expectedHash = computeSHA256(std::string(expectedData.begin(), expectedData.end())); // Calculates hash from saved data

        if (fileHash == expectedHash) { // Only if they are identical will we say it succeeded
            logMessage(INFO, "Successfully verified file hash for '" + filePath + "' on pass " + std::to_string(pass));
        } else {
            logMessage(WARNING, "Hash mismatch for '" + filePath + "' on pass " + std::to_string(pass));
            return 2; // Triggers verification failed for calling function
        }
        return 0; // Triggers verification success
    }
#endif

bool shredFile(const fs::path& filePath) {
    try {
        verificationFailed = 0;
        if (dry_run) { // Triggers if not deleting
            if (fs::is_symlink(filePath) && !follow_symlinks) { // Iterates through options for a reliable file iteration
                logMessage(DRY_RUN, "Symlink file '" + filePath.string() + "' would not be shredded.");
            } else {
            logMessage(DRY_RUN, "Simulating shredding file '" + filePath.string() + "'");
            }
            
            return true;
        } else if (fs::is_symlink(filePath) && follow_symlinks) {
            auto target = fs::read_symlink(filePath);
            if (!fs::exists(target)) {
                logMessage(WARNING, "Dangling symlink (not followed): '" + filePath.string() + "'");
                return false;
            } else {
                fs::path filePath = target;
                return true;
            }
        }

        if (fs::is_empty(filePath)) {
            logMessage(ERROR, "File '" + filePath.string() + "' is empty and will not be shredded.");
            return false;
        }

        // Gets file permissions, aborts if not found
        bool writePermission = hasWritePermission(filePath); // Retrieve write permission status
        if (!writePermission && force_delete) { // Only if force_delete flag is set
            logMessage(INFO, "There are no write permissions for '" + filePath.string() + "'");
            changePermissions(filePath); // If file permission modification succeeds, set write permission
        }
        if (!writePermission && !failedToRetrievePermissions) { logMessage(ERROR, "No write permissions for file '" + filePath.string() + "'"); return false; }

        if (fs::file_size(filePath) == 0) { // Skip the shredding of empty files, delete them immediately.
            if (!keep_files) {
                logMessage(INFO, "File '" + filePath.string() + "' is empty and will be deleted without overwriting.");
                if (std::remove(filePath.c_str()) == 0) {
                    logMessage(INFO, "Empty file '" + filePath.string() + "' successfully deleted.");
                } else {
                    logMessage(ERROR, "Failed to delete empty file '" + filePath.string() + "'");
                    return false;
                }
            } else {
                logMessage(WARNING, "File '" + filePath.string() + "' is empty and will not be overwritten.");
            }
            return true;
        }

        auto fileSize = fs::file_size(filePath); // get size of file (to know how much to overwrite)
        std::fstream file; // fstream instead ofstream to prevent appending
        int attempts = 0;

        while (attempts < 10) { // Attempts to open file 10 times before quitting (relic now since obsolescense of multithreading [functionality impacts])
            file.open(filePath, std::ios::binary | std::ios::in | std::ios::out);
            if (file) { // If file opens, continue
                break;
            } else { // Otherwise, log the attempt, wait 1/2 second, and try again.
                attempts++;
                logMessage(WARNING, "Failed to open file '" + filePath.string() + "' for overwriting.");
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
        }

        if (!file) { // After the attempts if the file still isn't open, log the error and exit function
            logMessage(ERROR, "Failed to open file '" + filePath.string() + "' after 10 attempts. Skipping.");
            return false;
        }

        for (int i = 0; i < overwriteCount; ++i) { // Call shredder for amount specified in overwriteCount
            file.seekp(0, std::ios::beg); // Move to beginning of buffer (file)
            if (overwriteWithRandomData(filePath.string(), file, fileSize, i + 1) == 1) {
                verificationFailed = 1; // Overwrite function returns 1 if verification fails
            }
            logMessage(INFO, "Completed overwrite pass " + std::to_string(i + 1) + " for file '" + filePath.string() + "'"); // Prints pass count
            std::cout << "Progress: " << std::fixed << std::setprecision(1)  // Percent-style progress meter
                      << ((i + 1) / static_cast<float>(overwriteCount)) * 100 << "%\r" << std::flush;
        }

        if (internal && verificationFailed || verbose && verificationFailed) { logMessage(WARNING, "Overwrite verification failed for '" + filePath.string() + "' Skipping deletion."); } // Prints verification failure, only if verbose because overwrite function says it too.
        file.close(); // Close file, if completed
        syncFile(filePath); // Force filesystem synchronization

        bufferSizePrinted = false; // Reset for next file
        
        if (!keep_files && !verificationFailed) { // Delete file after shredding (if not keeping)
            std::string obfuscatedPath;
            try {
                std::unique_lock<std::mutex> lock(fileMutex); // Acquire file lock

                fs::permissions(filePath, fs::perms::none); // Remove file permissions

                std::string randomFileName = generateRandomFileName(); // Get a random name
                obfuscatedPath = fs::temp_directory_path() / randomFileName; // Make a temp path and add the random name
                fs::rename(filePath, obfuscatedPath); // Move the file to the new temp directory with the random name

                std::this_thread::sleep_for(std::chrono::milliseconds(50)); // Sleep to wait for new metadata to propagate
                cleanupMetadata(obfuscatedPath); // Cleanup metadata
                std::this_thread::sleep_for(std::chrono::milliseconds(50)); // Same as above
            } catch (...) {
                std::cerr << "An error has occured while obfuscating metadata on the file '" << filePath.string() << "'" << std::endl;
            }

            if (std::remove(obfuscatedPath.c_str()) == 0 || std::remove(filePath.c_str()) == 0) { // If successfully deleted
                if (verify) { logMessage(INFO, "File '" + filePath.string() + "' shredded, verified, and deleted."); }
                    else if (!verify) { logMessage(INFO, "File '" + filePath.string() +"' shredded and deleted without verification."); }
            } else { // Or not
                logMessage(ERROR, "Failed to delete file '" + filePath.string() + "'");
                return false;
            }
        } else {
            logMessage(INFO, "File '" + filePath.string() + "' overwritten without deletion."); // Keep file mode
        }
        return true;
        
    } catch (const fs::filesystem_error& e) {
        logMessage(ERROR, "Filesystem error: " + std::string(e.what()));
        return false;
    } catch (...) {
        logMessage(ERROR, "An unknown error occured in shredFile()");
        return false;
    }
}

int overwriteWithRandomData(std::string filePath, std::fstream& file, std::uintmax_t fileSize, int pass) {
    const std::uintmax_t bufferSize = getOptimalBlockSize();  // Get the block size
    std::vector<char> buffer(bufferSize); // Set buffersize to retrieved value (block size)

    // Patterns for DoD compliance and additional security
    std::vector<std::string> patterns = {
        std::string(bufferSize, '\x00'),  // Pass of 0x00 (00000000 in binary)
        std::string(bufferSize, '\xFF'),  // Pass of 0xFF (11111111 in binary)
        std::string(bufferSize, '\xAA'),  // Pass of 0xAA (10101010 in binary)
        std::string(bufferSize, '\x55'),  // Pass of 0x55 (01010101 in binary)
        std::string(bufferSize, '\x3D'),  // Pass of 0x3D (00111101 in binary)
        std::string(bufferSize, '\xC2'),  // Pass of 0xC2 (11000010 in binary)
        std::string(bufferSize, '\x8E'),  // Pass of 0x8E (10001110 in binary)
        std::string(bufferSize, '\x4E')   // Pass of 0x4E (01001110 in binary)
    };

    int securePasses = patterns.size();  // Number of secure passes (to change add/remove from patterns array)
    

    // Secure random generator
    std::random_device rd; // Opens a random device
    std::mt19937 gen(rd()); // Set the random device to generate
    std::uniform_int_distribution<> dist(0, 255); // Sets even distribution for data generation
    std::vector<char> lastRandomData(fileSize); // For verification

    for (std::uintmax_t offset = 0; offset < fileSize; offset += bufferSize) {
        std::uintmax_t writeSize = std::min(bufferSize, fileSize - offset); // Finds writesize
        
        // Generate random data for non-secure or final pass
        if (!secure_mode) {
            std::generate(buffer.begin(), buffer.end(), [&]() { return static_cast<char>(dist(gen)); }); // Generates it
            if (verify) { std::copy(buffer.begin(), buffer.begin() + writeSize, lastRandomData.begin() + offset); } // Copies the verification
            file.seekp(offset); // Moves to offset
            file.write(buffer.data(), writeSize);  // Writes buffer with retrieved size
        } else {
            // Secure shredding mode with multiple patterns (defined and random, plus DoD standards)
            for (int pass = 0; pass < securePasses; ++pass) {
                gen.seed(rd() + pass + offset); // Re-seed with the pass and offset
                
                // Apply a pre-set pattern
                std::memcpy(buffer.data(), patterns[pass].data(), bufferSize); // Copy pattern (number 'pass') to buffer9
                file.seekp(offset); // Move to offset
                file.write(buffer.data(), writeSize); // Write buffer to file

                // Introduce random pattern for every other pass for additional security
                if (pass % 2 == 1) {
                    std::generate(buffer.begin(), buffer.end(), [&]() { return static_cast<char>(dist(gen)); });
                    file.seekp(offset);
                    file.write(buffer.data(), writeSize);
                }
            }

            // DoD-required passes
            // Pass 1: Overwrite with 0x00
            std::fill(buffer.begin(), buffer.end(), '\x00'); // Fills buffer
            file.seekp(offset); // Moves to offset
            file.write(buffer.data(), writeSize); // Writes buffer to file

            // Pass 2: Overwrite with 0xFF
            std::fill(buffer.begin(), buffer.end(), '\xFF');
            file.seekp(offset);
            file.write(buffer.data(), writeSize);

            // Pass 3: Overwrite with random data
            std::generate(buffer.begin(), buffer.end(), [&]() { return static_cast<char>(dist(gen)); }); // Fills buffer with random data
            if (verify) { std::copy(buffer.begin(), buffer.begin() + writeSize, lastRandomData.begin() + offset); }
            file.seekp(offset);
            file.write(buffer.data(), writeSize);
            if (internal) { logMessage(INTERNAL, "Successfully wrote all DoD passes to block"); }
        }
    }
    if (internal && !bufferSizePrinted) { logMessage(INTERNAL, "Blocksize: " + std::to_string(bufferSize)); bufferSizePrinted = true; }
    if (verify) {
        int ret = 1; // Return value (default as "fail")
        file.flush(); // Ensure all writes are complete
        file.seekg(0); // Reset to beginning for verification

        std::vector<char> verifyBuffer(bufferSize);
        verificationFailed = false; // Initializes boolean that determines if file verification failed
#ifdef OPENSSL_FOUND
        ret = verifyWithHash(filePath, lastRandomData, pass); // Verify hash
        if (ret == 2) { verificationFailed = true; } // If failed
        if (ret == 0) { return 0; } // If successful
#endif
    if (ret == 1) { // If it failed or OpenSSL is not defined, use fallback verification
        for (std::uintmax_t offset = 0; offset < fileSize; offset += bufferSize) {
            std::uintmax_t readSize = std::min(bufferSize, fileSize - offset); // Gets size to read
            file.read(verifyBuffer.data(), readSize); // Reads the control

            // Check if the data is consistent with erasure (e.g., all zeroes after overwrite)
            if (!std::equal(verifyBuffer.begin(), verifyBuffer.begin() + readSize, lastRandomData.begin() + offset)) {
                if (verbose) { std::cerr << "Verification failed at offset: " << offset << '\n'; }
                verificationFailed = true; // If it is not equal, fail
                break;
            }
        }
    }
        if (verificationFailed) { return 1; } // This will export to the other function for altered behavior
    }
    return 0; // Exports success
}

bool hasWritePermission(const fs::path& path) {
#ifdef _WIN32
    // Windows-specific write permission check using CreateFile
    DWORD dwDesiredAccess = GENERIC_WRITE; // Set write permission as desired
    DWORD dwError = 0; // Initialize error variable
    HANDLE hFile = CreateFile(path.c_str(), dwDesiredAccess, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL); // Gets file info

    if (hFile == INVALID_HANDLE_VALUE) { // Trigger for incorrectly opened handles
        dwError = GetLastError(); // Gets error value
        if (dwError == ERROR_ACCESS_DENIED) { // If it is because of wrtie permissions, it will fail
            logMessage("WARNING", "Access denied for file '" + path.string() + "'");
            failedToRetrievePermissions = true;
            return false;
        }
    } else {
        CloseHandle(hFile); // Closes handle and returns has write permission
        return true;
    }
    return false;
#else
    // POSIX (Linux/macOS) write permission check
    std::error_code ec; // Opens an error code
    fs::file_status status = fs::status(path, ec); // Copies the file information (status) into the file_status struct status (uses error code)
    if (ec) { // If there is an error retrieving the file status
        logMessage(ERROR, "Failed to retrieve permissions for '" + path.string() + "': " + ec.message());
        failedToRetrievePermissions = true;
        return false;
    }

    auto perms = status.permissions(); // Extracts file permissions from the file_status structure status

    struct stat fileStat; // Creates a structure following the stat structure
    if (stat(path.c_str(), &fileStat) == -1) { // Gets file status (information) and copies it into the fileStat structure
        logMessage(ERROR, "Failed to get file status for '" + path.string() + "'");
        failedToRetrievePermissions = true;
        return false;
    }

    uid_t fileOwner = fileStat.st_uid; // Gets file owner
    gid_t fileGroup = fileStat.st_gid; // Gets file group

    uid_t currentUser = getuid(); // Gets current user id
    gid_t currentGroup = getgid(); // Gets current group id

    bool isOwner = (currentUser == fileOwner); // Checks if current user is file owner
    bool isInGroup = (currentGroup == fileGroup); // Checks if current user is in file group

    writePermission = false; // By default, no permissions

    // Iterates through perms looking for the respective write permissions
    if (isOwner) { // Checks for owner write, if owner
        writePermission = (perms & fs::perms::owner_write) != fs::perms::none;
    } else if (isInGroup) { // Checks for group write, if in group
        writePermission = (perms & fs::perms::group_write) != fs::perms::none;
    } else { // Checks for others write, if neither owner or in group
        writePermission = (perms & fs::perms::others_write) != fs::perms::none;
    }

    if (geteuid() == 0) { writePermission = true; } // If root, bypass this check

    return writePermission;
#endif
}

bool changePermissions(const std::string &filePath) {
    try {
        bool isExecutable = false; // Boolean to store if the file is executable
        logMessage(INFO, "Attempting to add write permissions to '" + filePath + "'");
#ifdef _WIN32
        // On Windows, remove read-only attribute
        DWORD attributes = GetFileAttributes(filePath.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES) { // If the attributes are invalid
            logMessage(ERROR, "Failed to retrieve file attributes for '" + filePath + "'");
            return false;
        }
        if (attributes & FILE_ATTRIBUTE_READONLY) { // If one of the attributes are read-only
            if (SetFileAttributes(filePath.c_str(), attributes & ~FILE_ATTRIBUTE_READONLY)) { // If it unsets read-only
                logMessage(INFO, "Removed read-only attribute on file '" + filePath + "'");
                failedToRetrievePermissions = true; // Ignore this variable, it is to trick the computer because I don't know XD (seriously though, keep it as is, unless you know better)
            } else {
                logMessage(ERROR, "Failed to remove read-only attribute on file '" + filePath "'");
                return false;
            }
        }

        // Creates a temporary file with attributes from the other file, then tests its write privileges
        HANDLE fileHandle = CreateFile(filePath.c_str(), GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (fileHandle != INVALID_HANDLE_VALUE) {
            CloseHandle(fileHandle);
            logMessage(INFO, "Write access verified on file '" + filePath + "'");
            return true;
        }
#else
        struct stat fileStat; // Creates a stat structure for the file
        if (stat(filePath.c_str(), &fileStat) == 0) { // If it successfully gets the stats
            isExecutable = (fileStat.st_mode & S_IXUSR) || (fileStat.st_mode & S_IXGRP); // Checks for owner or group execution privileges and sets the boolean accordingly
        } else {
            logMessage(WARNING, "Failed to obtain stats on file '" + filePath + "'");
        }

        // On POSIX systems, ensure full permissions
        int ret = 0; // To store the exit result

        if (isExecutable) { // Determines whether to change the permissions with execute or not
            ret = chmod(filePath.c_str(), S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IWOTH | S_IXOTH);
        } else {
            ret = chmod(filePath.c_str(), S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
        }

        if (ret == 0) { // Based on exit value of chmod
            logMessage(INFO, "Permissions updated on file '" + filePath + "'");
        } else {
            logMessage(ERROR, "Permissions failed to change on file '" + filePath + "'");
            return false;
        }
#endif
        // Attempt to remove extended attributes (Linux/macOS)
#ifndef _WIN32
        logMessage(INFO, "Clearing extended attributes on file '" + filePath + "'");

        // Extended attributes are system-dependent, handled here if supported
        if (system(("xattr -c \"" + filePath + "\" 2>/dev/null").c_str()) == 0) { // Mac / Linux
            logMessage(INFO, "Extended attributes cleared on file '" + filePath + "'");
        } 
        else if (system(("attr -r \"\" \"" + filePath + "\" 2>/dev/null").c_str()) == 0) { // Linux
            logMessage(INFO, "Extended attributes cleared on file '" + filePath + "'");
        } 
        else { // no
            logMessage(WARNING, "Failed to clear extended attributes on file '" + filePath + "'");
        }
#endif
        if (access(filePath.c_str(), W_OK) == 0) { // If the file has write permissions
            logMessage(INFO, "Write access verified on file '" + filePath + "'");
            writePermission = true;
            failedToRetrievePermissions = true; // Ignore this boolean (important)
            return true;
        }
    } catch (const fs::filesystem_error) {
        logMessage(ERROR, "Filesystem error for file '" + filePath + "'");
    } catch (const std::exception) {
        logMessage(ERROR, "Error on file '" + filePath + "'");
    }

    return false;
}

void help(char* argv[]) { // The print help functon (At bottom due to size and lack of functionality)
    std::cerr << "NAME\n";
    std::cerr << "    " << argv[0] << " - Securely overwrite and remove files\n\n";

    std::cerr << "SYNOPSIS\n";
    std::cerr << "    " << argv[0] << " [OPTIONS] <file1> <file2> ...\n\n";

    std::cerr << "DESCRIPTION\n";
    std::cerr << "    " << argv[0] << " is a tool designed to securely overwrite and remove files and directories.\n";
    std::cerr << "    By default, it overwrites the specified files with random data and removes them, ensuring that\n";
    std::cerr << "    data is unrecoverable. The tool offers various options for customizing the shredding process.\n";
    std::cerr << "    This tool almost conforms to DoD 5220.22-M when the '-s' flag is used without the '-c' flag, and\n";
    std::cerr << "    this tool does not conform due to the unnecessary complexity (which enhances the security of the shred).\n";
    std::cerr << "    This program will exit 2 on this dialogue, 1 on failure, and 0 on success.\n\n";

    std::cerr << "OPTIONS\n";
    std::cerr << "    -n <overwrites>       Set number of overwrites (default: 3)\n";
    std::cerr << "    -r <recursive>        Enable recursive mode to shred directories and their contents\n";
    std::cerr << "    -k <keep files>       Keep files after overwriting (no removal)\n";
    std::cerr << "    -v <verbose>          Enable verbose output for detailed logging\n";
    std::cerr << "    -e <follow symlinks>  Follow symlinks during shredding\n";
    std::cerr << "    -s <secure mode>      Enable secure shredding with randomization (slower)\n";
    std::cerr << "    -d <dry run>          Show what would be shredded without actual processing\n";
    std::cerr << "    -c <no verification>  Skip post-shredding verification (faster)\n";
    std::cerr << "    -f <force>            Force delete the files if there is no write permission\n\n";

    std::cerr << "DESCRIPTION OF OPTIONS\n";
    std::cerr << "    -n <overwrites>\n";
    std::cerr << "        Specifies the number of overwriting passes. By default, 3 passes are performed, but you can increase\n";
    std::cerr << "        this number for higher security. More passes will make the process slower.\n\n";

    std::cerr << "    -r <recursive>\n";
    std::cerr << "        Enables recursive mode. If set, the program will shred the contents of directories as well as the\n";
    std::cerr << "        files themselves. Without this flag, only files are processed.\n\n";

    std::cerr << "    -k <keep files>\n";
    std::cerr << "        If set, files will be overwritten with random data, but they will not be deleted. This option is useful\n";
    std::cerr << "        if you want to securely wipe a file's contents but retain the file itself.\n\n";

    std::cerr << "    -v <verbose>\n";
    std::cerr << "        Enables verbose output, printing detailed information about each step of the shredding process.\n";
    std::cerr << "        Useful for debugging or confirming that the program is functioning as expected.\n\n";

    std::cerr << "    -e <follow symlinks>\n";
    std::cerr << "        Follow symbolic links and include them in the shredding process. Without this flag, symlinks are ignored.\n\n";

    std::cerr << "    -s <secure mode>\n";
    std::cerr << "        Enables secure shredding with byte-level randomization, making data recovery significantly more difficult.\n";
    std::cerr << "        This mode is slower due to the added security, but it provides stronger protection against data recovery.\n\n";

    std::cerr << "    -d <dry run>\n";
    std::cerr << "        Simulates the shredding process without performing any actual deletion. Use this to verify which files\n";
    std::cerr << "        would be affected before running the program for real.\n\n";

    std::cerr << "    -c <no verification>\n";
    std::cerr << "        Disables the post-shredding file verification. Normally, the tool verifies that files have been overwritten\n";
    std::cerr << "        after shredding, but this step can be skipped with this option for faster operation.\n\n";

    std::cerr << "    -f <force>\n";
    std::cerr << "        Will attempt to change file permissions and remove extended attributes to attempt to delete files which\n";
    std::cerr << "        do not currently have effective write permission, use this for stubborn files.\n\n";

    std::cerr << "EXAMPLES\n";
    std::cerr << "    " << argv[0] << " -n 5 -r -v -s file1.txt file2.txt directory1\n";
    std::cerr << "        Overwrites 'file1.txt' and 'file2.txt' with 5 passes, recursively handles 'directory1', and uses secure\n";
    std::cerr << "        mode with verbose output.\n\n";

    std::cerr << "    " << argv[0] << " -d file1.txt file2.txt\n";
    std::cerr << "        Performs a dry run to show what would be shredded without actual deletion.\n\n";

    std::cerr << "COPYRIGHT\n";
    std::cerr << "    File and directory shredder. It shreds files and directories specified on the command line.\n";
    std::cerr << "    Copyright (C) 2024  Aristotle Daskaleas\n\n";
    std::cerr << "    This program is free software: you can redistribute it and/or modify\n";
    std::cerr << "    it under the terms of the GNU General Public License as published by\n";
    std::cerr << "    the Free Software Foundation, either version 3 of the License, or\n";
    std::cerr << "    (at your option) any later version.\n\n";
    std::cerr << "    This program is distributed in the hope that it will be useful,\n";
    std::cerr << "    but WITHOUT ANY WARRANTY; without even the implied warranty of\n";
    std::cerr << "    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n";
    std::cerr << "    GNU General Public License for more details.\n\n";
    std::cerr << "    You should have received a copy of the GNU General Public License\n";
    std::cerr << "    along with this program.  If not, see <https://www.gnu.org/licenses/>.\n";
}