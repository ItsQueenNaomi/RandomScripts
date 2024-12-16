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
Version: 10.4c
Author: Aristotle Daskaleas (2024)
Changelog (since v10):
    -> As of version 10, format of version is now XX.Xx where X ~ [0-9] and x ~ [a-z]
    -> Added a couple more comments and squashed a bug pertaining to the new uniform initializaion
    -> Added a short help menu which will come up with the traditional -h|--help flag and a -H|--full-help flag to access the full help menu
10.1-> Moved the copyright to a new flag -C|--copyright
    -> Moved all global booleans into structures with friends for specific access control
    -> Added Secure Random Data generation with an RNG class (bcrypt/urandom entropy)
    -> Renamed repeated variables
    -> Moved old version changelog (v1-v10) into a history file
    -> Fixed a grammatical mistake on the help menu
    -> Updated the 'examples' section of the help menu to include examples with long flags
10.2-> Fixed extensive bugs as a result of the structures
    -> Added functions to the stat and moved the declaration of hashStat to after it was structured
    -> Converted all publicly accessible variables in the structures to constant functions
    -> Added a fallback in case the new rng class fails to generate data
    -> Refactored structures and improved readability
    -> Modified permission checking functions to include 'read' permissions
10.3-> Changed the way permission checking was handled to reduce false-positives and negatives
    -> Since the boolean for write permissions are handled globally, changed hasWritePermissions return from bool to int
    -> Squashed a bug pertaining to write permissions and the force flag
    -> Made long flags case insensitive (e.g., --help == --HeLp == --hELp), of course short flags need to be case-sensitive (e.g., '-h' and '-H' have different effects)
    -> Fixed inconsequential bugs and reduced verbose logging
10.4-> Improved general operability; ensured correctness of log levels
    -> Reduced redundancy in namespaces/functions
    -> Fixed overlooked bug pertaining to exit status - implemented a program structure with an error bool and modified end of main() function to incorporate the structure
To-do:
    -> Nothing.

Current full compilation flags: -std=c++20 -DOPENSSL_FOUND -L/path/to/openssl/lib -I/path/to/openssl/include -lssl -lcrypto
*/

const char VERSION[]{"10.4c"}; // Define program version for later use
const char CW_YEAR[]{"2024"}; // Define copyright year for later use

#include <iostream>       // For console logging
#include <fstream>        // For file operations (reading/writing)
#include <iomanip>        // For formatting log files
#include <filesystem>     // For file/directory operations (stats)
#include <random>         // For generating random data
#include <chrono>         // For time measurements
#include <string>         // For string manipulation
#include <mutex>          // For secure file name generation
#include <vector>         // For buffer storage
#include <cstring>        // For std::memcpy
#include <thread>         // For sleeping (std::this_thread::sleep_for)
#include <algorithm>      // For std::transform
#include <stdexcept>      // For exceptions
#include <cstdlib>        // For environment variables
#include <unordered_map>  // For unordered maps
#include <functional>     // For lambda functions within maps
#include <memory>         // For dynamic pointers

#ifdef __linux__
#include <sys/statvfs.h>  // For block size retrieval
#endif

#ifdef _WIN32
#include <windows.h>      // Windows library that allows for block size retrieval
#include <winbase.h>      // For file deletion
#include <aclAPI.h>       // For file permissions
#include <sddl.h>         // For security descriptor strings
#include <bcrypt.h>       // For secure data generation via entropy
#pragma comment(lib, "bcrypt.lib") // Links against bcrypt
#endif

#ifdef __APPLE__
#include <sys/sysctl.h>   // System info
#include <sys/mount.h>    // File system info
#endif

#if defined(__APPLE__) || defined(__linux__)
#include <sys/stat.h>     // File information
#include <sys/xattr.h>    // Extended attributes
#include <unistd.h>       // POSIX operations
#include <fcntl.h>        // For secure random data generation from urandom
#endif

#ifdef OPENSSL_FOUND
#include <openssl/evp.h>  // For hashing
bool isOpenSSL{true}; // Boolean to determine if OpenSSL is found
#else
bool isOpenSSL{false}; // Boolean to determine if OpenSSL is found
#endif

namespace fs = std::filesystem; // Makes linking commands from the 'std::filesystem' easier

// Script configuration (defaults; mutable only by parseArguments(...))
struct config {
private:
    friend std::vector<std::string> parseArguments(int argc, char* argv[]);

    int overwriteCount{3}; // integer to indicate number of passes to shred the file
    bool recursive{false}; // boolean to indicate whether directories are shredded or just files
    bool keep_files{false}; // boolean to indicate whether files are deleted after shredding or not
    bool verbose{false}; // boolean to indicate verbosity
    bool follow_symlinks{false}; // boolean to indicate whether symbolic links will be followed or not
    bool secure_mode{false}; // boolean to indicate shredding mode
    bool dry_run{false}; // boolean to indicate if any files will actually be shredded
    bool verify{true}; // boolean to indicate verification after shredding
    bool force_delete{false}; // boolean to indicate force delete attempt
    bool internal{false}; // boolean to indicate whether scripting information is revealed

    void updateCount(const int value) {
        overwriteCount = value;
    }

    void updateFlag(const std::string& name, bool value) {
        // Convert name to lowercase for case-insensitive comparison
        std::string lowerName = name;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

        if (lowerName == "recursive") recursive = value;
        else if (lowerName == "keep_files") keep_files = value;
        else if (lowerName == "verbose") verbose = value;
        else if (lowerName == "dry_run") dry_run = value;
        else if (lowerName == "secure_mode") secure_mode = value;
        else if (lowerName == "verify") verify = value;
        else if (lowerName == "force_delete") force_delete = value;
        else if (lowerName == "internal") internal = value;
        else if (lowerName == "follow_symlinks") follow_symlinks = value;
        else std::cerr << "INTERNAL ERROR: \"'" + name + "' is not valid in the context of updateFlag()\"" << std::endl;
    }
public:
    const bool& isInternal() const {return internal;};
    const bool& isForce_delete() const {return force_delete;};
    const bool& isVerify() const {return verify;};
    const bool& isDry_run() const {return dry_run;};
    const bool& isSecure_mode() const {return secure_mode;};
    const bool& isFollow_symlinks() const {return follow_symlinks;};
    const bool& isVerbose() const {return verbose;};
    const bool& isKeep_files() const {return keep_files;};
    const bool& isRecursive() const {return recursive;};
    const int& getOverwriteCount() const {return overwriteCount;};
};

// Write permission boolean(s) to indicate if the file being processed has write permissions
struct wPerm {
private:
    friend int hasWritePermission(const fs::path& path);
    friend bool changePermissions(const std::string &filePath);

    bool failedToRetrievePermissions{false}; // boolean to indicate if permissions were successfully retrieved
    bool writePermission{false}; // boolean to determine if the current file being processed has write permissions
    bool readPermission{false}; // boolean to determine if the current file beign processed has read permissions
    void updateWritePerm(bool value) { writePermission = value; }
    void updateReadPerm(bool value) { readPermission = value; }
    void updateFailedToGetPerm(bool value) { failedToRetrievePermissions = value; }
public:
    const bool& isWritePerm() const {return writePermission;} // read-only determination of value of writePermission
    const bool& isReadPerm() const {return readPermission;} // read-only determination of value of readPermission
    const bool& failedWritePerm() const {return failedToRetrievePermissions;} // read-only determination of failedToRetrievePermissions
};

// Structure with boolean(s) associated with the --internal flag
struct internal {
private:
    friend bool shredFile(const fs::path& filePath);
    friend int overwriteWithRandomData(std::string filePath, std::fstream& file, std::uintmax_t fileSize, int pass);

    bool bufferSizePrinted{false}; // Global boolean to indicate if the buffer size was already printed
    void updateBufferPrintStatus(bool value) {bufferSizePrinted = value;}
public:
    const bool& wasBufferPrinted() const {return bufferSizePrinted;}
};

// Structure with boolean(s) associated with program functionality / success
struct pgrm {
private:
    bool isProgramError{false};
public:
    void updateErrorStatus() {isProgramError = true;}
    const bool& isError() const {return isProgramError;}
};

// Secure random data generation class
class secureRandom {
public:
    secureRandom() = default;

    std::vector<unsigned char> generate(size_t size) {
        std::vector<unsigned char> buffer(size);

#ifdef _WIN32
        NTSTATUS status = BCryptGenRandom(
            NULL,                           // Use default RNG algorithm
            buffer.data(),                  // Destination buffer
            static_cast<ULONG>(size),       // Buffer size
            BCRYPT_USE_SYSTEM_PREFERRED_RNG // Use system RNG
        );
        if (status != STATUS_SUCCESS) {
            throw std::runtime_error("BCryptGenRandom failed to generate secure random data.");
        }
#else
        std::ifstream urandom("/dev/urandom", std::ios::in | std::ios::binary);
        if (!urandom) {
            throw std::runtime_error("Failed to open /dev/urandom for secure random data generation.");
        }
        urandom.read(reinterpret_cast<char*>(buffer.data()), size);
        if (!urandom) {
            throw std::runtime_error("Failed to read random data from /dev/urandom");
        }
#endif
        return buffer;
    }
};

// Declares structures in global scope so all functions reference the same structure
config Config;
wPerm wc;
internal ic;
pgrm Program;

std::mutex fileMutex; // Defines file name generation lock

enum logLevel { // Define valid log levels
    INFO, // Level to inform with verbosity (i.e., every action)
    WARNING, // Level to inform a non-critical error
    ERROR, // Level to indicate core operational errors
    DRY_RUN, // Only used with '-d|--dry' flag
    INTERNAL // Only used with '--internal' flag
};

// Prototype declarations for refactoring
#ifdef OPENSSL_FOUND // Only declares these prototypes if compiling with OpenSSL (since it would be required)
    int verifyWithHash(const std::string& filePath, const std::vector<unsigned char>& expectedData, const int& pass);
    std::string computeSHA256(const std::vector<unsigned char>& data);
    struct hashStat {
    private:
        friend int verifyWithHash(const std::string& filePath, const std::vector<unsigned char>& expectedData, const int& pass);
        bool isVerified{false};
        void updateVerification(bool value){isVerified = value;}
    public:
        bool Verified(){return isVerified;}
    };
    hashStat hash;
#endif

void help(char* argv[]);
void shortHelp(char* argv[]);
void copyright(char* argv[]);
void version(char* argv[]);

int overwriteWithRandomData(std::string filePath, std::fstream& file, std::uintmax_t fileSize, int pass = 1);

bool shredFile(const fs::path& filePath);
int hasWritePermission(const fs::path& path);
bool changePermissions(const std::string &filePath);

void processPath(const fs::path& path);
void syncFile(const fs::path& filePath);
void logMessage(logLevel type, const std::string& message);
void errorExit(int value = 1, std::string message = "", std::string flag = "", bool customLogger = false);
void cleanupMetadata(std::string& filePath);

std::vector<std::string> parseArguments(int argc, char* argv[]);
std::uintmax_t getOptimalBlockSize();
std::string generateRandomFileName(size_t length = 32);

bool isRegularFile(const fs::path& file) { return fs::is_regular_file(file); } // Function to check if a path is a regular file

int main(int argc, char* argv[]) {
    std::vector<std::string> fileArgs{parseArguments(argc, argv)}; // Initialize vector with arguments
    if (Config.isInternal()) { // Funny extra feature for people in the know about this flag (outputs parameters, files, and a confirmation)
        // Sets flags to strings for readability
        std::string recursiveStr{Config.isRecursive() ? "true" : "false"};
        std::string keep_filesStr{Config.isKeep_files() ? "true" : "false"};
        std::string follow_symlinksStr{Config.isFollow_symlinks() ? "true" : "false"};
        std::string secure_modeStr{Config.isSecure_mode() ? "true" : "false"};
        std::string dry_runStr{Config.isDry_run() ? "true" : "false"};
        std::string verifyStr{Config.isVerify() ? "true" : "false"};
        std::string force_deleteStr{Config.isForce_delete() ? "true" : "false"};

        // Prints set options
        std::cout << "Parameters ~ Overwrites: " << Config.getOverwriteCount() << ", Recursive: " << recursiveStr << ", Keep_files: " << keep_filesStr << ", Follow_symlinks: " << follow_symlinksStr << ", Secure_mode: " << secure_modeStr << ", Dry_run: " << dry_runStr << ", Verify: " << verifyStr << ", Force: " << force_deleteStr << std::endl;
        std::cout << "Files: " << std::endl;
        for (const auto& filePath : fileArgs) { std::cout << filePath << std::endl; } std::cout << std::endl; // Prints file names
        
        // Prompt to continue the script with the printed options / files
        std::cout << "Continue? (y/N)" << std::endl;
        std::string reply; // Declare reply variable for confirmation
        std::getline(std::cin, reply); // getline may be extra, since input is one character or 2-3 letters (not line)
        std::transform(reply.begin(), reply.end(), reply.begin(), ::tolower); // Transforms case into lowercase
        if (reply == "y") { } else if (reply == "yes") { } else { return 3; } // Unless 'y' or 'yes' is specified, we're done
    }

    auto startT{std::chrono::system_clock::now()}; // For start time (printed at start of program)
    auto startTime{std::chrono::high_resolution_clock::now()}; // For end time (when it is subtracted later)

    std::time_t start_time_t{std::chrono::system_clock::to_time_t(startT)}; // Retrieves current time
    std::tm local_tm{*std::localtime(&start_time_t)}; // Converts it to local time

    std::cout << "Beginning Shred at: " << std::put_time(&local_tm, "%H:%M:%S") << std::endl; // Prints start time to user terminal

    for (const auto& filePath : fileArgs) { // Process each provided path (main function)
        processPath(filePath);
    }

    auto endT{std::chrono::system_clock::now()}; // Gets end time (for printing at end)
    auto endTime{std::chrono::high_resolution_clock::now()}; // Retrieves time after program has completed
    std::chrono::duration<double> duration{endTime - startTime}; // Calculates total run time in seconds

    if (!Config.isRecursive()) { // Will print at the end (if verbose) [runtime statistics]
        logMessage(INFO, "File shredding process completed. " + std::to_string(duration.count()) + " seconds.");
    } else { // Specifies mode
        logMessage(INFO, "Recursive shredding process completed. " + std::to_string(duration.count()) + " seconds.");
    }

    std::time_t EndTime{std::chrono::system_clock::to_time_t(endT)}; // Converts end time to printable format
    std::tm localEndTime{*std::localtime(&EndTime)}; // Gets time in local timezone

    std::cout << "Shred completed at: " << std::put_time(&localEndTime, "%H:%M:%S") << std::endl;
    
    if (Program.isError()) { return EXIT_FAILURE; }
    return EXIT_SUCCESS; // Success!
}

std::vector<std::string> parseArguments(int argc, char* argv[]) {
    std::vector<std::string> fileArgs; // Store file paths
    std::string nfMsg{"Flag '-n' requires a positive integer"};
    std::string nlMsg{"Flag '--number' requires a positive integer"};
    
    int i{};

    // Define short flag handlers
    std::unordered_map<char, std::function<void(size_t&, const std::string&)>> shortFlagActions{
        {'h', [&](size_t&, const std::string&) { shortHelp(argv); }},
        {'H', [&](size_t&, const std::string&) { help(argv); }},
        {'n', [&](size_t& j, const std::string& arg) { 
            size_t start{j + 1}, end{start};
            while (end < arg.size() && std::isdigit(arg[end])) {
                ++end;
            }
            if (start < end) {
                try {
                    Config.updateCount(std::stoi(arg.substr(start, end - start)));
                    j = end - 1;
                } catch (...) {
                    errorExit(1, nfMsg);
                }
            } else if (j + 1 < argc) {
                try {
                    Config.updateCount(std::stoi(argv[++j]));
                } catch (...) {
                    errorExit(1, nfMsg);
                }
            } else {
                errorExit(1, nfMsg);
            }
        }},
        {'r', [&](size_t&, const std::string&) { Config.updateFlag("recursive", true); }},
        {'k', [&](size_t&, const std::string&) { Config.updateFlag("keep_files", true); }},
        {'v', [&](size_t&, const std::string&) { Config.updateFlag("verbose", true); }},
        {'e', [&](size_t&, const std::string&) { Config.updateFlag("follow_symlinks", true); }},
        {'s', [&](size_t&, const std::string&) { Config.updateFlag("secure_mode", true); }},
        {'d', [&](size_t&, const std::string&) { Config.updateFlag("dry_run", true); }},
        {'c', [&](size_t&, const std::string&) { Config.updateFlag("verify", false); }},
        {'f', [&](size_t&, const std::string&) { Config.updateFlag("force_delete", true); }},
        {'V', [&](size_t&, const std::string&) { version(argv); }},
        {'C', [&](size_t&, const std::string&) { copyright(argv); }},
    };

    // Define long option handlers
    std::unordered_map<std::string, std::function<void()>> longOptionActions{
        {"help", [&]() { shortHelp(argv); }},
        {"full-help", [&]() { help(argv); }},
        {"overwrite-count", [&]() {
            if (++i < argc) { 
                try { Config.updateCount(std::stoi(argv[i])); }
                catch (...) { errorExit(1, nlMsg); }
            } else { errorExit(1, nlMsg); }
        }},
        {"recursive", [&]() { Config.updateFlag("recursive", true); }},
        {"keep-files", [&]() { Config.updateFlag("keep_files", true); }},
        {"verbose", [&]() { Config.updateFlag("verbose", true); }},
        {"follow-symlinks", [&]() { Config.updateFlag("follow_symlinks", true); }},
        {"secure", [&]() { Config.updateFlag("secure_mode", true); }},
        {"dry", [&]() { Config.updateFlag("dry_run", true); }},
        {"no-verify", [&]() { Config.updateFlag("verify", false); }},
        {"force", [&]() { Config.updateFlag("force_delete", true); }},
        {"internal", [&]() { Config.updateFlag("internal", true); }},
        {"version", [&]() { version(argv); }},
        {"copyright", [&]() { copyright(argv); }},
    };

    // Parse command-line arguments
    for (i = 1; i < argc; ++i) {
        std::string arg{argv[i]};

        if (arg[0] == '-') {
            if (arg[1] == '-') { // Handle long options
                std::string longOption{arg.substr(2)}; // Initializes option without '--'
                std::transform(longOption.begin(), longOption.end(), longOption.begin(), ::tolower); // Will lower-case flag for case insensitivity

                auto action{longOptionActions.find(longOption)}; // Finds option in respective unordered map
                if (action != longOptionActions.end()) { // If it is found
                    action->second(); // Execute the associated lambda function
                } else {
                    errorExit(1, "Invalid long option", "--" + longOption); // Me when it's not found
                }
            } else { // Handle short flags
                for (size_t j = 1; j < arg.size(); ++j) { // Iterate through each character in the argument
                    char flag{arg[j]}; // Initializes flag as the character in the iteration
                    auto action{shortFlagActions.find(flag)}; // Sets action to the flag (if found in the map)
                    if (action != shortFlagActions.end()) { // If it is found
                        action->second(j, arg); // Call corresponding lambda
                    } else {
                        errorExit(1, "Invalid flag", "-" + std::string(1, flag)); // Not found
                    }
                }
            }
        } else { // Handle non-flag arguments (files)
            fileArgs.emplace_back(arg);
        }
    }

    // Ensure at least one file argument is provided
    if (fileArgs.empty()) {
        errorExit(1, "Incorrect usage. Use '-h' or '--help' for help");
    }

    return fileArgs;
}

void processPath(const fs::path& path) {
    try {
        if (fs::is_symlink(path) && !Config.isFollow_symlinks()) { // Skip symlinks
            logMessage(WARNING, "Skipping symlink '" + path.string() + "'");
            return;
        } else if (fs::is_symlink(path) && Config.isFollow_symlinks()) {
            auto target{fs::read_symlink(path)};
            if (!fs::exists(target)) {
                logMessage(WARNING, "Dangling symlink (not followed): '" + path.string() + "'");
                return;
            } else {
                fs::path path{target};
            }
        }

        if (fs::is_directory(path)) {
            if (Config.isRecursive()) { // Processes all files in a directory (recursive required)
                logMessage(INFO, "Entering directory '" + path.string() + "'...");
                for (const auto& entry : fs::recursive_directory_iterator(path, Config.isFollow_symlinks() ? fs::directory_options::follow_directory_symlink : fs::directory_options::none)) {
                    if (fs::is_regular_file(entry)) {
                        shredFile(entry.path());
                    }
                }

                if (!Config.isKeep_files() && fs::is_empty(path) && !Config.isDry_run()) { // Processes if not keeping files, is a legitimate run, and the directory is empty
                    if (fs::remove(path)) { // Remove directory after after successful deletion of all files
                        logMessage(INFO, "Directory '" + path.string() + "' successfully deleted.");
                    } else {
                        logMessage(ERROR, "Failed to delete directory '" + path.string() + "'");
                        Program.updateErrorStatus();
                    }
                } else { // Directory wasn't deleted: keep files or directory is not empty
                    if (Config.isKeep_files()) { logMessage(WARNING, "Directory '" + path.string() + "' was not deleted (keep_files flag)."); }
                        else if (!fs::is_empty(path) && !Config.isDry_run()) { logMessage(WARNING, "Directory '" + path.string() + "' is not empty. Skipping deletion."); }
                        else if (Config.isDry_run()) { logMessage(DRY_RUN, "Directory '" + path.string() + "' would be shredded."); }
                }
            } else { // No recursive = No shredding
                logMessage(WARNING, "'" + path.string() + "' is a directory. Use -r for recursive shredding.");
            }
        } else if (fs::is_regular_file(path)) { // For files to shred individually
            shredFile(path);
        } else { // This file, trash
            logMessage(ERROR, "'" + path.string() + "' is not a valid file or directory.");
            Program.updateErrorStatus();
        }
    } catch (const fs::filesystem_error& e) { // Expose filesystem errors to the user
        logMessage(ERROR, "Filesystem error: " + std::string(e.what()));
        Program.updateErrorStatus();
    } catch (const std::runtime_error& e) { // Expose other errors
        logMessage(ERROR, "An error has occured: " + std::string(e.what()));
        Program.updateErrorStatus();
    } catch (...) {
        logMessage(ERROR, "An unknown error has occured in processPath()");
        Program.updateErrorStatus();
    }
}

void logMessage(logLevel type, const std::string& message) { // Function to log messages with timestamps
    std::string level;
    if (type == INFO) { level = "INFO"; } // To print the actual word rather than the numerical representation.
    if (type == ERROR) { level = "ERROR"; }
    if (type == WARNING) { level = "WARNING"; }
    if (type == DRY_RUN) { level = "DRY_RUN"; }
    if (type == INTERNAL) { level = "INTERNAL"; }
    if (Config.isVerbose() || Config.isInternal() || type != INFO ) { // Only print WARNING, ERRORS, or DRY_RUN levels (unless verbose)
        auto now{std::chrono::system_clock::now()}; // gets current time
        auto time{std::chrono::system_clock::to_time_t(now)}; // changes time to correct format
        auto tm{*std::localtime(&time)}; // gets local time
        std::cout << "[" << std::put_time(&tm, "%m-%d-%Y %H:%M:%S") << "] [" << level << "] " << message << std::endl; // logs in format: [MM-DD-YY] [LEVEL] MESSAGE
    }
}

void errorExit(int value, std::string message, std::string flag, bool customLogger) { // Function to provide ability to exit program outside of main function
    if (customLogger) { 
        if (!message.empty() && flag.empty()) {
            logMessage(ERROR, message);
        } else if (!message.empty() && !flag.empty()) {
            logMessage(ERROR, message + " (" + flag + ")");
        }
    } else {
        if (!message.empty() && flag.empty()) {
            std::cerr << "Error: " << message << std::endl;
        } else if (!message.empty() && !flag.empty()) {
            std::cerr << "Error: " << message << " (" + flag + ")" << std::endl;
        }
    }
    exit(value);
}

std::uintmax_t getOptimalBlockSize() { // This function returns the retrieves blocksize defined in the kernel for the current OS.
#ifdef __linux__
    struct statvfs fsInfo;
    if (statvfs(".", &fsInfo) != 0) {
        logMessage(ERROR, "Error getting block size on Linux. Defaulting to 4096 bytes.");
        return 4096;  // Default block size if statvfs fails
    }
    return fsInfo.f_frsize;  // f_frsize is the optimal block size
#elif _WIN32
    DWORD sectorsPerCluster, bytesPerSector, numberOfFreeClusters, totalNumberOfClusters;
    if (!GetDiskFreeSpace(".", &sectorsPerCluster, &bytesPerSector, &numberOfFreeClusters, &totalNumberOfClusters)) {
        logMessage(ERROR, "Error getting block size on Windows. Defaulting to 4096 bytes.");
        return 4096;  // Default block size if GetDiskFreeSpace fails
    }
    return sectorsPerCluster * bytesPerSector;  // This is the block size
#elif __APPLE__
    int blockSize{};
    size_t len{sizeof(blockSize)};

    if (sysctlbyname("kern.maxfiles", &blockSize, &len, NULL, 0) != 0) {
        logMessage(ERROR, "Error getting block size on MacOS. Defaulting to 4096 bytes.");
        return 4096; // Default block size if sysctl fails
    }
    return blockSize; // blockSize is the optimal block size
#else
    logMessage(INFO, "OS type could not be determined. Using default block size (4096 bytes)")
    return 4096;  // Default block size for unsupported platforms
#endif
}

std::string generateRandomFileName(size_t length) {
    static const char charset[]{"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"};
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
    HANDLE hFile{CreateFile(
        filePath.c_str(), // The file
        GENERIC_WRITE, // To flush the file
        0, // Do not share
        NULL, // Default security
        OPEN_EXISTING, // Open the file
        FILE_ATTRIBUTE_NORMAL, // Normal attributes
        NULL)}; // No template
    if (hFile == INVALID_HANDLE_VALUE) { // Checks if sync was successful
        logMessage(WARNING, "File '" + filePath.string() + "' failed to synchronize.");
        return;
    }
    if (!FlushFileBuffers(hFile)) { // Flushes file
        logMessage(WARNING, "File '" + filePath.string() + "' failed to flush.");
    }
    CloseHandle(hFile);
#else
    FILE* file{fopen(filePath.c_str(), "r")}; // Opens the file
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
        DWORD lastError{GetLastError()};
        logMessage(WARNING, "The file's metadata failed to stripped." + std::to_string(lastError));
    }
#else
    try {
        ssize_t len{listxattr(filePath.c_str(), nullptr, 0, 0)}; // Retrieves length of attributes
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
    std::string computeSHA256(const std::vector<unsigned char>& data) { // Gets SHA256 hash
        EVP_MD_CTX *mdctx{EVP_MD_CTX_new()}; // Initializes context
        const EVP_MD *md{EVP_sha256()}; // Sets mode to SHA256
        unsigned char hash[EVP_MAX_MD_SIZE]{}; // Buffer for hash
        unsigned int hashLen{}; // Length for hash

        if (mdctx == nullptr) { // If it failed to initialize
            logMessage(ERROR, "Failed to create OpenSSL EVP context for SHA256.");
            return "";
        }

        if (EVP_DigestInit_ex(mdctx, md, nullptr) != 1) { // Initialize the context with the mode
            EVP_MD_CTX_free(mdctx); // Frees context
            logMessage(ERROR, "Failed to initialize OpenSSL SHA256 context.");
            return "";
        }

        if (EVP_DigestUpdate(mdctx, data.data(), data.size()) != 1) { // Updates the hash with data
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

    int verifyWithHash(const std::string& filePath, const std::vector<unsigned char>& expectedData, const int& pass) {
        struct hashStat hash;
        hash.updateVerification(false);
        std::ifstream file(filePath, std::ios::binary); // Opens input (binary) stream for file (rb)
        if (!file.is_open()) { // If the file doesn't open
            logMessage(ERROR, "File " + filePath + "failed to open for hashing. Attempting fallback..");
            return 1; // Triggers fallback initiation for calling function
        }

        std::vector<unsigned char> fileContent((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>()); // Retrieves files contents
        file.close(); // Closes file

        std::string fileHash{computeSHA256(fileContent)}; // Calculates hash from file data
        std::string expectedHash{computeSHA256(expectedData)}; // Calculates hash from saved data

        if (fileHash == expectedHash) { // Only if they are identical will we say it succeeded
            hash.updateVerification(true);
        } else {
            logMessage(WARNING, "Hash mismatch for '" + filePath + "' on pass " + std::to_string(pass));
            hash.updateVerification(false);
            return 2; // Triggers verification failed for calling function
        }
        return 0; // Triggers verification success
    }
#endif

bool shredFile(const fs::path& filePath) {
    bool verificationFailed{false};
    try {
        verificationFailed = false;
        if (Config.isDry_run()) { // Triggers if not deleting
            if (fs::is_symlink(filePath) && !Config.isFollow_symlinks()) { // Iterates through options for a reliable file iteration
                logMessage(DRY_RUN, "Symlink file '" + filePath.string() + "' would not be shredded.");
            } else {
            logMessage(DRY_RUN, "Simulating shredding file '" + filePath.string() + "'");
            }
            
            return true;
        } else if (fs::is_symlink(filePath) && Config.isFollow_symlinks()) {
            auto target{fs::read_symlink(filePath)};
            if (!fs::exists(target)) {
                logMessage(WARNING, "Dangling symlink (not followed): '" + filePath.string() + "'");
                return false;
            } else {
                fs::path filePath{target};
                return true;
            }
        }

        if (fs::is_empty(filePath)) {
            logMessage(ERROR, "File '" + filePath.string() + "' is empty and will not be shredded.");
            return false;
        }

        // Gets file permissions, aborts if not found
        hasWritePermission(filePath); // Populate structure with the current file's permissions

        if (Config.isForce_delete()) { // Only if force_delete flag is set
            bool needChange{false};
            if (!wc.isWritePerm() || !wc.isReadPerm()) { logMessage(INFO, "The necessary permissions for file '" + filePath.string() + "' are not present"); needChange = true; }
            if (needChange) {
                std::string rwexpose = ((!wc.isWritePerm() && !wc.isReadPerm()) ? "read or write" : "");
                std::string wexpose;
                std::string rexpose;
                if (rwexpose.empty()) {
                    wexpose = (!wc.isWritePerm() ? "write" : "");
                    rexpose = (!wc.isReadPerm() ? "read" : "");
                }
                std::string perms = (rwexpose.empty() ? "" : rwexpose) + (wexpose.empty() ? "" : wexpose) + (rexpose.empty() ? "" : rexpose);
                logMessage(WARNING, "Changing permissions for file '" + filePath.string() + "' due to no" + (perms.empty() ? "" : " " + perms) + " permissions.");
                changePermissions(filePath); // If file permission modification succeeds, set write permission
            }
        }
        if (wc.failedWritePerm()) { Program.updateErrorStatus(); return false; }
        if (!wc.isWritePerm()) { logMessage(ERROR, "There are no" + std::string(wc.isReadPerm() ? " " : " read or ") + "write permissions for file '" + filePath.string() + "'"); Program.updateErrorStatus(); return false; }
        if (!wc.isReadPerm()) { logMessage(ERROR, "There are no read permissions for file '" + filePath.string() + "'"); Program.updateErrorStatus(); return false;}

        if (fs::file_size(filePath) == 0) { // Skip the shredding of empty files, delete them immediately.
            if (!Config.isKeep_files()) {
                logMessage(INFO, "File '" + filePath.string() + "' is empty and will be deleted without overwriting.");
                if (std::remove(filePath.c_str()) == 0) {
                    logMessage(INFO, "Empty file '" + filePath.string() + "' successfully deleted.");
                } else {
                    logMessage(ERROR, "Failed to delete empty file '" + filePath.string() + "'");
                    Program.updateErrorStatus();
                    return false;
                }
            } else {
                logMessage(WARNING, "File '" + filePath.string() + "' is empty and will not be overwritten.");
            }
            return true;
        }

        auto fileSize{fs::file_size(filePath)}; // get size of file (to know how much to overwrite)
        std::fstream file; // fstream instead ofstream to prevent appending
        int attempts{}; // Will initialize this variable as 0

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
            Program.updateErrorStatus();
            return false;
        }

        for (int i = 0; i < Config.getOverwriteCount(); ++i) { // Call shredder for amount specified in overwriteCount
            file.seekp(0, std::ios::beg); // Move to beginning of buffer (file)
            if (overwriteWithRandomData(filePath.string(), file, fileSize, i + 1) == 1) {
                verificationFailed = true; // Overwrite function returns 1 if verification fails
            }
            logMessage(INFO, "Completed overwrite pass " + std::to_string(i + 1) + " for file '" + filePath.string() + "'"); // Prints pass count

            std::cout << "Progress: " << std::fixed << std::setprecision(1)  // Percent-style progress meter
                      << ((i + 1) / static_cast<float>(Config.getOverwriteCount())) * 100 << "%\r" << std::flush;
        }

        if (Config.isInternal() && verificationFailed || Config.isVerbose() && verificationFailed) { logMessage(WARNING, "Overwrite verification failed for '" + filePath.string() + "' Skipping deletion."); } // Prints verification failure, only if verbose because overwrite function says it too.
        file.close(); // Close file, if completed
        syncFile(filePath); // Force filesystem synchronization

        ic.updateBufferPrintStatus(false); // Reset for next file
        
        if (!Config.isKeep_files() && !verificationFailed) { // Delete file after shredding (if not keeping)
            std::string obfuscatedPath{};
            try {
                std::unique_lock<std::mutex> lock(fileMutex); // Acquire file lock

                fs::permissions(filePath, fs::perms::none); // Remove file permissions

                std::string randomFileName{generateRandomFileName()}; // Get a random name
                obfuscatedPath = fs::temp_directory_path() / randomFileName; // Make a temp path and add the random name
                fs::rename(filePath, obfuscatedPath); // Move the file to the new temp directory with the random name

                std::this_thread::sleep_for(std::chrono::milliseconds(50)); // Sleep to wait for new metadata to propagate
                cleanupMetadata(obfuscatedPath); // Cleanup metadata
                std::this_thread::sleep_for(std::chrono::milliseconds(50)); // Same as above
            } catch (...) {
                std::cerr << "An error has occured while obfuscating metadata on the file '" << filePath.string() << "'" << std::endl;
            }

            if (std::remove(obfuscatedPath.c_str()) == 0 || std::remove(filePath.c_str()) == 0) { // If successfully deleted
                if (Config.isVerify()) { logMessage(INFO, "File '" + filePath.string() + "' shredded, verified, and deleted."); }
                    else if (!Config.isVerify()) { logMessage(INFO, "File '" + filePath.string() +"' shredded and deleted without verification."); }
            } else { // Or not
                logMessage(ERROR, "Failed to delete file '" + filePath.string() + "'");
                Program.updateErrorStatus();
                return false;
            }
        } else {
            logMessage(INFO, "File '" + filePath.string() + "' overwritten without deletion."); // Keep file mode
        }
        return true;
        
    } catch (const fs::filesystem_error& e) {
        logMessage(ERROR, "Filesystem error: " + std::string(e.what()));
        Program.updateErrorStatus();
        return false;
    } catch (...) {
        logMessage(ERROR, "An unknown error occured in shredFile()");
        Program.updateErrorStatus();
        return false;
    }
}

int overwriteWithRandomData(std::string filePath, std::fstream& file, std::uintmax_t fileSize, int pass) {
    secureRandom rng;

    const std::uintmax_t bufferSize{getOptimalBlockSize()};  // Get the block size
    std::vector<char> buffer(bufferSize); // Set buffer to retrieved value (block size)

    // Patterns for DoD compliance and additional security
    std::vector<std::string> patterns{
        std::string(bufferSize, '\x00'),  // Pass of 0x00 (00000000 in binary)
        std::string(bufferSize, '\xFF'),  // Pass of 0xFF (11111111 in binary)
        std::string(bufferSize, '\xAA'),  // Pass of 0xAA (10101010 in binary)
        std::string(bufferSize, '\x55'),  // Pass of 0x55 (01010101 in binary)
        std::string(bufferSize, '\x3D'),  // Pass of 0x3D (00111101 in binary)
        std::string(bufferSize, '\xC2'),  // Pass of 0xC2 (11000010 in binary)
        std::string(bufferSize, '\x8E'),  // Pass of 0x8E (10001110 in binary)
        std::string(bufferSize, '\x4E')   // Pass of 0x4E (01001110 in binary)
    };

    int securePasses(patterns.size());  // Number of secure passes (to change add/remove from patterns array)
    

    // Secure random generator
    std::random_device rd; // Opens a random device
    std::mt19937 gen(rd()); // Set the random device to generate
    std::uniform_int_distribution<> dist(0, 255); // Sets even distribution for data generation
    std::vector<unsigned char> lastRandomData(fileSize); // For verification

    for (std::uintmax_t offset = 0; offset < fileSize; offset += bufferSize) {
        std::uintmax_t writeSize{std::min(bufferSize, fileSize - offset)}; // Finds writesize
        
        // Generate random data for non-secure or final pass
        if (!Config.isSecure_mode()) {
            std::vector<unsigned char> randomData;
            try {
                randomData = rng.generate(writeSize);
            } catch (std::runtime_error& e) {
                logMessage(WARNING, "Failed to generate secure random data: " + std::string(e.what()));
                randomData.resize(writeSize);
                std::generate(randomData.begin(), randomData.end(), [&](){ return static_cast<char>(dist(gen)); });
            } catch (...) {
                logMessage(ERROR, "An unknown error occurred when generating secure random data");
                randomData.resize(writeSize);
                std::generate(randomData.begin(), randomData.end(), [&](){ return static_cast<char>(dist(gen)); });
            }
            file.seekp(offset); // Moves to offset
            file.write(reinterpret_cast<char*>(randomData.data()), writeSize);  // Writes buffer with retrieved size
            if (Config.isVerify()) { std::copy(randomData.begin(), randomData.end(), lastRandomData.begin() + offset); } // Copies the verification
        } else {
            std::vector<unsigned char> randomData;
            // Secure shredding mode with multiple patterns (defined and random, plus DoD standards)
            for (int pass = 0; pass < securePasses; ++pass) {
                gen.seed(rd() + pass + offset); // Re-seed with the pass and offset
                
                // Apply a pre-set pattern
                std::memcpy(buffer.data(), patterns[pass].data(), bufferSize); // Copy pattern (number 'pass') to buffer9
                file.seekp(offset); // Move to offset
                file.write(buffer.data(), writeSize); // Write buffer to file

                // Introduce random pattern for every other pass for additional security
                if (pass % 2 == 1) {
                    try {
                        randomData = rng.generate(writeSize);
                    } catch (std::runtime_error& e) {
                        logMessage(WARNING, "Failed to generate secure random data: " + std::string(e.what()));
                        randomData.resize(writeSize);
                        std::generate(randomData.begin(), randomData.end(), [&](){ return static_cast<char>(dist(gen)); });
                    } catch (...) {
                        logMessage(ERROR, "An unknown error occurred when generating secure random data");
                        randomData.resize(writeSize);
                        std::generate(randomData.begin(), randomData.end(), [&](){ return static_cast<char>(dist(gen)); });
                    }
                    file.seekp(offset);
                    file.write(reinterpret_cast<char*>(randomData.data()), writeSize);
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
            //std::generate(buffer.begin(), buffer.end(), [&]() { return static_cast<char>(dist(gen)); }); // Fills buffer with random data
            try {
                randomData = rng.generate(writeSize);
            } catch (std::runtime_error& e) {
                logMessage(WARNING, "Failed to generate secure random data: " + std::string(e.what()));
                randomData.resize(writeSize);
                std::generate(randomData.begin(), randomData.end(), [&](){ return static_cast<char>(dist(gen)); });
            } catch (...) {
                logMessage(ERROR, "An unknown error occurred when generating secure random data");
                randomData.resize(writeSize);
                std::generate(randomData.begin(), randomData.end(), [&](){ return static_cast<char>(dist(gen)); });
            }
            if (Config.isVerify()) { if (lastRandomData.size() < offset + writeSize) {lastRandomData.resize(offset + writeSize); } std::copy(randomData.begin(), randomData.end(), lastRandomData.begin() + offset); }
            file.seekp(offset);
            file.write(reinterpret_cast<char*>(randomData.data()), writeSize);
            if (Config.isInternal()) { logMessage(INTERNAL, "Successfully wrote all DoD passes to block"); }
        }
    }
    if (Config.isInternal() && !ic.wasBufferPrinted()) { logMessage(INTERNAL, "Blocksize: " + std::to_string(bufferSize)); ic.updateBufferPrintStatus(true); }
    if (Config.isVerify()) {
        int ret{1}; // Return value (default as "fail")
        file.flush(); // Ensure all writes are complete
        file.seekg(0); // Reset to beginning for verification

        std::vector<char> verifyBuffer(bufferSize);
        bool verificationFailedHere = false; // Initializes boolean that determines if file verification failed
#ifdef OPENSSL_FOUND
        ret = verifyWithHash(filePath, lastRandomData, pass); // Config.verify hash
        if (ret == 2) { verificationFailedHere = true; } // If failed
        if (ret == 0) { return 0; } // If successful
#endif
    if (ret == 1) { // If it failed or OpenSSL is not defined, use fallback verification
        for (std::uintmax_t offset = 0; offset < fileSize; offset += bufferSize) {
            std::uintmax_t readSize{std::min(bufferSize, fileSize - offset)}; // Gets size to read
            file.read(verifyBuffer.data(), readSize); // Reads the control

            // Check if the data is consistent with erasure (e.g., all zeroes after overwrite)
            if (!std::equal(verifyBuffer.begin(), verifyBuffer.begin() + readSize, lastRandomData.begin() + offset)) {
                if (Config.isVerbose()) { std::cerr << "Verification failed at offset: " << offset << '\n'; }
                verificationFailedHere = true; // If it is not equal, fail
                break;
            }
        }
    }
        if (verificationFailedHere) { return 1; } // This will export to the other function for altered behavior
    }
    return 0; // Exports success
}

int hasWritePermission(const fs::path& path) {
#ifdef _WIN32
    // Windows-specific write permission check using CreateFile
    DWORD dwDesiredAccess{GENERIC_READ | GENERIC_WRITE}; // Set read/write permission as desired
    DWORD dwError{0}; // Initialize error variable
    HANDLE hFile{CreateFile(path.c_str(), dwDesiredAccess, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)}; // Gets file info

    if (hFile == INVALID_HANDLE_VALUE) { // Trigger for incorrectly opened handles
        dwError = GetLastError(); // Gets error value
        if (dwError == ERROR_ACCESS_DENIED) { // If it is because of write permissions, it will fail
            logMessage("WARNING", "Access denied for file '" + path.string() + "'");
            wc.updateWritePerm(false);
            wc.updateReadPerm(false);
        }
    } else {
        CloseHandle(hFile); // Closes handle and returns has write permission
        wc.updateWritePerm(true);
        wc.updateReadPerm(true);
        return EXIT_SUCCESS;
    }
    wc.updateFailedToGetPerm(true);
    return EXIT_FAILURE;
#else
    // POSIX (Linux/macOS) write permission check
    std::error_code ec{}; // Opens an error code
    fs::file_status status{fs::status(path, ec)}; // Copies the file information (status) into the file_status struct status (uses error code)
    if (ec) { // If there is an error retrieving the file status
        logMessage(ERROR, "Failed to retrieve permissions for '" + path.string() + "': " + ec.message());
        wc.updateFailedToGetPerm(true);
        return EXIT_FAILURE;
    }

    auto perms{status.permissions()}; // Extracts file permissions from the file_status structure status

    struct stat fileStat; // Creates a structure following the stat structure
    if (stat(path.c_str(), &fileStat) == -1) { // Gets file status (information) and copies it into the fileStat structure
        logMessage(ERROR, "Failed to get file status for '" + path.string() + "'");
        wc.updateFailedToGetPerm(true);
        return EXIT_FAILURE;
    }

    uid_t fileOwner{fileStat.st_uid}; // Gets file owner
    gid_t fileGroup{fileStat.st_gid}; // Gets file group

    uid_t currentUser{getuid()}; // Gets current user id
    gid_t currentGroup{getgid()}; // Gets current group id

    bool isOwner{currentUser == fileOwner}; // Checks if current user is file owner
    bool isInGroup{currentGroup == fileGroup}; // Checks if current user is in file group

    wc.updateFailedToGetPerm(false); // By default, no permissions

    // Iterates through perms looking for the respective write permissions
    if (isOwner) { // Checks for owner write, if owner
        wc.updateWritePerm((perms & fs::perms::owner_write) != fs::perms::none);
        wc.updateReadPerm((perms & fs::perms::owner_read) != fs::perms::none);
    } else if (isInGroup) { // Checks for group write, if in group
        wc.updateWritePerm((perms & fs::perms::group_write) != fs::perms::none);
        wc.updateReadPerm((perms & fs::perms::group_read) != fs::perms::none);
    } else { // Checks for others write, if neither owner or in group
        wc.updateWritePerm((perms & fs::perms::others_write) != fs::perms::none);
        wc.updateReadPerm((perms & fs::perms::others_read) != fs::perms::none);
    }

    if (geteuid() == 0) { wc.updateWritePerm(true); wc.updateReadPerm(true); } // If root, bypass this check
    if (!wc.isWritePerm()) { // In case the checks fail, yet the user has write permissions
        if (access(path.c_str(), W_OK) == 0) {
            wc.updateWritePerm(true);
        }
    }
    if (!wc.isReadPerm()) { // In case the checks fail, yet the user has read permissions
        if (access(path.c_str(), R_OK) == 0) {
            wc.updateReadPerm(true);
        }
    }

    return EXIT_SUCCESS;
#endif
}

bool changePermissions(const std::string &filePath) {
    try {
        bool isExecutable{false}; // Boolean to store if the file is executable
#ifdef _WIN32
        // On Windows, remove read-only attribute
        DWORD attributes{GetFileAttributes(filePath.c_str())};
        if (attributes == INVALID_FILE_ATTRIBUTES) { // If the attributes are invalid
            logMessage(ERROR, "Failed to retrieve file attributes for '" + filePath + "'");
            return false;
        }
        if (attributes & FILE_ATTRIBUTE_READONLY) { // If one of the attributes are read-only
            if (!SetFileAttributes(filePath.c_str(), attributes & ~FILE_ATTRIBUTE_READONLY)) { // If it unsets read-only
                logMessage(ERROR, "Failed to remove read-only attribute on file '" + filePath "'");
                return false;
            }
        }

        // Creates a temporary file with attributes from the other file, then tests its write privileges
        HANDLE fileHandle{CreateFile(filePath.c_str(), (GENERIC_READ | GENERIC_WRITE), 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)};
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
        int ret{}; // To store the exit result

        if (isExecutable) { // Determines whether to change the permissions with execute or not
            ret = chmod(filePath.c_str(), S_IRWXU | S_IRWXG | S_IRWXO); // rwxrwxrwx
        } else {
            ret = chmod(filePath.c_str(), S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH); // rw-rw-rw-
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
    bool successOne{false};
        if (access(filePath.c_str(), W_OK) == 0) { // If the file has write permissions
            logMessage(INFO, "Write access verified on file '" + filePath + "'");
            wc.updateWritePerm(true);
            successOne = true;
        }
        if (access(filePath.c_str(), R_OK) == 0) {
            wc.updateReadPerm(true);
            if (successOne) { return true; }
        }

    } catch (const fs::filesystem_error& e) {
        logMessage(ERROR, "Filesystem error for file '" + filePath + "': " + std::string(e.what()));
    } catch (const std::exception& e) {
        logMessage(ERROR, "Error on file '" + filePath + "': " + std::string(e.what()));
    }

    return false;
}

void help(char* argv[]) { // The print help functon (At bottom due to size and lack of functionality)
    std::cerr << "NAME" << std::endl;
    std::cerr << "    " << argv[0] << " - Securely overwrite and remove files\n" << std::endl;

    std::cerr << "SYNOPSIS" << std::endl;
    std::cerr << "    " << argv[0] << " [OPTIONS] <file1> <file2> ...\n" << std::endl;

    std::cerr << "DESCRIPTION" << std::endl;
    std::cerr << "    " << argv[0] << " is a tool designed to securely overwrite and remove files and directories." << std::endl;
    std::cerr << "    By default, it overwrites the specified files with random data and removes them, ensuring that" << std::endl;
    std::cerr << "    data is unrecoverable. The tool offers various options for customizing the shredding process." << std::endl;
    std::cerr << "    This tool almost conforms to DoD 5220.22-M when the '--secure' flag is used without the '--no-verify' flag, and" << std::endl;
    std::cerr << "    this tool does not conform due to the unnecessary complexity (which enhances the security of the shred)." << std::endl;
    std::cerr << "    This program will exit 2 on this dialogue, 1 on failure, and 0 on success.\n" << std::endl;
#ifdef OPENSSL_FOUND
    std::cerr << "    Since this program was compiled with OpenSSL, the file verification function uses SHA256 hashing," << std::endl;
    std::cerr << "    which is more efficient, secure, and accurate for file shredding confirmation.\n" << std::endl;
#endif
    std::cerr << "OPTIONS" << std::endl;
    std::cerr << "    -h <help>             Print the short help dialogue and exit" << std::endl;
    std::cerr << "    -H <full-help>        Print this help dialogue and exit" << std::endl;
    std::cerr << "    -V <version>          Print the program version and exit" << std::endl;
    std::cerr << "    -C <copyright>        Print the program copyright and exit\n" << std::endl;
    
    std::cerr << "    -n[num] <overwrites>  Set number of overwrites (default: 3)" << std::endl;
    std::cerr << "    -r <recursive>        Enable recursive mode to shred directories and their contents" << std::endl;
    std::cerr << "    -k <keep files>       Keep files after overwriting (no removal)" << std::endl;
    std::cerr << "    -v <verbose>          Enable verbose output for detailed logging" << std::endl;
    std::cerr << "    -e <follow symlinks>  Follow symlinks during shredding" << std::endl;
    std::cerr << "    -s <secure mode>      Enable secure shredding with randomization (slower)" << std::endl;
    std::cerr << "    -d <dry run>          Show what would be shredded without actual processing" << std::endl;
    std::cerr << "    -c <no verification>  Skip post-shredding verification (faster)" << std::endl;
    std::cerr << "    -f <force>            Force delete the file if there is no write permission\n" << std::endl;

    std::cerr << "DESCRIPTION OF OPTIONS" << std::endl;
    std::cerr << "    -h, --help <help>" << std::endl;
    std::cerr << "        This option will print the short help dialogue and exit with the code 2." << std::endl;
    std::cerr << "        Useful to quickly see all possible options for reference before beginning the program.\n" << std::endl;

    std::cerr << "    -H, --full-help <full-help>" << std::endl;
    std::cerr << "        This option will print this long help dialogue and exit with the code 2." << std::endl;
    std::cerr << "        Useful to see all possible options, their full descriptions, and examples," << std::endl;
    std::cerr << "        along with copyright and exit status information.\n" << std::endl;

    std::cerr << "    -V, --version <version>" << std::endl;
    std::cerr << "        This option will print the currently installed program version and exit with code 2." << std::endl;
    std::cerr << "        Useful to quickly determine the installed version or view basic copyright information.\n" << std::endl;

    std::cerr << "    -C, --copyright <copyright>" << std::endl;
    std::cerr << "        This option will print the copyright associated with the program and exit with code 2." << std::endl;
    std::cerr << "        this is NOT the full copyright, but a rendition of its summary for brevity.\n" << std::endl;

    std::cerr << "    -n[num], --overwrite-count [num] <overwrites>" << std::endl;
    std::cerr << "        Specifies the number of overwriting passes. By default, 3 passes are performed, but you can increase" << std::endl;
    std::cerr << "        this number for higher security. More passes will make the process slower.\n" << std::endl;

    std::cerr << "    -r, --recursive <recursive>" << std::endl;
    std::cerr << "        Enables recursive mode. If set, the program will shred the contents of directories as well as the" << std::endl;
    std::cerr << "        files themselves. Without this flag, only files are processed.\n" << std::endl;

    std::cerr << "    -k, --keep-files <keep files>" << std::endl;
    std::cerr << "        If set, files will be overwritten with random data, but they will not be deleted. This option is useful" << std::endl;
    std::cerr << "        if you want to securely wipe a file's contents but retain the file itself.\n" << std::endl;

    std::cerr << "    -v, --verbose <verbose>" << std::endl;
    std::cerr << "        Enables verbose output, printing detailed information about each step of the shredding process." << std::endl;
    std::cerr << "        Useful for debugging or confirming that the program is functioning as expected.\n" << std::endl;

    std::cerr << "    -e, --follow-symlinks <follow symlinks>" << std::endl;
    std::cerr << "        Follow symbolic links and include them in the shredding process. Without this flag, symlinks are ignored.\n" << std::endl;

    std::cerr << "    -s, --secure <secure mode>" << std::endl;
    std::cerr << "        Enables secure shredding with byte-level randomization, making data recovery significantly more difficult." << std::endl;
    std::cerr << "        This mode is slower due to the added security, but it provides stronger protection against data recovery.\n" << std::endl;

    std::cerr << "    -d, --dry <dry run>" << std::endl;
    std::cerr << "        Simulates the shredding process without performing any actual deletion. Use this to verify which files" << std::endl;
    std::cerr << "        would be affected before running the program for real.\n" << std::endl;

    std::cerr << "    -c, --no-verify <no verification>" << std::endl;
    std::cerr << "        Disables the post-shredding file verification. Normally, the tool verifies that files have been overwritten" << std::endl;
    std::cerr << "        after shredding, but this step can be skipped with this option for faster operation.\n" << std::endl;

    std::cerr << "    -f, --force <force>" << std::endl;
    std::cerr << "        Will attempt to change file permissions and remove extended attributes to attempt to delete files which" << std::endl;
    std::cerr << "        do not currently have effective write permission, use this for stubborn files.\n" << std::endl;

    std::cerr << "EXAMPLES" << std::endl;
    std::cerr << "    " << argv[0] << " -n5 --force --recursive -vs file1.txt file2.txt directory1" << std::endl;
    std::cerr << "        Forcefully overwrites 'file1.txt' and 'file2.txt' with 5 passes, recursively handles 'directory1', and uses secure" << std::endl;
    std::cerr << "        mode with verbose output.\n" << std::endl;

    std::cerr << "    " << argv[0] << " --dry file1.txt file2.txt" << std::endl;
    std::cerr << "        Performs a dry run to show what would be shredded without actual deletion.\n" << std::endl;

    std::cerr << "EXIT STATUS" << std::endl;
    std::cerr << "    The " << argv[0] << " utility will exit 0 on success, 1 on error, and 2 on user-defined exit (i.e., help, version, copyright, etc.)." << std::endl;

    errorExit(2); // Calls the exit function
}

void shortHelp(char* argv[]) {
    std::cerr << "Usage: " << argv[0] << " [OPTIONS] <file1> <file2> ...\n" << std::endl;

    std::cerr << "Options: " << std::endl;
    std::cerr << "    -h, --help                        Print this help dialogue and exit" << std::endl;
    std::cerr << "    -H, --full-help                   Print the long help dialogue and exit" << std::endl;
    std::cerr << "    -V, --version                     Print the program version and exit" << std::endl;
    std::cerr << "    -C, --copyright                   Print the program copyright and exit\n" << std::endl;

    std::cerr << "    -n[num], --overwrite-count [num]  Set number of overwrites (default: 3)" << std::endl;
    std::cerr << "    -r, --recursive                   Enable recursive mode to shred directories and their contents" << std::endl;
    std::cerr << "    -k, --keep-files                  Keep files after overwriting (no removal)" << std::endl;
    std::cerr << "    -v, --verbose                     Enable verbose output for detailed logging" << std::endl;
    std::cerr << "    -e, --follow-symlinks             Follow symlinks during shredding" << std::endl;
    std::cerr << "    -s, --secure                      Enable secure shredding with randomization (slower)" << std::endl;
    std::cerr << "    -d, --dry                         Show what would be shredded without actual processing" << std::endl;
    std::cerr << "    -c, --no-verify                   Skip post-shredding verification (faster)" << std::endl;
    std::cerr << "    -f, --force                       Force delete the file if there is no write permission" << std::endl; 

    errorExit(2); // Exits
}

void version(char* argv[]) { // Function to print the program version and basic copyright information
    std::cerr << argv[0] << " - File and Directory Shredder " << (isOpenSSL ? "(OpenSSL Version)" : "\b") << " ver. " << VERSION << std::endl;
    std::cerr << "Copyright (C) Aristotle Daskaleas " << CW_YEAR << " - GNU General Public License.\n" << std::endl;
    std::cerr << "Use '--copyright' or '-C' to see more copyright information or see <https://www.gnu.org/licenses/>" << std::endl;
    std::cerr << "for the full license and its terms and conditions." << std::endl;

    errorExit(2); // Exits
}

void copyright(char* argv[]) {
    std::cerr << argv[0] << " - File and directory shredder. It shreds files and directories specified on the command line." << std::endl;
    std::cerr << "Copyright (C) " << CW_YEAR << " Aristotle Daskaleas\n" << std::endl;
    std::cerr << "This program is free software: you can redistribute it and/or modify" << std::endl;
    std::cerr << "it under the terms of the GNU General Public License as published by" << std::endl;
    std::cerr << "the Free Software Foundation, either version 3 of the License, or" << std::endl;
    std::cerr << "(at your option) any later version.\n" << std::endl;
    std::cerr << "This program is distributed in the hope that it will be useful," << std::endl;
    std::cerr << "but WITHOUT ANY WARRANTY; without even the implied warranty of" << std::endl;
    std::cerr << "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the" << std::endl;
    std::cerr << "GNU General Public License for more details.\n" << std::endl;
    std::cerr << "You should have received a copy of the GNU General Public License" << std::endl;
    std::cerr << "along with this program.  If not, see <https://www.gnu.org/licenses/>." << std::endl;

    errorExit(2);
}