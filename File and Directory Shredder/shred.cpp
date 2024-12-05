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
  Version: 4c
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
    -> Added hashing for verification for systems with openssl
  To-do:
    -> Nothing.
*/
#include <iostream> // For console logging
#include <fstream> // For file operations (writing)
#include <iomanip> // For formatting log files
#include <filesystem> // For file / directory operations (stats)
#include <random> // For overwriting
#include <chrono> // For clock
#include <string> // String manipulation
#include <mutex> // For secure file name generation
#include <vector> // Storing buffers
#include <cstring> // for std::memcpy
#include <thread> // for sleeping (std::this_thread::sleep_for)
#include <algorithm> // for std::transform
#ifdef __linux__
#include <sys/statvfs.h> // Linux library that allows for block size retrieval
#include <sys/xattr.h> // For OS-specific file operations
#include <unistd.h> // For filesystem syncing
#elif _WIN32
#include <windows.h> // Windows library that allows for block size retrieval
#include <winbase.h> // For file deletion
#elif __APPLE__
#include <sys/sysctl.h> // Defines required MacOS libraries that allow for block size retrieval
#include <sys/mount.h>
#include <sys/xattr.h> // Same as the one above
#include <unistd.h> // For filesystem syncing
#endif
#ifdef OPENSSL_FOUND
#include <openssl/sha.h> // For hashing
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
bool internal = false; // boolean to indicate whether scripting information is revealed

bool verificationFailed; // Global boolean to determine if verification failed (used in multiple functions)

const std::string validFlags = "nrkvfsdchi";

std::mutex fileMutex; // Defines file name generation variable

enum logLevel { // Define valid log levels
    INFO, // Level to inform with verbosity (i.e., every action)
    WARNING, // Level to inform a non-critical error
    ERROR, // Level to indicate core operational errors
    DRY_RUN // Only used with '-d' (dry_run) flag
};

// Prototype declarations for refactoring
int overwriteWithRandomData(std::string filePath, std::fstream& file, std::uintmax_t fileSize);
#ifdef OPENSSL_FOUND
    int verifyWithHash(const std::string& filePath, const std::vector<char>& expectedData);
    std::string computeSHA256(const std::string& data);
#endif
bool shredFile(const fs::path& filePath);
void processPath(const fs::path& path);
void syncFile(const fs::path& filePath);
void logMessage(logLevel type, const std::string& message);
void errorExit(int value = 1, std::string message = "");
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
        // Prints set options
        std::cout << "Parameters:: Overwrites: " << overwriteCount << ", Recursive: " << recursive << ", Keep_files: " << keep_files << ", Follow_symlinks: " << follow_symlinks << ", Secure_mode " << secure_mode << ", Dry_run: " << dry_run << ", Verify: " << verify << std::endl;
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
    
    // Parse command-line arguments
    for (int i = 1; i < argc; ++i) { // Iterates over input length
        std::string arg = argv[i]; // Initializes argument position to iteration

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
                                    std::cerr << "ERROR: '-n' flag requires a positive integer\n";
                                    errorExit(1);
                                }
                            } else if (i + 1 < argc) { // If there is a space, look in next argument
                                try {
                                    overwriteCount = std::stoi(argv[++i]); // Increments i and moves to the next argument
                                } catch (...) {
                                    std::cerr << "ERROR: '-n' flag requires a positive integer\n";
                                    errorExit(1);
                                }
                            } else {
                                std::cerr << "ERROR: '-n' flag requires a positive integer\n";
                                errorExit(1);
                            }
                            break;
                        }
                        case 'r': recursive = true; break;
                        case 'k': keep_files = true; break;
                        case 'v': verbose = true; break;
                        case 'f': follow_symlinks = true; break;
                        case 's': secure_mode = true; break;
                        case 'd': dry_run = true; break;
                        case 'c': verify = false; break;
                        case 'i': internal = true; break;
                    }
                } else { // If the character was not validated, deuces
                    std::cerr << "ERROR: Invalid flag (-" << flag << ").\n"; // If a letter was not in the valid flags variable
                    errorExit(1);
                }
            }
        } else { // Append all non-flag arguments to the file argument vector
            fileArgs.emplace_back(arg);
        }
    }

    // Check if any files were provided
    if (fileArgs.empty()) { // Suggest help if not
        std::cerr << "Incorrect usage. Use '-h' for help" << std::endl;
        errorExit(1);
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
                        logMessage(ERROR, "Failed to delete directory '" + path.string() + "'.");
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
    if (verbose || internal || type != INFO ) { // Only print WARNING, ERRORS, or DRY_RUN levels (unless verbose)
        auto now = std::chrono::system_clock::now(); // gets current time
        auto time = std::chrono::system_clock::to_time_t(now); // changes time to correct format
        auto tm = *std::localtime(&time); // gets local time
        std::cout << "[" << std::put_time(&tm, "%m-%d-%Y %H:%M:%S") << "] [" << level << "] " << message << std::endl; // logs in format: [MM-DD-YY] [LEVEL] MESSAGE
    }
}

void errorExit(int value, std::string message) { // Function to provide ability to exit program outside of main function
    if (!message.empty()) {
        logMessage(ERROR, message);
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
    if (hFile == INVALID_HANDLE_VALUE) { // 
        logMessage(WARNING, "File '" + filePath.string() + "' failed to synchronize.");
        return;
    }
    if (!FlushFileBuffers(hFile)) {
        logMessage(WARNING, "File '" + filePath.string() + "' failed to flush.");
    }
    CloseHandle(hFile);
#else
    FILE* file = fopen(filePath.c_str(), "r");
    for (int openCount = 0; openCount < 3; ++openCount) {
        if (file) {
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
    DeleteFile((filePath + ":$DATA").c_str());
#else
    if (listxattr(filePath.c_str(), nullptr, 0, 0) > 0) {
        std::vector<char> attrs(1024);
        ssize_t len = listxattr(filePath.c_str(), attrs.data(), attrs.size(), 0);
        for (ssize_t i = 0; i < len; i += strlen(&attrs[i]) + 1) {
            removexattr(filePath.c_str(), &attrs[i], 0);
        }
    }
#endif
}

#ifdef OPENSSL_FOUND
    std::string computeSHA256(const std::string& data) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256Context;
        SHA256_Init(&sha256Context);
        SHA256_Update(&sha256Context, data.c_str(), data.length());
        SHA256_Final(hash, &sha256Context);

        std::ostringstream hexStream;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
            hexStream << std::setw(2) << std::setfill('0') << std::hex << (int)hash[i];
        }
        return hexStream.str();
    }

    int verifyWithHash(const std::string& filePath, const std::vector<char>& expectedData) {
        std::ifstream file(filePath, std::ios::binary);
        if (!file.is_open()) {
            logMessage(ERROR, "File failed to open for hashing.");
            return 1;
        }
        std::string fileContent((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();

        std::string fileHash = computeSHA256(fileContent);
        std::string expectedHash = computeSHA256(std::string(expectedData.begin(), expectedData.end()));

        if (fileHash == expectedHash) {
            logMessage(INFO, "Successfully verified file hash for '" + filePath + "'");
        } else {
            logMessage(WARNING, "Hash mismatch for '" + filePath + "'");
            return 2;
        }
        return 0;
    }
#endif

bool shredFile(const fs::path& filePath) {
    int verificationFailed = 0;
    try {
        verificationFailed = 0;
        if (dry_run) {
            if (fs::is_symlink(filePath) && !follow_symlinks) {
                logMessage(DRY_RUN, "Symlink file '" + filePath.string() + "' would not be shredded.");
            } else {
            logMessage(DRY_RUN, "Simulating shredding file '" + filePath.string() + "'.");
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

        if (fs::file_size(filePath) == 0) {
            if (!keep_files) {
                logMessage(INFO, "File '" + filePath.string() + "' is empty and will be deleted without overwriting.");
                if (std::remove(filePath.c_str()) == 0) {
                    logMessage(INFO, "Empty file '" + filePath.string() + "' successfully deleted.");
                } else {
                    logMessage(ERROR, "Failed to delete empty file '" + filePath.string() + "'.");
                    return false;
                }
            } else {
                logMessage(WARNING, "File '" + filePath.string() + "' is empty and will not be overwritten.");
            }
            return true;
        }

        auto fileSize = fs::file_size(filePath);
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
            if (overwriteWithRandomData(filePath.string(), file, fileSize) == 1) {
                verificationFailed = 1; // Overwrite function returns 1 if verification fails
            }
            logMessage(INFO, "Completed overwrite pass " + std::to_string(i + 1) + " for file '" + filePath.string() + "'."); // Prints pass count
            std::cout << "Progress: " << std::fixed << std::setprecision(1)  // Percent-style progress meter
                      << ((i + 1) / static_cast<float>(overwriteCount)) * 100 << "%\r" << std::flush;
        }

        if (internal && verificationFailed || verbose && verificationFailed) { logMessage(WARNING, "Overwrite verification failed for '" + filePath.string() + "' Skipping deletion."); } // Prints verification failure, only if verbose because overwrite function says it too.
        file.close(); // Close file, if completed
        syncFile(filePath); // Force filesystem synchronization
        
        if (!keep_files && !verificationFailed) { // Delete file after shredding (if not keeping)
            try {
                std::unique_lock<std::mutex> lock(fileMutex); // Acquire file lock

                fs::permissions(filePath, fs::perms::none); // Remove file permissions

                std::string randomFileName = generateRandomFileName(); // Get a random name
                std::string obfuscatedPath = fs::temp_directory_path() / randomFileName; // Make a temp path and add the random name
                fs::rename(filePath, obfuscatedPath); // Move the file to the new temp directory with the random name

                std::this_thread::sleep_for(std::chrono::milliseconds(50)); // Sleep to wait for new metadata to propagate
                cleanupMetadata(obfuscatedPath); // Cleanup metadata
                std::this_thread::sleep_for(std::chrono::milliseconds(50)); // Same as above
            } catch (...) {
                std::cerr << "An error has occured while obfuscating metadata on the file '" << filePath.string() << "'" << std::endl;
            }

            if (std::remove(filePath.c_str()) == 0) {
                if (verify) { logMessage(INFO, "File '" + filePath.string() + "' shredded, verified, and deleted."); }
                    else if (!verify) { logMessage(INFO, "File '" + filePath.string() +"' shredded and deleted without verification."); }
            } else {
                logMessage(ERROR, "Failed to delete file '" + filePath.string() + "'.");
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

int overwriteWithRandomData(std::string filePath, std::fstream& file, std::uintmax_t fileSize) {
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
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(0, 255);
    std::vector<char> lastRandomData(fileSize); // For verification

    for (std::uintmax_t offset = 0; offset < fileSize; offset += bufferSize) {
        std::uintmax_t writeSize = std::min(bufferSize, fileSize - offset);
        
        // Generate random data for non-secure or final pass
        if (!secure_mode) {
            std::generate(buffer.begin(), buffer.end(), [&]() { return static_cast<char>(dist(gen)); });
            if (verify) { std::copy(buffer.begin(), buffer.begin() + writeSize, lastRandomData.begin() + offset); }
            file.seekp(offset);
            file.write(buffer.data(), writeSize);
        } else {
            // Secure shredding mode with multiple patterns
            for (int pass = 0; pass < securePasses; ++pass) {
                gen.seed(rd() + pass + offset); // Re-seed with the pass and offset
                
                // Apply a pre-set pattern
                std::memcpy(buffer.data(), patterns[pass % patterns.size()].data(), bufferSize);
                file.seekp(offset);
                file.write(buffer.data(), writeSize);

                // Introduce random pattern for every other pass for additional security
                if (pass % 2 == 1) {
                    std::generate(buffer.begin(), buffer.end(), [&]() { return static_cast<char>(dist(gen)); });
                    file.seekp(offset);
                    file.write(buffer.data(), writeSize);
                }
            }

            // DoD-required passes
            // Pass 1: Overwrite with 0x00
            std::fill(buffer.begin(), buffer.end(), '\x00');
            file.seekp(offset);
            file.write(buffer.data(), writeSize);

            // Pass 2: Overwrite with 0xFF
            std::fill(buffer.begin(), buffer.end(), '\xFF');
            file.seekp(offset);
            file.write(buffer.data(), writeSize);

            // Pass 3: Overwrite with random data
            std::generate(buffer.begin(), buffer.end(), [&]() { return static_cast<char>(dist(gen)); });
            if (verify) { std::copy(buffer.begin(), buffer.begin() + writeSize, lastRandomData.begin() + offset); }
            file.seekp(offset);
            file.write(buffer.data(), writeSize);
            if (internal) { std::cout << "Successfully wrote all DoD passes to block" << std::endl; }
        }
    }
    if (internal) { std::cout << "Blocksize: " << bufferSize << std::endl; }
    if (verify) {
        int ret = 1; // Return value (default as "fail")
        file.flush(); // Ensure all writes are complete
        file.seekg(0); // Reset to beginning for verification

        std::vector<char> verifyBuffer(bufferSize);
        verificationFailed = false; // Initializes boolean that determines if file verification failed
#ifdef OPENSSL_FOUND
        ret = verifyWithHash(filePath, lastRandomData); // Verify hash
        if (ret == 2) { verificationFailed = true; }
        if (ret == 0) { return 0; }
#endif
    if (ret == 1) {
        for (std::uintmax_t offset = 0; offset < fileSize; offset += bufferSize) {
            std::uintmax_t readSize = std::min(bufferSize, fileSize - offset);
            file.read(verifyBuffer.data(), readSize);

            // Check if the data is consistent with erasure (e.g., all zeroes after overwrite)
            if (!std::equal(verifyBuffer.begin(), verifyBuffer.begin() + readSize, lastRandomData.begin() + offset)) {
                if (verbose) { std::cerr << "Verification failed at offset: " << offset << '\n'; }
                verificationFailed = true;
                break;
            }
        }
    }
        if (verificationFailed) { return 1; }
    }
    return 0;
}

void help(char* argv[]) {
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
    std::cerr << "    -f <follow symlinks>  Follow symlinks during shredding\n";
    std::cerr << "    -s <secure mode>      Enable secure shredding with randomization (slower)\n";
    std::cerr << "    -d <dry run>          Show what would be shredded without actual processing\n";
    std::cerr << "    -c <no verification>  Skip post-shredding verification (faster)\n\n";

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

    std::cerr << "    -f <follow symlinks>\n";
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

    std::cerr << "EXAMPLES\n";
    std::cerr << "    " << argv[0] << " -n 5 -r -v -s file1.txt file2.txt directory1\n";
    std::cerr << "        Overwrites 'file1.txt' and 'file2.txt' with 5 passes, recursively handles 'directory1', and uses secure\n";
    std::cerr << "        mode with verbose output.\n\n";

    std::cerr << "    " << argv[0] << " -d file1.txt file2.txt\n";
    std::cerr << "        Performs a dry run to show what would be shredded without actual deletion.\n";
}