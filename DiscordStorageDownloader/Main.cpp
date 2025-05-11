#include <iostream>
#include <fstream>
#include <string>
#include <filesystem>
#include <nlohmann/json.hpp> 
using namespace std;
using namespace filesystem;
using json = nlohmann::json;

bool versionControl = false;
string remoteVersion, localVersion;
string botToken, categoryId, guildId;

struct FileData {
    string url;
    string fileName;
    bool forceDownload;
    int fileSize;
};

void download(const string& url, const string& filename, const bool& forceDownload, const int& fileSize) {
    string file = "C:\\Users\\Public\\Documents\\discordStorage\\" + filename;
    create_directories(path(file).parent_path());
    if (forceDownload || (!exists(file)) || (fileSize != 0 && fileSize != file_size(file))) {
        int systemResult = system(("powershell -Command \"Invoke-WebRequest -Uri '" + url + "' -OutFile '" + file + "'\"").c_str());
        cout << "\033[1;34m" << file << (systemResult == 0 ? "\033[1;32m,   downloaded.\033[0m" : "\033[1;31m,   failed to download.\033[0m") << endl;
    }
}

bool checkVersions() {
    if (!versionControl)
        download("https://github.com/KeremKuyucu/DiscordStorage/raw/refs/heads/main/AppFiles/latestversion.txt", "latestversion.txt", true, 0);

    ifstream file1("C:\\Users\\Public\\Documents\\discordStorage\\latestversion.txt");
    getline(file1, remoteVersion);
    file1.close();

    ifstream file2("C:\\Users\\Public\\Documents\\discordStorage\\localVersion.txt");
    getline(file2, localVersion);
    file2.close();

    versionControl = true;
    return remoteVersion != localVersion;
}

vector<FileData> files = {
    {"https://github.com/KeremKuyucu/DiscordStorage/raw/refs/heads/main/AppFiles/dpp.dll",                "dpp.dll", 0, 3207680},
    {"https://github.com/KeremKuyucu/DiscordStorage/raw/refs/heads/main/AppFiles/libcrypto-1_1-x64.dll",  "libcrypto-1_1-x64.dll", 0, 3473408},
    {"https://github.com/KeremKuyucu/DiscordStorage/raw/refs/heads/main/AppFiles/libcurl-x64.dll",        "libcurl-x64.dll", 0, 3155048},
    {"https://github.com/KeremKuyucu/DiscordStorage/raw/refs/heads/main/AppFiles/libsodium.dll",          "libsodium.dll", 0, 330752},
    {"https://github.com/KeremKuyucu/DiscordStorage/raw/refs/heads/main/AppFiles/libssl-1_1-x64.dll",     "libssl-1_1-x64.dll", 0, 686080},
    {"https://github.com/KeremKuyucu/DiscordStorage/raw/refs/heads/main/AppFiles/opus.dll",               "opus.dll", 0, 395776},
    {"https://github.com/KeremKuyucu/DiscordStorage/raw/refs/heads/main/AppFiles/zlib1.dll",              "zlib1.dll", 0, 87040},
    {"https://github.com/KeremKuyucu/DiscordStorage/raw/refs/heads/main/AppFiles/DiscordStorage.exe",     "discordStorage.exe", checkVersions(), 0},
    {"https://github.com/KeremKuyucu/DiscordStorage/raw/refs/heads/main/AppFiles/latestversion.txt",      "localVersion.txt", checkVersions(), 0}
};

int main() {
    setlocale(LC_ALL, "Turkish"); // You can change to "en_US.UTF-8" if needed
    current_path("C:\\Users\\Public\\Documents\\discordStorage");
    path applicationPath = "discordStorage.exe";

    cerr << "\033[1;31mVerifying files and downloading missing ones...\033[0m" << endl;

    for (const auto& data : files) {
        download(data.url, data.fileName, data.forceDownload, data.fileSize);
    }

    ifstream inFile("config.json");
    if (!inFile.is_open()) {
        cout << "\033[1;31mconfig.json file not found. Please enter the required information to create it.\033[0m" << endl;

        cout << "\033[1;31mEnter your Bot Token: \033[0m";
        cin >> botToken;

        cout << "\033[1;31mEnter your Storage Category ID: \033[0m";
        cin >> categoryId;

        cout << "\033[1;31mEnter your Guild ID: \033[0m";
        cin >> guildId;

        json configData;
        configData["BOT_TOKEN"] = botToken;
        configData["category_id"] = categoryId;
        configData["guild_id"] = guildId;

        ofstream outFile("config.json");
        if (outFile.is_open()) {
            outFile << configData.dump(4);
            outFile.close();
            cout << "\033[1;32mconfig.json file created successfully.\033[0m" << endl;
        }
        else {
            cerr << "\033[1;31mFailed to create config.json file.\033[0m" << endl;
            return 1;
        }
    }
    else {
        cout << "\033[1;32mconfig.json file exists.\033[0m" << endl;
    }

    int result = system("discordStorage.exe");
    if (result != 0) {
        cout << "\033[1;33mIf the application does not start,\n"
            << "\033[1;34mGo to C:\\Users\\Public\\Documents\\discordStorage\033[1;33m and try running "
            << "discordStorage.exe manually.\033[0m\n";
    }
    return 0;
}
