# DiscordStorage

DiscordStorage is a project that allows you to store files on Discord using a bot token. This project includes all the tools you need to securely store and manage your files.

![GitHub repo size](https://img.shields.io/github/repo-size/keremlolgg/DiscordStorage)
![GitHub stars](https://img.shields.io/github/stars/keremlolgg/DiscordStorage?style=social)
![GitHub forks](https://img.shields.io/github/forks/keremlolgg/DiscordStorage?style=social)
![GitHub issues](https://img.shields.io/github/issues/keremlolgg/DiscordStorage)
![GitHub license](https://img.shields.io/github/license/keremlolgg/DiscordStorage)
![GitHub all releases](https://img.shields.io/github/downloads/keremlolgg/DiscordStorage/total)

## Warning

After uploading a file, do not send any messages to the channel, as it will disrupt the bot's cloud storage functionality.

## Features

- Secure file storage using Discord bot token
- Easy configuration with `config.json` file
- Developed using LibCurl and Dpp libraries
- File size limit management
- Automatic logging of file transfers

## Requirements

- C++ compiler (C++17 or higher)
- [LibCurl](https://curl.se/libcurl/)
- [DPP](https://dpp.dev/)
- [nlohmann/json](https://github.com/nlohmann/json)

## Installation

1. Clone the project:

    ```bash
    git clone https://github.com/keremlolgg/DiscordStorage.git
    cd DiscordStorage
    ```

2. Install the required libraries:

    Install LibCurl and Dpp libraries on your system. You can find installation steps for both libraries in their official documentation.

3. Compile the project:

    Compile your project using Visual Studio or your preferred C++ IDE.

4. Start your bot:

    After compilation is complete, run the executable to start your bot.

## Usage

To upload and store files with the DiscordStorage bot, give your bot the necessary permissions on your Discord server after starting it. You can then use the relevant commands to store your files.

The application will automatically log file transfers in the `postlog.txt` file.

## How It Works

DiscordStorage uses Discord's API through the DPP library to create channels and upload files. The bot creates a dedicated channel for each file and manages the storage within your Discord server. File size limits can be configured in the `config.json` file.

## Contributors

- [Kerem_KK](https://github.com/keremlolgg) - Project owner and developer

## License

This project is licensed under the [GPL License](LICENSE).

## Contact

For any issues or suggestions, please contact me. [Contact](https://keremkk.glitch.me/contact)
