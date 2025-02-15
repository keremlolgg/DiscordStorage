#include <iostream>
#include <fstream>
#include <thread>
#include <future>
#include <cstdlib>
#include <vector>
#include <cstdio>
#include <memory>
#include <array>
#include <set>
#include <chrono>
#include <locale>
#include <regex>
#include <algorithm>
#include <CURL/curl/curl.h>
#include <nlohmann/json.hpp>
#include <dpp/dpp.h>
using namespace std;
using namespace dpp;
int mbsinir = 23;
json j;

string odaismi;
string oda_id;
string mesaj_id;
string olusturulanwebhook;
string odaid;
string guild_id;
string category_id;
using json = nlohmann::json;
json parseEnvFile() {
    json envData;
    std::ifstream file(".env");
    std::string line;

    if (file.is_open()) {
        while (std::getline(file, line)) {
            size_t delimiterPos = line.find('=');
            if (delimiterPos != std::string::npos) {
                std::string key = line.substr(0, delimiterPos);
                std::string value = line.substr(delimiterPos + 1);

                // Key ve value'leri json yapısına ekle
                envData[key] = value;
            }
        }
        file.close();
    }
    else {
        // .env dosyası bulunamazsa, varsayılan değerleri ayarla
        envData["BOT_TOKEN"] = 0;
        envData["guild_id"] = 0;
        envData["mbsinir"] = 8;
        envData["category_id"] = 0;

        // Dosyayı oluştur ve kaydet
        std::ofstream outfile(".env");
        if (outfile.is_open()) {
            outfile << "BOT_TOKEN=" << envData["BOT_TOKEN"] << "\n";
            outfile << "guild_id=" << envData["guild_id"] << "\n";
            outfile << "mbsinir=" << envData["mbsinir"] << "\n";
            outfile << "category_id=" << envData["category_id"] << "\n";
            outfile.close();
        }

        std::cout << ".env dosyası bulunmadı, oluşturuldu: .env" << std::endl;
    }

    return envData;
}
struct Response {
    std::string data;
};
struct Link {
    int parca_numarasi;
    std::string oda_id;
    std::string mesaj_id;
};
size_t write_data(void* buf, size_t size, size_t nmemb, FILE* userp) {
    size_t written = fwrite(buf, size, nmemb, userp);
    return written;
} 
// curl şeysi
size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t total_size = size * nmemb;
    Response* response = static_cast<Response*>(userp);
    response->data.append(static_cast<char*>(contents), total_size);
    return total_size;
}
// curl şeysi
std::string trimWhitespaceAndSpecialChars(const std::string& str) {
    std::string result = str;

    // Başındaki ve sonundaki boşlukları ve \r karakterlerini sil
    result.erase(result.begin(), std::find_if(result.begin(), result.end(), [](unsigned char c) {
        return !std::isspace(c) && c != '\r';
        }));
    result.erase(std::find_if(result.rbegin(), result.rend(), [](unsigned char c) {
        return !std::isspace(c) && c != '\r';
        }).base(), result.end());

    return result;
}
// txt ye yazılamayan hashdeki karakterleri silmek için
std::string getFileHash(const std::string& filename) {
    std::string command = "CertUtil -hashfile \"" + filename + "\" SHA256";
    STARTUPINFOA startupInfo;
    PROCESS_INFORMATION processInfo;
    ZeroMemory(&startupInfo, sizeof(startupInfo));
    ZeroMemory(&processInfo, sizeof(processInfo));
    startupInfo.cb = sizeof(startupInfo);
    startupInfo.dwFlags |= STARTF_USESTDHANDLES;
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    HANDLE hReadPipe, hWritePipe;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        std::cerr << "Pipe oluşturulamadı! Hata kodu: " << GetLastError() << std::endl;
        return "";
    }
    startupInfo.hStdOutput = hWritePipe;
    startupInfo.hStdError = hWritePipe;
    if (!CreateProcessA(NULL, const_cast<char*>(command.c_str()), NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &startupInfo, &processInfo)) {
        CloseHandle(hWritePipe);
        CloseHandle(hReadPipe);
        std::cerr << "Process oluşturulamadı! Hata kodu: " << GetLastError() << std::endl;
        return "";
    }
    CloseHandle(hWritePipe);
    std::array<char, 128> buffer;
    std::string result;
    DWORD bytesRead;
    while (ReadFile(hReadPipe, buffer.data(), buffer.size() - 1, &bytesRead, NULL) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        result += buffer.data();
    }
    CloseHandle(hReadPipe);
    WaitForSingleObject(processInfo.hProcess, INFINITE);
    CloseHandle(processInfo.hProcess);
    CloseHandle(processInfo.hThread);

    std::ofstream outFile("result.txt");
    if (outFile.is_open()) {
        outFile << result;  // Tüm çıktıyı dosyaya yaz
        outFile.close();
    }
    else {
        std::cerr << "Dosya açılamadı!" << std::endl;
        return "";
    }

    // Dosyadan ikinci satırı oku
    std::ifstream inFile("result.txt");
    std::string line;
    std::string secondLine;

    if (inFile.is_open()) {
        int lineCount = 0;
        while (std::getline(inFile, line)) {
            lineCount++;
            if (lineCount == 2) { // İkinci satırı bul
                secondLine = line;
                break;
            }
        }
        inFile.close();
    }
    else {
        std::cerr << "Dosya açılamadı!" << std::endl;
        return "";
    }
    if (std::remove("result.txt") != 0) {
        std::cerr << "Dosya silme hatası: result.txt" << std::endl;
    }
    // İkinci satırı döndür
    return secondLine;
}
// hash hesaplama
std::pair<std::string, std::string> id_bul(const std::string& json_str) {
    std::string oda_id;  // channel_id
    std::string mesaj_id;  // id
    std::string embed_key = "\"embeds\"";

    // JSON verisini parse et
    auto json_response = nlohmann::json::parse(json_str);

    // Channel ID'yi (Oda ID) bulma
    if (json_response.contains("channel_id")) {
        oda_id = json_response["channel_id"].get<std::string>();
    }

    // ID'yi (Mesaj ID) bulma
    if (json_response.contains("id")) {
        mesaj_id = json_response["id"].get<std::string>();
    }

    // Eğer embeds varsa, oradan da id ve channel_id'yi alalım
    if (json_response.contains("embeds") && !json_response["embeds"].empty()) {
        for (const auto& embed : json_response["embeds"]) {
            if (embed.contains("id") && embed.contains("channel_id")) {
                // Embeddeki channel_id ve id'yi alıp ayrı tutuyoruz
                oda_id = embed["channel_id"].get<std::string>();
                mesaj_id = embed["id"].get<std::string>();
            }
        }
    }

    // Oda ve Mesaj ID'lerini döndürüyoruz
    return { oda_id, mesaj_id };
}
// dosyadan oda ve mesaj id yi ayıkla

std::string get_second_line(const std::string& dosya_adi) {
    std::ifstream file(dosya_adi);
    std::string line;
    int line_number = 0;

    // İkinci satırı okuma
    while (std::getline(file, line)) {
        line_number++;
        if (line_number == 2) {
            return line; // İkinci satırı döndür
        }
    }

    return ""; // İkinci satır yoksa boş döndür
}
//buluttaki dosyanın ismini alma
std::pair<std::string, std::string> extract_discord_id(const std::string& input) {
    std::regex number_regex(R"(\((\d+),(\d+)\))"); // (oda_id,mesaj_id) formatındaki sayıları yakalayan regex
    std::smatch number_match;

    if (std::regex_search(input, number_match, number_regex)) {
        return { number_match.str(1), number_match.str(2) }; // Oda ID ve Mesaj ID döndür
    }
    else {
        return { "", "" }; // Eşleşme olmazsa boş stringler döndür
    }
}
// buluttaki dosyanın indirme idleri alma
string get_messages(dpp::cluster& bot, dpp::snowflake channel_id, int64_t limit) {
    std::promise<std::string> promise; // Promise nesnesi oluştur
    std::future<std::string> future = promise.get_future(); // Future oluştur

    bot.messages_get(channel_id, 0, 0, 0, limit, [&promise](const dpp::confirmation_callback_t& callback_response) {
        if (callback_response.is_error()) {
            std::cerr << "Hata: " << callback_response.get_error().message << std::endl;
            promise.set_value(""); // Hata durumunda boş string döndür
            return;
        }

        auto messages = callback_response.get<dpp::message_map>();
        std::string contents;

        for (const auto& x : messages) {
            contents += x.second.content + '\n'; // Mesaj içeriğini ekle
        }

        promise.set_value(contents); // Mesaj içeriğini döndür
        });

    return future.get(); // Mesajlar alındıktan sonra sonucu döndür
}
// odadaki son mesajı alır
std::string get_file_url(const std::string& channel_id, const std::string& message_id) {
    // Örnek: parseEnvFile fonksiyonunu kullanarak BOT_TOKEN'ı çekiyoruz (kendi fonksiyonunuz)
    json envData = parseEnvFile();  // Burada çevresel verileri okuyoruz (BOT_TOKEN gibi)
    std::string bot_token = envData["BOT_TOKEN"]; // Token'ı alıyoruz
    CURL* curl;
    CURLcode res;
    std::string read_buffer;

    // Discord API URL'si
    std::string url = "https://discord.com/api/v10/channels/" + channel_id + "/messages/" + message_id;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L); // SSL doğrulamasını devre dışı bırak
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L); // Host doğrulamasını devre dışı bırak

    if (curl) {
        // Header'lar
        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, ("Authorization: Bot " + bot_token).c_str());  // Burada .c_str() kullanıyoruz

        // URL ve header'lar ayarlandı
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());  // .c_str() kullanarak doğru türde parametre sağlıyoruz
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        // Yanıtın okunacağı buffer
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &read_buffer);

        // İstek gönderiliyor
        res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            std::cerr << "Curl hata: " << curl_easy_strerror(res) << std::endl;
            curl_easy_cleanup(curl);
            return "";
        }

        // JSON parsing işlemi
        try {
            // nlohmann/json kütüphanesi ile yanıtı parse ediyoruz
            auto json_response = nlohmann::json::parse(read_buffer);

            // Dosyanın URL'sini almak için json yanıtını kontrol ediyoruz
            if (!json_response.empty() && json_response.contains("attachments") && !json_response["attachments"].empty()) {
                // İlk dosyanın URL'si
                std::string file_url = json_response["attachments"][0]["url"];
                curl_easy_cleanup(curl);
                return file_url;
            }
            else {
                cerr << "Dönüt: " << read_buffer << endl;
                std::cerr << "Mesajda dosya bulunamadı!" << std::endl;
                curl_easy_cleanup(curl);
                return "";
            }
        }
        catch (const nlohmann::json::exception& e) {
            std::cerr << "JSON parsing hatası: " << e.what() << std::endl;
            curl_easy_cleanup(curl);
            return "";
        }
    }

    curl_easy_cleanup(curl);
    return "";
}
// oda id ve mesaj id den indirme linki alma
std::string json_yaz(int parca_no, const std::string& oda_id, const std::string& mesaj_id) {
    // JSON objesi oluştur
    nlohmann::json json_obj;
    json_obj["parca_no"] = parca_no;
    json_obj["oda_id"] = oda_id;
    json_obj["mesaj_id"] = mesaj_id;

    // JSON'u string olarak döndür
    std::string json_string = json_obj.dump();


    return json_string;  // JSON stringini döndür
}

void createWebhook(dpp::cluster& bot, const std::string& channel_id, const std::string& name) {
    dpp::webhook wh;
    wh.name = name;  // Webhook adını belirle
    wh.channel_id = channel_id;  // Hedef kanalın ID'sini belirt

    string webhook_url; // URL için optional değişken

    bot.create_webhook(wh, [&webhook_url](const dpp::confirmation_callback_t& callback) {
        if (callback.is_error()) {
            std::cerr << "Webhook oluşturulamadı: " << callback.get_error().message << std::endl;
        }
        else {
            const dpp::webhook& created_webhook = std::get<dpp::webhook>(callback.value);
            std::cout << "Webhook oluşturuldu: " << created_webhook.name << " (ID: " << created_webhook.id << ")" << std::endl;
            std::cout << "Webhook URL: " << created_webhook.url << std::endl;
            olusturulanwebhook = created_webhook.url; // URL'yi optional değişkene ata
        }
        });
}
//webhook oluşturma
void create_category(dpp::cluster& bot, const std::string& category_name, const std::string& guild_id, std::function<void(const std::string&)> on_category_created) {
    // Kategori oluşturma
    dpp::channel category = dpp::channel()
        .set_name(category_name)
        .set_guild_id(guild_id)
        .set_type(dpp::channel_type::CHANNEL_CATEGORY); // Kategori olarak ayarla

    bot.channel_create(category, [&bot, on_category_created](const dpp::confirmation_callback_t& callback) {
        if (callback.is_error()) {
            bot.log(dpp::loglevel::ll_error, callback.get_error().message);
            return;
        }

        auto created_category = callback.get<dpp::channel>();
        std::string category_id = std::to_string(created_category.id);
        std::cout << "Kategori oluşturuldu: " << created_category.name << " (ID: " << category_id << ")" << std::endl;
        on_category_created(category_id);  // Kategori ID'sini geri döndür
        });
}
// kategori oluşturma
void create_channel(dpp::cluster& bot, const std::string& channel_name, const std::string& guild_id, const std::string& category_id) {
    dpp::channel channel = dpp::channel()
        .set_name(channel_name)
        .set_guild_id(guild_id);

    if (category_id != "category_id") {
        channel.set_parent_id(category_id); // Kategori ID'si varsa kanalı ona bağla
    }

    bot.channel_create(channel, [&bot, category_id](const dpp::confirmation_callback_t& callback) {
        if (callback.is_error()) {
            bot.log(dpp::loglevel::ll_error, callback.get_error().message);
            return;
        }

        auto created_channel = callback.get<dpp::channel>();
        std::string odaismi = created_channel.name;
        std::string odaid = std::to_string(created_channel.id);
        std::cout << "Odanın adı: " << odaismi << ", ID: " << odaid << std::endl;
        createWebhook(bot, odaid, "Dosya Yukleyici"); 
    });
}
// kanal oluşturma

std::vector<std::string> dosya_listesi(const std::string& yol) {
    std::vector<std::string> dosyalar;
    // Dışlanacak dosyaların seti
    std::set<std::string> dislanacak_dosyalar = {
        ".env",
        "DiscordDepolama.exe",
        "dpp.dll",
        "libcrypto-1_1-x64.dll",
        "libcurl-x64.dll",
        "libsodium.dll",
        "libssl-1_1-x64.dll",
        "opus.dll",
        "zlib1.dll",
        //debug için rahatsız ediyor
        "DiscordDepolama.aps",
        "DiscordDepolama.vcxproj",
        "DiscordDepolama.vcxproj.filters",
        "DiscordDepolama.vcxproj.user",
        "gonderimlog.txt",
        "Main.cpp",
        "Resource.rc",
        "resource1.h",
        "Özellik.props"
    };

    for (const auto& entry : std::filesystem::directory_iterator(yol)) {
        if (entry.is_regular_file()) {
            std::string dosya_adi = entry.path().filename().string();
            // Eğer dosya adını dışlanacak dosyalar setinde bulamazsak ekle
            if (dislanacak_dosyalar.find(dosya_adi) == dislanacak_dosyalar.end()) {
                dosyalar.push_back(dosya_adi);
            }
        }
    }
    return dosyalar;
}
//yerel dosya listesi
void get_cloud_files(dpp::cluster& bot, const std::string& guild_id, const std::string& category_id, std::vector<dpp::snowflake>& bulut_dosyalar) {
    bulut_dosyalar.clear();
    bot.channels_get(guild_id, [&bot, category_id, &bulut_dosyalar](const dpp::confirmation_callback_t& callback) {
        if (callback.is_error()) {
            std::cerr << "Kanallar alınırken hata oluştu: " << callback.get_error().message << std::endl;
            return;
        }

        auto channel_map = std::get<dpp::channel_map>(callback.value);
        for (const auto& [id, channel] : channel_map) {
            if (std::to_string(channel.parent_id) == category_id) {
                bulut_dosyalar.push_back(channel.id);
            }
        }
        });
}
// buluttaki dosya listesi
void dosya_gonder(const std::string& webhook_url, const std::string& dosya_yolu, const int& parca_no, const std::string& mesaj, const int& silme, const string& linkleridosyasi) {
    CURL* curl;
    CURLcode res;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    if (curl) {
        curl_mime* form = NULL;
        curl_mimepart* field = NULL;

        form = curl_mime_init(curl);

        curl_easy_setopt(curl, CURLOPT_URL, webhook_url.c_str());

        field = curl_mime_addpart(form);
        curl_mime_data(field, mesaj.c_str(), CURL_ZERO_TERMINATED);
        curl_mime_name(field, "content");

        field = curl_mime_addpart(form);
        curl_mime_filedata(field, dosya_yolu.c_str());
        curl_mime_name(field, "file");

        curl_easy_setopt(curl, CURLOPT_MIMEPOST, form);

        Response response;
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            std::cerr << "Dosya gönderme hatasi: " << curl_easy_strerror(res) << std::endl;
        }
        else {
            std::cout << "\033[1;31m" << dosya_yolu << " Basari ile gönderildi!" << std::endl;

            if (silme) {
                if (std::remove(dosya_yolu.c_str()) != 0) {
                    std::cerr << "Dosya silme hatasi: " << dosya_yolu << std::endl;
                }
            }
            std::ofstream dosya2("gonderimlog.txt", std::ios::app);
            dosya2 << "Webhook Yanıtı: " << response.data << std::endl;
            dosya2.close();
            auto [oda_id2, mesaj_id2] = id_bul(response.data);
            if (!mesaj_id2.empty()) {
                if (silme == 1) {
                    std::ofstream dosya2(linkleridosyasi, std::ios::app);
                    dosya2 << json_yaz(parca_no,oda_id2,mesaj_id2) << std::endl;
                    cout << json_yaz(parca_no, oda_id2, mesaj_id2) << endl;
                    dosya2.close();
                }
                else {
                    cout << json_yaz(parca_no, oda_id2, mesaj_id2) << endl;
                    oda_id = oda_id2;
                    mesaj_id = mesaj_id2;
                }
            }
            else {
                std::cout << "URL bulunamadi. Lütfen gonderimlog.txt dosyasından hataya bakınız." << std::endl;
            }
        }

        curl_mime_free(form);
        curl_easy_cleanup(curl);
    }

    curl_global_cleanup();
}
// weebhook ile dosyası gönderme
int dosya_indir(const std::string& url, const std::string& dosya_adi) {
    CURL* curl;
    FILE* fp;
    CURLcode res;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);

        if (fopen_s(&fp, dosya_adi.c_str(), "wb") != 0) {
            std::cerr << "Dosya açılamadı: " << dosya_adi << std::endl;
            return 1;
        }

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }

        fclose(fp);
        curl_easy_cleanup(curl);
    }

    curl_global_cleanup();
    return 0;
}
//dosya indirme
void dosya_sec(dpp::cluster& bot, const std::vector<std::string>& yerel_dosyalar, const std::vector<dpp::snowflake>& bulut_dosyalar, std::string& dosya_yolu) {
    while (true) {
        std::cout << "\033[1;33mMevcut dosyalar:\033[0m" << std::endl;

        // Yerel dosyalar
        std::cout << "\033[1;34mYerel Dosyalar:\033[0m" << std::endl;
        for (size_t i = 0; i < yerel_dosyalar.size(); ++i) {
            std::cout << i + 1 << ". " << yerel_dosyalar[i] << std::endl;
        }

        // Buluttaki dosyalar
        std::cout << "\033[1;34mBuluttaki Dosyalar:\033[0m" << std::endl;
        for (size_t i = 0; i < bulut_dosyalar.size(); ++i) {
            string obj = get_messages(bot, bulut_dosyalar[i], 1);

            // JSON formatında olup olmadığını kontrol et
            try {
                json json_obj = json::parse(obj);
                std::cout << i + 1 + yerel_dosyalar.size() << ". " << json_obj["dosya_adi"] << std::endl;
            }
            catch (const json::parse_error& e) {
                // JSON formatında değilse, hata ver ve geç
                std::cout << "\033[1;31mBuluttaki dosya JSON formatında değil, geçiliyor...\033[0m" << std::endl;
                continue;  // JSON hatası alırsak bu öğeyi atla
            }
        }

        std::cout << "\033[1;34m-----------------------------------------------------------------------" << std::endl;
        std::cout << "\033[1;33mLütfen seçiminizi yapınız (numara giriniz):\033[0m" << std::endl;

        int secim;
        std::cin >> secim;

        // Seçim kontrolü
        if (secim > 0 && secim <= static_cast<int>(yerel_dosyalar.size() + bulut_dosyalar.size())) {
            if (secim <= static_cast<int>(yerel_dosyalar.size())) {
                dosya_yolu = yerel_dosyalar[secim - 1];
            }
            else {
                string obj = get_messages(bot, bulut_dosyalar[secim - 1 - yerel_dosyalar.size()], 1);

                // JSON formatında olmasını bekliyoruz, ancak bunu tekrar kontrol edelim
                try {
                    json data = json::parse(obj);
                    string oda_id = data["oda_id"];
                    string mesaj_id = data["mesaj_id"];
                    std::cout << "oda id: " << oda_id << " mesaj id: " << mesaj_id << std::endl;
                    string download_link = get_file_url(oda_id, mesaj_id);
                    std::string indirilen_dosya = "indirilen_dosya"; // Geçici dosya adı

                    // Dosyayı indir
                    if (dosya_indir(download_link, indirilen_dosya) == 0) {
                        std::cout << "Dosya başarıyla indirildi: " << indirilen_dosya << std::endl;

                        // İkinci satırı oku ve dosya adını belirle
                        std::string yeni_dosya_adi = get_second_line(indirilen_dosya);
                        if (!yeni_dosya_adi.empty()) {
                            yeni_dosya_adi += ".txt"; // Dosya uzantısını ekleyin
                            rename(indirilen_dosya.c_str(), yeni_dosya_adi.c_str()); // Dosya adını değiştir
                            dosya_yolu = yeni_dosya_adi; // İndirilen dosyanın yeni yolunu güncelle
                            std::cout << "Dosya adı değiştirildi: " << yeni_dosya_adi << std::endl;
                        }
                        else {
                            std::cout << "\033[1;31mİkinci satır okunamadı. Dosya adı değiştirilemedi.\033[0m" << std::endl;
                        }
                    }
                    else {
                        std::cout << "\033[1;31mDosya indirme işlemi başarısız.\033[0m" << std::endl;
                    }
                }
                catch (const json::parse_error& e) {
                    std::cout << "\033[1;31mBulut dosyası JSON formatında değil, geçiliyor...\033[0m" << std::endl;
                    continue;  // JSON hatası alırsak bu dosyayı atla
                }
            }
            break;
        }
        else {
            std::cout << "\033[1;31mGeçersiz seçim.\033[0m" << std::endl;
        }
    }
}
// dosya seçtirir dosya_yolu nu seçilen dosyanın adı yapar

void dosyayi_parcalara_bol_ve_gonder(const std::string& dosya_yolu, dpp::cluster& bot, size_t parca_boyutu = mbsinir * 1024 * 1024) {
    std::string linkler_txt = dosya_yolu + "_linkleri.txt";
    int mevcut_parca_sayisi = 0;
    string hash;
    std::ifstream dosya(dosya_yolu, std::ios::binary);
    if (!dosya) {
        std::cerr << "Dosya açılamadı: " << dosya_yolu << std::endl;
        return;
    }
    dosya.seekg(0, std::ios::end);
    size_t dosya_boyutu = dosya.tellg();
    dosya.seekg(0, std::ios::beg);
    int toplam_parca = static_cast<int>((dosya_boyutu + parca_boyutu - 1) / parca_boyutu);
    std::ifstream kontrol(linkler_txt);
    if (kontrol) {
        std::string son_satir;
        getline(kontrol, son_satir);
        getline(kontrol, son_satir);
        getline(kontrol, hash);
        getline(kontrol, olusturulanwebhook);
        if (trimWhitespaceAndSpecialChars(hash) == trimWhitespaceAndSpecialChars(getFileHash(dosya_yolu))) {
            while (std::getline(kontrol, son_satir)) {
                json json_obj = json::parse(son_satir);
                mevcut_parca_sayisi = json_obj["parca_no"];
            }
            cout << "\033[1;31mAynı dosya tespit edildi kaldığı yerden devam ediyor.\n" << endl;
        }
        else {
            cout << "\033[1;31mAynı isimde farklı bir dosya tespit edildi lütfen diğer dosyayı silin veya taşıyın." << endl;
            kontrol.close();
            dosya.close();
            return;
        }
        kontrol.close();
    }
    else {
        create_channel(bot, dosya_yolu, guild_id, category_id); // webhook oluşturuluyor
        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::ofstream dosya2(linkler_txt, std::ios::app);
        dosya2 << toplam_parca << std::endl;
        dosya2 << dosya_yolu << std::endl;
        dosya2 << getFileHash(dosya_yolu) << endl;
        dosya2 << olusturulanwebhook << endl;
        dosya2.close();
    }

    char* buffer = new char[parca_boyutu];
    cout << "\033[1;31mToplam yuklenecek parca sayisi. " << toplam_parca << endl;
    int parca_no = mevcut_parca_sayisi + 1;
    dosya.seekg(parca_boyutu * (mevcut_parca_sayisi), std::ios::beg);
    while (!dosya.eof()) {
        dosya.read(buffer, parca_boyutu);
        std::streamsize bytes_okunan = dosya.gcount();

        if (bytes_okunan <= 0) {
            break;
        }

        std::string parca_dosyasi_adi = dosya_yolu + " parca" + std::to_string(parca_no) + ".txt";

        std::ofstream parca_dosyasi(parca_dosyasi_adi, std::ios::binary);
        parca_dosyasi.write(buffer, bytes_okunan);
        parca_dosyasi.close();

        std::string mesaj = dosya_yolu + "'nin parcasi No: " + std::to_string(parca_no);
        dosya_gonder(olusturulanwebhook, parca_dosyasi_adi, parca_no, mesaj, 1, linkler_txt);
        parca_no++;
    }

    delete[] buffer;
    dosya.close();
    dosya_gonder(olusturulanwebhook, linkler_txt, parca_no, dosya_yolu + "'nin indirme linkleri\n```Dosyanin Anlami:\n1. Satir: Toplam Parca Sayisi\n2. Satir: Dosyanin Adi\n3. Satir: Dosyanin Hash Degeri\nSonraki Satirlar: Parca Numarasi, Oda Id, Mesaj Id```", 0, linkler_txt);
    dpp::webhook wh(olusturulanwebhook);
   // bot.execute_webhook(wh, dpp::message(dosya_yolu + "'nin indirme bilgileri: ("+oda_id+mesaj_id+")\nProgram linki: [Tikla](https://github.com/keremlolgg/DiscordStorage/releases/latest)"));
    bot.execute_webhook(wh, dpp::message("Program Linki: https://github.com/keremlolgg/DiscordStorage/releases/latest"));
    json json_obj = {
        {"dosya_adi", dosya_yolu},
        {"oda_id", oda_id},
        {"mesaj_id", mesaj_id}
    };
    bot.execute_webhook(wh, dpp::message(json_obj.dump()));
}
// secilen dosyayı parçalara ayırır ve gönderir
void dosyalari_birlestir(const std::string& linkler_dosya_adi) {
    std::ifstream linkler_dosyasi(linkler_dosya_adi);
    if (!linkler_dosyasi) {
        std::cerr << "Linkler dosyası açılamadı: " << linkler_dosya_adi << std::endl;
        return;
    }

    int toplam_parca = 0;
    std::string hash;
    std::string satir;
    std::string hedef_dosya_adi;
    std::string webhook;
    std::vector<Link> linkler;

    if (std::getline(linkler_dosyasi, satir)) {
        try {
            toplam_parca = std::stoi(satir);
        }
        catch (const std::exception& e) {
            std::cerr << "Toplam parça sayısı okunamadı: " << e.what() << std::endl;
            return;
        }
    }

    if (!std::getline(linkler_dosyasi, hedef_dosya_adi)) {
        std::cerr << "Hedef dosya adı okunamadı!" << std::endl;
        return;
    }
    if (!std::getline(linkler_dosyasi, hash)) {
        std::cerr << "Hash okunamadı!" << std::endl;
        return;
    }
    if (!std::getline(linkler_dosyasi, webhook)) {
        std::cerr << "Webhook okunamadı!" << std::endl;
        return;
    }
    while (std::getline(linkler_dosyasi, satir)) {
        int parca_numarasi;
        std::string oda_id, mesaj_id;
        json json_obj = json::parse(satir);
        cout << json_obj << endl;

        parca_numarasi = json_obj["parca_no"];
        mesaj_id = json_obj["mesaj_id"];
        oda_id = json_obj["oda_id"];
        linkler.push_back({ parca_numarasi, oda_id, mesaj_id });
    }
    linkler_dosyasi.close();

    // URL sayısının toplam parça sayısı ile uyumlu olup olmadığını kontrol ediyoruz
    if (linkler.size() != toplam_parca) {
        cout << "Link Sayısı: " << linkler.size() << " Parça Sayısı: " << toplam_parca << endl;
        std::cerr << "URL sayısı toplam parça sayısıyla uyuşmuyor!" << std::endl;
        return;
    }

    // Parçaları sırasına göre sıralıyoruz
    std::sort(linkler.begin(), linkler.end(), [](const Link& a, const Link& b) {
        return a.parca_numarasi < b.parca_numarasi;
        });

    // Hedef dosyayı açıyoruz
    std::ofstream hedef_dosya(hedef_dosya_adi, std::ios::binary);
    if (!hedef_dosya) {
        std::cerr << "Hedef dosya açılamadı: " << hedef_dosya_adi << std::endl;
        return;
    }

    // Paralel indirme işlemlerini başlatıyoruz
    std::vector<std::future<void>> paralel_indirmeler;

    for (const auto& link : linkler) {
        std::string parca_dosyasi_adi = "parca" + std::to_string(link.parca_numarasi) + ".txt";
        std::string url = get_file_url(link.oda_id, link.mesaj_id);
        //cout << "Parça: "+ parca_dosyasi_adi+"\nUrl: " << url << "\nOda İd: " << link.oda_id << "\nMesaj İd: " << link.mesaj_id << endl;

        paralel_indirmeler.push_back(std::async(std::launch::async, [url, parca_dosyasi_adi]() {
            dosya_indir(url, parca_dosyasi_adi);
            }));
    }

    // İndirme işlemleri tamamlanana kadar bekliyoruz
    for (auto& indirme : paralel_indirmeler) {
        indirme.get();
    }

    // İndirilen parçaları birleştiriyoruz
    for (const auto& link : linkler) {
        std::string parca_dosyasi_adi = "parca" + std::to_string(link.parca_numarasi) + ".txt";
        std::ifstream parca_dosyasi(parca_dosyasi_adi, std::ios::binary);
        if (parca_dosyasi) {
            hedef_dosya << parca_dosyasi.rdbuf();
            parca_dosyasi.close();
            std::cout << parca_dosyasi_adi << " birleştirildi." << std::endl;
        }
        else {
            std::cerr << "Parça açılamadı: " << parca_dosyasi_adi << std::endl;
        }

        // Parça dosyasını siliyoruz
        if (std::remove(parca_dosyasi_adi.c_str()) != 0) {
            std::cerr << "Parça dosyası silme hatası: " << parca_dosyasi_adi << std::endl;
        }
    }

    hedef_dosya.close();

    // Oluşturulan dosyanın hash'ini kontrol ediyoruz
    if (getFileHash(hedef_dosya_adi) != hash) {
        std::cout << "\033[1;31mOluşturulan dosya ile yüklenen dosya hashleri tutmuyor!" << std::endl;
    }
    else {
        std::cout << "\033[1;31mOluşturulan dosya ile yüklenen dosya hashleri aynı!" << std::endl;
    }
}
// secilen dosyaları indirir birleştirir ardından geçici dosyaları siler

int main() {
    setlocale(LC_ALL, "Turkish");
    string secim = "";
    std::vector<dpp::snowflake> bulut_dosyalar;
    json envData = parseEnvFile();
    dpp::cluster bot(envData["BOT_TOKEN"], dpp::i_default_intents | dpp::i_message_content);
    guild_id = envData["guild_id"]; string mbsinir_str = envData["mbsinir"]; mbsinir = stoi(mbsinir_str); category_id = envData["category_id"];
    bot.on_ready([&bot](const dpp::ready_t& event) {
        if (dpp::run_once<struct register_bot_commands>()) {
            dpp::slashcommand ping("ping", "pong!", bot.me.id);
            bot.global_bulk_command_create({ ping });
        }
 
        bot.set_presence(dpp::presence(dpp::ps_online, dpp::at_game, "Github: Keremlolgg/DiscordStorage"));
    });
    bot.on_slashcommand([](const dpp::slashcommand_t& event) {
        if (event.command.get_command_name() == "ping") {
            event.reply("pong!");
            std::cout << "Pong!" << endl;
        }
    });
    std::thread bot_thread([&bot]() {
        bot.start(dpp::st_wait);
    });
    while (true) {
        std::cout << "\033[1;31mProgram Sahibi Kerem Kuyucu.\n";
        cout << "\033[1;34m-----------------------------------------------------------------------" << endl;
        cout << "\033[1;33mLütfen 'Yedekle', 'İndir' veya 'hatalı-dosyayı-yükle' seçeneğini giriniz:" << endl;
        cout << "1. Yedekle" << endl;
        cout << "2. İndir" << endl;
        cout << "3. hatalı-dosyayı-yükle" << endl;
        cin >> secim;
        cin.ignore();

        if (secim != "1" && secim != "2" && secim != "3") {
            cout << "\033[1;31mGeçersiz seçim. Lütfen 'Yedekle', 'İndir' veya 'hatalı-dosyayı-yükle' seçeneğini giriniz:\033[0m" << endl;
            continue; // Geçersiz seçimde döngünün başına dön
        }

        if (secim == "1") {
            // Yedekleme işlemleri
            string dosya_yolu;
            cout << "\033[1;33mLütfen yüklemek istediğiniz dosyayı seçiniz.\033[0m" << endl;
            vector<string> dosyalar = dosya_listesi(".");
            get_cloud_files(bot, guild_id, category_id, bulut_dosyalar);
            cout << "\033[1;33mLütfen 1 saniye bekleyin.\033[0m" << endl;
            std::this_thread::sleep_for(std::chrono::seconds(1));
            dosya_sec(bot, dosyalar, bulut_dosyalar, dosya_yolu);
            if (!dosya_yolu.empty()) {
                dosyayi_parcalara_bol_ve_gonder(dosya_yolu, bot);
                cout << "\n\n\n\n\n";
                cout << "\033[1;33mLütfen " + dosya_yolu + "_linkleri.txt dosyasını saklayın. O dosya sayesinde dosyanızı tekrar indirebilirsiniz.\033[0m" << endl;
                cout << "\033[1;34mOdaya Sakın Mesaj yazmayın.\033[0m" << endl;
                cout << "\033[1;33mEğer silinmeyen parça varsa o yüklenmemiş olabilir lütfen o parçayı kontrol edin ve parçayı elle yükleyerek\noda ve mesaj id sini olması gereken yere ekleyin.\033[0m" << endl;
                cout << "\033[1;33mLütfen bu yedeği dosyanın tek yedeği olarak tutmayın alternatif olarak saklayın.\033[0m" << endl;
                cout << "\033[1;34mNe Demişler: Veriniz üç yerde yoksa o veri yok demektir.\033[0m" << endl;
            }
        }
        else if (secim == "2") {
            // İndirme işlemleri
            string dosya_yolu;
            cout << "\033[1;33mLütfen \"dosya adı\"_linkleri.txt dosyasını seçin.\033[0m" << endl;
            vector<string> dosyalar = dosya_listesi(".");
            get_cloud_files(bot, guild_id, category_id, bulut_dosyalar);
            cout << "\033[1;33mLütfen 1 saniye bekleyin.\033[0m" << endl;
            std::this_thread::sleep_for(std::chrono::seconds(1));
            dosya_sec(bot, dosyalar, bulut_dosyalar, dosya_yolu);

            if (!dosya_yolu.empty()) {
                dosyalari_birlestir(dosya_yolu);
                cout << "\033[1;31mDosya indirildi!" << endl;
            }
        }
        else if (secim == "3") {
            string hataliwebhook;
            string dosya_yolu;
            cout << "Lütfen hatalı dosyayı yüklemek için webhook linki giriniz:" << endl;
            getline(cin, hataliwebhook);
            cout << "Lütfen hatalı dosyayı seçin." << endl;
            vector<string> dosyalar = dosya_listesi(".");
            get_cloud_files(bot, guild_id, category_id, bulut_dosyalar);
            cout << "\033[1;33mLütfen 1 saniye bekleyin.\033[0m" << endl;
            std::this_thread::sleep_for(std::chrono::seconds(1));
            dosya_sec(bot, dosyalar, bulut_dosyalar, dosya_yolu);
            dosya_gonder(hataliwebhook, dosya_yolu, 1, dosya_yolu + " ", 0, "gonderimlog.txt");
        }
    }
    bot_thread.join();
    return 0;
}
