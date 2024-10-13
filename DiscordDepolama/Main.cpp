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
#include <CURL/curl/curl.h>
#include <nlohmann/json.hpp>
#include <dpp/dpp.h>
using namespace std;
using namespace dpp;
int mbsinir = 23;
json j;
string url;
string odaismi;
string olusturulanwebhook;
string webhook_log;
string odaid;
string guild_id;
string category_id;
using json = nlohmann::json;
struct Response {
    std::string data;
};
std::vector<std::string> dosya_listesi(const std::string& yol) {
    std::vector<std::string> dosyalar;
    // Dışlanacak dosyaların seti
    std::set<std::string> dislanacak_dosyalar = {
        "discord.json",
        "DiscordDepolama.exe",
        "dpp.dll",
        "libcrypto-1_1-x64.dll",
        "libcurl-x64.dll",
        "libsodium.dll",
        "libssl-1_1-x64.dll",
        "opus.dll",
        "zlib1.dll"
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
void update_json_and_save() {
    std::ofstream outFile("discord.json");
    outFile << j.dump(4);
    outFile.close();
}
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
std::string url_bul(const std::string& json_str) {
    std::string url;
    std::string key = "\"url\":\"";
    std::size_t start = json_str.find(key);

    if (start != std::string::npos) {
        start += key.length();
        std::size_t end = json_str.find("\"", start);
        if (end != std::string::npos) {
            url = json_str.substr(start, end - start);
        }
    }

    return url;
}
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
std::string extract_discord_link(const std::string& input) {
    std::regex url_regex(R"(https?://cdn\.discordapp\.com[^\s]*)"); // "cdn.discord" ile başlayan URL'yi bulmak için regex
    std::smatch url_match;

    if (std::regex_search(input, url_match, url_regex)) {
        return url_match.str(0); // Bulunan ilk URL'yi döndür
    }
    else {
        return ""; // Eğer URL bulunamazsa boş string döndür
    }
}
std::string extract_before_download_links(const std::string& input) {
    std::string delimiter = ": [Tikla]"; // Hedef kelime
    size_t pos = input.find(delimiter); // Hedef kelimenin pozisyonu

    if (pos != std::string::npos) { // Eğer hedef kelime bulunduysa
        return input.substr(0, pos); // Başlangıçtan hedef kelimenin bulunduğu yere kadar olan kısmı döndür
    }
    else {
        return ""; // Eğer hedef kelime bulunamazsa boş string döndür
    }
}
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
size_t write_data(void* buf, size_t size, size_t nmemb, FILE* userp) {
    size_t written = fwrite(buf, size, nmemb, userp);
    return written;
}
size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t total_size = size * nmemb;
    Response* response = static_cast<Response*>(userp);
    response->data.append(static_cast<char*>(contents), total_size);
    return total_size;
}
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
void create_channel(dpp::cluster& bot, const std::string& channel_name, const std::string& guild_id, const std::string& category_id) {
    dpp::channel channel = dpp::channel()
        .set_name(channel_name)
        .set_guild_id(guild_id);

    if (category_id != "0") {
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
        createWebhook(bot, odaid, "Dosya Yukleyici"); // Webhook oluştur
        });
}
void handle_channel_creation(dpp::cluster& bot, const std::string& channel_name, const std::string& guild_id, const std::string& category_id) {
    if (category_id == "0") {
        create_category(bot, "Yuklemeler", guild_id, [&bot, channel_name, guild_id](const std::string& new_category_id) {
            create_channel(bot, channel_name, guild_id, new_category_id);
            });
    }
    else {
        create_channel(bot, channel_name, guild_id, category_id);
    }
}
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
void list_channels(dpp::cluster& bot, const std::string& guild_id, const std::string& category_id) {
    bot.channels_get(guild_id, [&bot, category_id](const dpp::confirmation_callback_t& callback) {
        if (callback.is_error()) {
            std::cerr << "Kanallar alınırken hata oluştu: " << callback.get_error().message << std::endl;
            return;
        }

        // Kanalları alınca callback.value içerisinden çekiyoruz
        auto channel_map = std::get<dpp::channel_map>(callback.value);

        // Belirtilen kategori ID'sindeki kanalları listeleyelim
        std::cout << "Kategori ID'sindeki kanallar:" << std::endl;
        for (const auto& [id, channel] : channel_map) {
            // Kategori ID'sini kontrol et (snowflake formatında)
            if (std::to_string(channel.parent_id) == category_id) {
                std::cout << "Kanal İsmi: " << channel.name << ", Kanal ID'si: " << id << std::endl;
            }
        }
        });
}
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
            std::cout << i + 1 + yerel_dosyalar.size() << ". " << extract_before_download_links(get_messages(bot, bulut_dosyalar[i], 1)) << std::endl;
            //cout << "Dosya Url: " << extract_discord_link(get_messages(bot, bulut_dosyalar[i], 1)) << endl;
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
                // Bulut dosyası seçildiğinde
                std::string selected_message_content = get_messages(bot, bulut_dosyalar[secim - 1 - yerel_dosyalar.size()], 1);
                std::string download_link = extract_discord_link(selected_message_content);
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
            break;
        }
        else {
            std::cout << "\033[1;31mGeçersiz seçim.\033[0m" << std::endl;
        }
    }
}
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
            url = url_bul(response.data);
            if (!url.empty()) {
                std::cout << "\033[1;34mBulunan URL: " << url << std::endl;
                if (silme == 1) {
                    std::ofstream dosya2(linkleridosyasi, std::ios::app);
                    dosya2 << std::to_string(parca_no) + " " + url << std::endl;
                    dosya2.close();
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
        if (trimWhitespaceAndSpecialChars(hash) == trimWhitespaceAndSpecialChars(getFileHash(dosya_yolu))) {
            while (std::getline(kontrol, son_satir)) {
                std::istringstream iss(son_satir);
                int parca_sayisi;
                std::string url;
                if (iss >> parca_sayisi >> url) {
                    mevcut_parca_sayisi = parca_sayisi;
                }
            }
            cout << "\033[1;31mAynı dosya tespit edildi kaldığı yerden devam ediyor." << endl;
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
        std::ofstream dosya2(linkler_txt, std::ios::app);
        dosya2 << toplam_parca << std::endl;
        dosya2 << dosya_yolu << std::endl;
        dosya2 << getFileHash(dosya_yolu) << endl;
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
    dosya_gonder(olusturulanwebhook, linkler_txt, parca_no, dosya_yolu + "'nin indirme linkleri", 0, linkler_txt);
    dpp::webhook wh(olusturulanwebhook);
    dpp::webhook whlog(webhook_log);
    bot.execute_webhook_sync(whlog, dpp::message(dosya_yolu + "'nin indirme linkleri: [Tikla](" + url + ")\nProgram linki: [Tikla](https://github.com/keremlolgg/DiscordStorage/releases/latest)"));
    bot.execute_webhook_sync(wh, dpp::message(dosya_yolu + "'nin indirme linkleri: [Tikla](" + url + ")\nProgram linki: [Tikla](https://github.com/keremlolgg/DiscordStorage/releases/latest)"));
}
void dosyalari_birlestir(const std::string& linkler_dosya_adi) {
    std::ifstream linkler_dosyasi(linkler_dosya_adi);
    if (!linkler_dosyasi) {
        std::cerr << "Linkler dosyası açılamadı: " << linkler_dosya_adi << std::endl;
        return;
    }

    int toplam_parca = 0;
    string hash;
    std::string satir;
    std::string hedef_dosya_adi;
    std::vector<std::pair<int, std::string>> linkler;

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
        std::cerr << "Hash okunamadı okunamadı!" << std::endl;
        return;
    }
    while (std::getline(linkler_dosyasi, satir)) {
        std::istringstream iss(satir);
        int parca_numarasi;
        std::string url;

        if (!(iss >> parca_numarasi >> url)) {
            std::cerr << "Satır okunurken hata: " << satir << std::endl;
            continue;
        }

        linkler.push_back({ parca_numarasi, url });
    }
    linkler_dosyasi.close();

    if (linkler.size() != toplam_parca) {
        std::cerr << "URL sayısı toplam parça sayısıyla uyuşmuyor!" << std::endl;
        return;
    }

    std::sort(linkler.begin(), linkler.end(), [](const std::pair<int, std::string>& a, const std::pair<int, std::string>& b) {
        return a.first < b.first;
        });

    std::ofstream hedef_dosya(hedef_dosya_adi, std::ios::binary);
    if (!hedef_dosya) {
        std::cerr << "Hedef dosya açılamadı: " << hedef_dosya_adi << std::endl;
        return;
    }

    std::vector<std::future<void>> paralel_indirmeler;

    for (const auto& [parca_no, url] : linkler) {
        std::string parca_dosyasi_adi = "parca" + std::to_string(parca_no) + ".txt";

        paralel_indirmeler.push_back(std::async(std::launch::async, [url, parca_dosyasi_adi]() {
            dosya_indir(url, parca_dosyasi_adi);
            }));
    }

    for (auto& indirme : paralel_indirmeler) {
        indirme.get();
    }

    for (const auto& [parca_no, url] : linkler) {
        std::string parca_dosyasi_adi = "parca" + std::to_string(parca_no) + ".txt";
        std::ifstream parca_dosyasi(parca_dosyasi_adi, std::ios::binary);
        if (parca_dosyasi) {
            hedef_dosya << parca_dosyasi.rdbuf();
            parca_dosyasi.close();
            std::cout << parca_dosyasi_adi << " birleştirildi." << std::endl;
        }
        else {
            std::cerr << "Parça açılamadı: " << parca_dosyasi_adi << std::endl;
        }

        if (std::remove(parca_dosyasi_adi.c_str()) != 0) {
            std::cerr << "Parça dosyası silme hatası: " << parca_dosyasi_adi << std::endl;
        }
    }

    hedef_dosya.close();
    if (getFileHash(hedef_dosya_adi) != hash) {
        cout << "\033[1;31mOluşturulan dosya ile yüklenen dosya hashleri tutmuyor!" << endl;
    }
    else
        cout << "\033[1;31mOluşturulan dosya ile yüklenen dosya hashleri aynı!" << endl;
}

int main() {
    setlocale(LC_ALL, "Turkish");
    string secim = "";
    std::vector<dpp::snowflake> bulut_dosyalar;
    std::ifstream file("discord.json");
    if (file.is_open()) {
        file >> j;
        file.close();
    }
    else {
        j["webhook_log"] = "your log webhook url";
        j["BOT_TOKEN"] = "your token";
        j["guild_id"] = "your storage server";
        j["mbsinir"] = 23;
        j["category_id"] = "0";
        update_json_and_save();
        cout << "JSON dosyası bulunmadı, oluşturuldu: " << "discord.json" << std::endl;
    }
    dpp::cluster bot(j["BOT_TOKEN"], dpp::i_default_intents | dpp::i_message_content);
    webhook_log = j["webhook_log"]; guild_id = j["guild_id"]; mbsinir = j["mbsinir"]; category_id = j["category_id"];
    bot.on_ready([&bot](const dpp::ready_t& event) {
        bot.set_presence(dpp::presence(dpp::ps_online, dpp::at_game, "Dosya yukleyici aktif"));
        });
    std::thread bot_thread([&bot]() {
        bot.start(dpp::st_wait);
        });
    while (true) {
        cout << "\033[1;31mProgram Sahibi Kerem Kuyucu.\n";
        cout << "\033[1;34m-----------------------------------------------------------------------" << endl;
        cout << "\033[1;33mLütfen 'Yedekle', 'İndir' seçeneğini giriniz:" << endl;
        cout << "1. Yedekle" << endl;
        cout << "2. İndir" << endl;
        cin >> secim;
        cin.ignore();

        if (secim != "1" && secim != "2" && secim != "3") {
            cout << "\033[1;31mGeçersiz seçim. Lütfen 'Yedekle', 'İndir' seçeneğini giriniz.\033[0m" << endl;
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
                handle_channel_creation(bot, dosya_yolu, guild_id, category_id); // webhook oluşturuluyor
                std::this_thread::sleep_for(std::chrono::seconds(1));
                dosyayi_parcalara_bol_ve_gonder(dosya_yolu, bot);
                cout << "\033[1;33mLütfen " + dosya_yolu + "_linkleri.txt dosyasını saklayın. O linkler sayesinde dosyanızı tekrar indirebilirsiniz.\033[0m" << endl;
                cout << "\033[1;33mEğer silinmeyen parça varsa o yüklenmemiş olabilir lütfen o parçayı kontrol edin ve parçayı elle yükleyerek olması gereken yere ekleyin.\033[0m" << endl;
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
            }
            cout << "\033[1;31mDosya indirildi!" << endl;
        }
    }
    bot_thread.join();
    return 0;
}