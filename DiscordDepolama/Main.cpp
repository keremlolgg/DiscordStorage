﻿#include <iostream>
#include <fstream>
#include <future>
#include <cstdlib>
#include <cstdio>
#include <memory>
#include <array>
#include <filesystem>
#include <CURL/curl/curl.h>
#include <nlohmann/json.hpp>
using namespace std;
int mbsinir=23;
using json = nlohmann::json;
struct Response {
    std::string data;
};
vector<string> dosya_listesi(const std::string& yol) {
    vector<string> dosyalar;
    for (const auto& entry : std::filesystem::directory_iterator(yol)) {
        if (entry.is_regular_file()) {
            dosyalar.push_back(entry.path().filename().string());
        }
    }
    return dosyalar;
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

void dosya_sec(const vector<string>& dosyalar, std::string& secilen_dosya) {
    cout << "\033[1;33mMevcut dosyalar:\033[0m" << endl;
    for (size_t i = 0; i < dosyalar.size(); ++i) {
        cout << i + 1 << ". " << dosyalar[i] << endl;
    }
    cout << "\033[1;33mLütfen seçiminizi yapınız (numara giriniz):\033[0m" << endl;
    int secim;
    cin >> secim;
    if (secim > 0 && secim <= static_cast<int>(dosyalar.size())) {
        secilen_dosya = dosyalar[secim - 1];
    }
    else {
        cout << "\033[1;31mGeçersiz seçim.\033[0m" << endl;
    }
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
void dosya_gonder(const std::string& webhook_url, const std::string& dosya_yolu, const int& parca_no, const std::string& mesaj, const int& silme,const string& linkleridosyasi) {
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

            if(silme){
                if (std::remove(dosya_yolu.c_str()) != 0) {
                    std::cerr << "Dosya silme hatasi: " << dosya_yolu << std::endl;
                }
            }
            std::ofstream dosya2("gonderimlog.txt", std::ios::app);
            dosya2 << "Webhook Yanıtı: "<<response.data << std::endl;
            dosya2.close();
            string url = url_bul(response.data);
            if (!url.empty()) {
                std::cout << "\033[1;34mBulunan URL: " << url << std::endl;
                if(silme==1){
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

void dosyayi_parcalara_bol_ve_gonder(const std::string& dosya_yolu, const std::string& webhook_url, size_t parca_boyutu = mbsinir * 1024 * 1024) {
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
        getline(kontrol,hash);
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
    } else {
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
        dosya_gonder(webhook_url, parca_dosyasi_adi, parca_no, mesaj, 1,linkler_txt);
        parca_no++;
    }

    delete[] buffer;
    dosya.close();
    dosya_gonder(webhook_url, linkler_txt, parca_no, dosya_yolu + "'nin indirme linkleri\nProgram linki: https://github.com/keremlolgg/DiscordStorage/releases/latest", 0,linkler_txt);
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
}

int main() {
    setlocale(LC_ALL, "Turkish");
    string webhook_url;
    string dosya_yolu;
    string secim, secim2;
    string secilen_dosya;
    cout << "\033[1;31mProgram Sahibi Kerem Kuyucu.\n";
    std::ifstream file("discord.json");
    json j;
    if (file.is_open()) {
        file >> j;
        file.close();
    }
    else {
        j["url"] = "https://discord.com/api/webhooks/example";
        j["mbsinir"] = 23;
        std::ofstream outFile("discord.json");
        outFile << j.dump(4);
        outFile.close();
        std::cout << "JSON dosyası bulunmadı, oluşturuldu: " << "discord.json" << std::endl;
    }
    webhook_url = j["url"];
    mbsinir = j["mbsinir"];
    do {
        cout << "\033[1;34m-----------------------------------------------------------------------" << endl;
        cout << "\033[1;33mLütfen 'Yedekle' veya 'İndir' seçeneğini giriniz:" << endl;
        cout << "1. Yedekle" << endl;
        cout << "2. İndir" << endl;
        cin >> secim;
        cin.ignore();
        if (secim != "1" && secim != "2") {
            cout << "\033[1;31mGeçersiz seçim. Lütfen 'Yedekle' veya 'İndir' seçeneğini giriniz.\033[0m" << endl;
        }
        if (secim == "1") {
            string dosya_yolu;
            cout << "\033[1;33mLütfen yüklemek istediğiniz dosyayı seçiniz.\033[0m" << endl;
            vector<string> dosyalar = dosya_listesi(".");
            dosya_sec(dosyalar, dosya_yolu);
            if (!dosya_yolu.empty()) {
                dosyayi_parcalara_bol_ve_gonder(dosya_yolu, webhook_url);
                cout << "\033[1;33mLütfen " + dosya_yolu + "_linkleri.txt dosyasını saklayın. O linkler sayesinde dosyanızı tekrar indirebilirsiniz.\033[0m";
            }
            cin >> secim;
        }
        else if (secim == "2") {
            cout << "\033[1;33mLütfen " + dosya_yolu + "_linkleri.txt dosyasını secin.\033[0m";
            string dosya_yolu;
            vector<string> dosyalar = dosya_listesi(".");
            dosya_sec(dosyalar, dosya_yolu);

            if (!dosya_yolu.empty()) {
                dosyalari_birlestir(dosya_yolu);
            }
            cout << "\033[1;31mDosya indirildi!" << endl;
            cin >> secim;
        }
    } while (secim != "1" || secim != "2");

    return 0;
}
