#include <iostream>
#include <fstream>
#include <future>
#include <CURL/curl/curl.h>
#include <nlohmann/json.hpp>
using namespace std;
int mbsinir=23;
using json = nlohmann::json;
struct Response {
    std::string data;
};
std::vector<std::string> url_listesi;
std::mutex url_listesi_mutex;
vector<string> dosya_listesi(const std::string& yol) {
    vector<string> dosyalar;
    for (const auto& entry : std::filesystem::directory_iterator(yol)) {
        if (entry.is_regular_file()) {
            dosyalar.push_back(entry.path().filename().string());
        }
    }
    return dosyalar;
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
size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t total_size = size * nmemb;
    Response* response = static_cast<Response*>(userp);
    response->data.append(static_cast<char*>(contents), total_size);
    return total_size;
}
size_t write_data(void* buf, size_t size, size_t nmemb, FILE* userp) {
    size_t written = fwrite(buf, size, nmemb, userp);
    return written;
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
void dosya_gonder(const std::string& webhook_url, const std::string& dosya_yolu, const int& parca_no, const std::string& mesaj, const int& silme) {
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
            std::string url = url_bul(response.data);
            if (!url.empty()) {
                std::cout << "\033[1;34mBulunan URL: " << url << std::endl;
                std::string url_entry = std::to_string(parca_no) + " " + url;
                url_listesi.push_back(url_entry);
            }
            else {
                std::cout << "URL bulunamadi." << std::endl;
            }
        }

        curl_mime_free(form);
        curl_easy_cleanup(curl);
    }

    curl_global_cleanup();
}

void dosyayi_parcalara_bol_ve_gonder(const std::string& dosya_yolu, const std::string& webhook_url, size_t parca_boyutu = mbsinir * 1024 * 1024) {
    std::ifstream dosya(dosya_yolu, std::ios::binary);
    if (!dosya) {
        std::cerr << "Dosya açılamadı: " << dosya_yolu << std::endl;
        return;
    }
    dosya.seekg(0, std::ios::end);
    size_t dosya_boyutu = dosya.tellg();
    dosya.seekg(0, std::ios::beg);

    int toplam_parca = static_cast<int>((dosya_boyutu + parca_boyutu - 1) / parca_boyutu);

    int parca_no = 1;
    char* buffer = new char[parca_boyutu];
    std::string linkler_txt = dosya_yolu + "_linkleri.txt";

    std::ofstream temizle_txt(linkler_txt, std::ios::trunc);
    if (!temizle_txt) {
        std::cerr << "linkleri.txt dosyası temizlenemedi: " << linkler_txt << std::endl;
    }
    temizle_txt.close();
    cout << "\033[1;31mToplam yuklenecek parca sayisi. " << toplam_parca << endl;
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
        dosya_gonder(webhook_url, parca_dosyasi_adi, parca_no, mesaj, 1);

        parca_no++;
    }

    std::ofstream dosya2(dosya_yolu + "_linkleri.txt", std::ios::app);
    dosya2 << parca_no - 1 << std::endl;
    dosya2 << dosya_yolu << std::endl;
    for (const auto& url : url_listesi) {
        dosya2 << url << std::endl;
    }
    dosya2.close();

    delete[] buffer;
    dosya.close();
    dosya_gonder(webhook_url, linkler_txt, parca_no, dosya_yolu + "'nin indirme linkleri\nProgram linki: https://github.com/keremlolgg/DiscordStorage/releases/latest", 0);
}
void dosyalari_birlestir(const std::string& linkler_dosya_adi) {
    std::ifstream linkler_dosyasi(linkler_dosya_adi);
    if (!linkler_dosyasi) {
        std::cerr << "Linkler dosyası açılamadı: " << linkler_dosya_adi << std::endl;
        return;
    }

    int toplam_parca = 0;
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