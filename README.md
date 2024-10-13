# DiscordDepolama

DiscordDepolama, Discord'da bot tokeni sayesinde dosya depolamanızı sağlayan bir projedir. Bu proje, dosyalarınızı güvenli bir şekilde depolamak ve yönetmek için gereken tüm araçları içerir.

## Bilinen Sorun

Dosyayı yükledikten sonra linki alınıyor fakat link belli bir süre sonra geçersiz oluyor.

## Uyarı

Dosyayı yükledikten sonra odaya herhangi bir mesaj atmayın botun bulut depolaması bozuluyor.

## Özellikler

- Discord bot tokeni kullanarak güvenli dosya depolama.
- `.env` dosyası ile kolay yapılandırma.
- LibCurl ve Dpp kütüphaneleri ile geliştirilmiştir.

## Gereksinimler

- C++ derleyicisi (C++11 veya üstü)
- [LibCurl](https://curl.se/libcurl/)
- [DPP](https://dpp.dev/) kütüphanesi

## Kurulum

1. Projeyi klonlayın:

   ```bash
   git clone https://github.com/keremlolgg/DiscordStorage.git
   cd DiscordStorage
   ```

2. Gerekli kütüphaneleri yükleyin:

   LibCurl ve Dpp kütüphanelerini sisteminize yükleyin. Her iki kütüphanenin de kurulum adımlarını kendi resmi belgelerinden bulabilirsiniz.

3. `.env` isimli bir dosya oluşturun:

   Aşağıdaki içeriği `.env` dosyasına ekleyin:

   ```plaintext
   BOT_TOKEN=your_token
   category_id=0
   guild_id=your_storage_server
   mbsinir=23
   webhook_log=your_log_webhook_url
   ```

4. Projeyi derleyin:

   Projenizi Visual Studio veya tercih ettiğiniz bir C++ IDE ile derleyin.

5. Botunuzu başlatın:

   Derleme tamamlandıktan sonra, botunuzu başlatmak için çalıştırın.

## Kullanım

DiscordDepolama botu ile dosya yüklemek ve depolamak için botunuzu çalıştırdıktan sonra Discord sunucunuzda botunuza gerekli izinleri verin. İlgili komutları kullanarak dosyalarınızı depolamaya başlayabilirsiniz.

## Katkıda Bulunanlar

- [KeremLolg](https://github.com/keremlolgg) - Proje sahibi ve geliştirici

## Lisans

Bu proje [GPL Lisansı](LICENSE) altında lisanslanmıştır.

## İletişim

Herhangi bir sorun veya öneri için lütfen benimle iletişime geçin.
