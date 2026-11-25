# Spring Boot OAuth2 ile Sosyal Giriş

Google, LinkedIn, Twitter ve Facebook hesaplarıyla giriş yapmayı gösteren küçük bir Spring Boot örneği.
Giriş yapan kullanıcının bilgileri `/user` adresinden döner ve tek sayfalık arayüzde gösterilir.

> **Not:** Bu depo 2019 yılında eğitim/örnek amaçlı yazıldı ve artık güncellenmiyor. Bağımlılıkları eskidir ve
> bilinen güvenlik açıkları içerir; üretimde kullanmayın. Kullanılan `spring-security-oauth2-autoconfigure`
> kütüphanesi artık geliştirilmiyor; LinkedIn v1 ve Twitter OAuth 1.0a uç noktaları da değişmiş olabilir.

## İçerik

- `Oauth2Application.java`: uygulamanın giriş noktası ve oturumdaki kullanıcıyı dönen `/user` uç noktası.
- `conf/SecurityConf.java`: her sağlayıcı için bir OAuth2 istemci filtresi tanımlar
  (`/connect/google`, `/connect/linkedIn`, `/connect/twitter`, `/connect/facebook`); diğer adresler oturum ister.
- `application.yml`: port (9990) ve sağlayıcıların istemci, yetkilendirme ve kullanıcı bilgisi adresleri.
- `static/index.html`: giriş bağlantılarını, kullanıcı adını ve çıkış düğmesini gösteren AngularJS 1.4 + Bootstrap 4 sayfası.

## Teknolojiler

- Java 8, Spring Boot 2.1.6, Spring Security
- spring-security-oauth2-autoconfigure 2.0.1
- Arayüz: AngularJS 1.4, Bootstrap 4.3, jQuery 3.3 (CDN üzerinden)

## Çalıştırma

1. Kullanmak istediğiniz sağlayıcıların geliştirici konsolunda bir OAuth uygulaması oluşturun ve geri dönüş
   adresi olarak `http://localhost:9990/connect/<sağlayıcı>` adresini tanımlayın.
2. `src/main/resources/application.yml` içindeki `clientId` ve `clientSecret` alanları boştur; kendi
   değerlerinizi yazın. Gizli anahtarları depoya göndermeyin; tercihen ortam değişkeni ya da komut satırı
   argümanıyla verin (örneğin `--google.client.clientSecret=...`).
3. Uygulamayı başlatın ve http://localhost:9990 adresini açın:

```bash
mvn spring-boot:run
```
