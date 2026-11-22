<div align="center" dir="rtl">

# رخش

**تونل از سرور ایران به سرورهای خارج؛ ساخت، پایش و کلاستر از یک پنل وب.**

کاربران به IP عمومی سرور ایران وصل می‌شوند و ترافیکشان از راه GRE+FRP، Backhaul، Xray، باقر (SSH) یا اسپوف (WireGuard) به سرویس‌های سرور خارج می‌رسد؛ با بررسی سلامت، تعویض حامل، کلاستر و جابه‌جایی خودکار DNS.

</div>

<div dir="rtl">

## نصب سریع

روی **هر** سرور (ایران یا خارج) این را اجرا کنید:

</div>

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/mehdinemani33-boop/rakhsh/main/install.sh)
```

<div dir="rtl">

۱. **سرور ایران:** گزینه‌ی `1`.
۲. **سرور خارج:** گزینه‌ی `2`.
۳. پنل با آدرسی که آخر نصب چاپ می‌شود باز می‌شود (`http://<ip>:7777/<secret>`).

آدرس را گم کردید؟ `rakhsh show-panel-url`. رمز تازه؟ `rakhsh reset-password`.

## موتورهای تونل

| موتور | از چه راهی | رایگان/Pro |
| --- | --- | --- |
| **GRE + FRP** | FRP روی GRE (tcp، kcp، quic، websocket، wss) | رایگان |
| **Xray** | VLESS با Reality، XHTTP، gRPC، mKCP، CDN | Pro |
| **Backhaul** | ترنسپورت‌های tcp، tcpmux، ws، wss، udp | Pro |
| **باقر** | FRP/پورت‌فوروارد داخل SSH (autossh) | Pro |
| **اسپوف** | WireGuard با کلید خودکار از توکن مشترک | Pro |

## امکانات

- **تونل دوطرفه با باندل:** روی ایران تونل بساز، باندل `rkh1_…` را روی سرور خارج بچسبان.
- **کلاستر:** چند سرور خارج پشت یک پورت ایران با بالانسر سلامت‌آگاه (failover، balance، sticky، کمترین تأخیر، کمترین اتصال).
- **جابه‌جایی خودکار DNS (Cloudflare):** دامنه همیشه فقط به هاب‌های ایرانِ سالم اشاره می‌کند؛ هاب مُرده با دیبانس Fall/Rise ظرف چند ثانیه از دامنه برداشته و پس از برگشت دوباره اضافه می‌شود.
- **تعویض حامل و Autopilot:** تونل قطع، تست مسیر می‌شود و به بهترین حاملِ سالم می‌رود.
- **نودها:** افزودن سرور با یک کد، نقشه و هارت‌بیت زنده (CPU/RAM/دیسک/ترافیک).
- **عیب‌یابی:** دسترسی‌پذیری (تفکیک پورت‌فیلتر از IP‌فیلتر)، مسیر هاپ، تست پایداری، تست پورت‌ها.
- **مشتری‌ها:** فروش تونل با پلن روز/حجم/سرعت و قطع خودکار با پایان پلن.
- **امنیت و نگهداری:** رمز argon2id، CSRF، ۲ مرحله‌ای (TOTP)، بکاپ رمزنگاری AES-256، آپدیت قابل‌برگشت با SHA-256، واچ‌داگ، TLS.

## خط فرمان

| دستور | کار |
| --- | --- |
| `rakhsh run` | اجرای پنل |
| `rakhsh setup --role iran\|foreign` | راه‌اندازی اولیه |
| `rakhsh status` · `rakhsh doctor` | وضعیت و سلامت تونل‌ها |
| `rakhsh bundle make <id>` | چاپ باندل یک تونل |
| `rakhsh carrier next <id>` · `rakhsh autopilot on\|off` | تعویض حامل، Autopilot |
| `rakhsh node-join <code>` | پیوستن به پنل مرکزی |
| `rakhsh show-panel-url` · `rakhsh reset-password` | آدرس پنل، رمز تازه |

## نیازمندی‌ها

- لینوکس با systemd، معماری amd64 یا arm64، دسترسی root. نصاب بسته‌های لازم را خودش نصب می‌کند.
- پورت `7777` برای پنل، و پورت کنترلی که برای تونل انتخاب می‌کنید باز باشد.

## ساخت از سورس

```bash
git clone https://github.com/mehdinemani33-boop/rakhsh && cd rakhsh
CGO_ENABLED=0 go build -o rakhsh ./cmd/rakhsh
```

</div>
