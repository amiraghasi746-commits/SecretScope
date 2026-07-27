# 🔐 SecretScope

**A pure-Python, dependency-light secret & credential leak scanner for source code repositories** — with optional AI-powered risk analysis via the Claude API.

[![CI](https://github.com/YOUR_USERNAME/secretscope/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_USERNAME/secretscope/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-blue)
![License](https://img.shields.io/badge/license-MIT-green)

---

## English

### What it does

SecretScope walks a file or an entire directory tree and flags likely leaked secrets using two complementary techniques:

1. **Signature matching** — regex rules for well-known secret formats: AWS keys, GitHub tokens (classic & fine-grained), Slack tokens/webhooks, Google API keys, Anthropic/OpenAI/Groq API keys, Stripe keys, JWTs, private key blocks, database connection strings, and generic `key = "..."` style assignments.
2. **Shannon entropy analysis** — catches high-randomness strings (16+ characters) that look like secrets even when they don't match a known format, a common way to catch custom or unusual token formats.

It's built to slot straight into a CI/CD pipeline as a pre-merge or pre-deploy gate, or to run locally before you `git push`.

### Features

- ✅ Zero required dependencies — pure Python standard library
- ✅ Recursive directory scanning with sensible default ignores (`.git`, `node_modules`, `venv`, build artifacts, binaries, etc.)
- ✅ Three severity levels (HIGH / MEDIUM / LOW)
- ✅ Three output formats: colored console output, JSON, and a styled standalone HTML report
- ✅ `--fail-on-findings` flag for CI pipelines (non-zero exit code on detections)
- ✅ Optional AI-powered risk summary using the **Anthropic Claude API** (`--ai` flag)
- ✅ Full unit test suite, GitHub Actions CI across Python 3.9–3.12

### Installation

```bash
git clone https://github.com/YOUR_USERNAME/secretscope.git
cd secretscope
pip install -r requirements.txt
pip install -e .
```

### Usage

```bash
# Scan a directory, print colored results to console
secretscope /path/to/your/repo

# Scan a single file, write an HTML report
secretscope config.py --output html --output-file report.html

# JSON output, useful for feeding into other tooling
secretscope . --output json --output-file findings.json

# CI mode: exit code 1 if anything is found
secretscope . --fail-on-findings

# Disable entropy checks, use signature rules only (fewer false positives)
secretscope . --no-entropy

# Get a plain-language AI risk explanation (requires ANTHROPIC_API_KEY)
export ANTHROPIC_API_KEY="your-key-here"
secretscope . --ai
```

Or run it directly as a module without installing:

```bash
python -m secretscope.cli examples/vulnerable_sample.py
```

### Try the demo

The `examples/vulnerable_sample.py` file contains deliberately fake (non-functional) secrets covering every detection rule, so you can see SecretScope in action immediately:

```bash
python -m secretscope.cli examples/vulnerable_sample.py
```

### Project structure

```
secretscope/
├── secretscope/
│   ├── __init__.py
│   ├── scanner.py       # core scan engine (walks files, applies rules)
│   ├── patterns.py      # regex signatures for known secret formats
│   ├── entropy.py       # Shannon entropy calculation + token extraction
│   ├── reporter.py       # console / JSON / HTML report rendering
│   ├── ai_analyzer.py    # optional Claude API risk analysis
│   └── cli.py             # argparse-based command-line interface
├── tests/                  # unit tests (unittest, no external deps)
├── examples/
│   └── vulnerable_sample.py
├── .github/workflows/ci.yml
├── requirements.txt
├── setup.py
├── LICENSE (MIT)
└── .gitignore
```

### Running tests

```bash
python -m unittest discover -s tests -v
```

### Disclaimer

SecretScope is a heuristic scanner. It reduces risk but cannot guarantee zero false negatives or zero false positives — always pair it with proper secret management practices (environment variables, dedicated secret managers, key rotation policies) rather than relying on scanning alone.

---

## فارسی

### این پروژه چه کاری انجام می‌دهد

**SecretScope** یک اسکنر پایتون خالص (بدون وابستگی اجباری به کتابخانه خارجی) برای شناسایی کلیدها، توکن‌ها و اطلاعات محرمانه‌ی افشا شده در کد منبع است. این ابزار یک فایل یا کل یک پوشه را پیمایش می‌کند و با دو روش مکمل، موارد مشکوک را علامت‌گذاری می‌کند:

1. **تطبیق الگو (Signature Matching)** — قوانین regex برای فرمت‌های شناخته‌شده مانند کلیدهای AWS، توکن‌های گیت‌هاب، اسلک، گوگل، Anthropic، OpenAI، Groq، Stripe، JWT، بلوک‌های کلید خصوصی و رشته‌های اتصال پایگاه داده.
2. **تحلیل آنتروپی شانون (Shannon Entropy)** — رشته‌های با تصادفی‌بودن بالا را حتی زمانی که با هیچ الگوی شناخته‌شده‌ای مطابقت ندارند، شناسایی می‌کند.

این ابزار طوری طراحی شده که می‌توان آن را مستقیماً در پایپ‌لاین CI/CD قرار داد یا پیش از `git push` به‌صورت محلی اجرا کرد.

### امکانات

- ✅ بدون وابستگی اجباری — فقط با کتابخانه استاندارد پایتون کار می‌کند
- ✅ اسکن بازگشتی پوشه‌ها با نادیده‌گرفتن هوشمندانه‌ی موارد پیش‌فرض (`.git`، `node_modules`، `venv` و غیره)
- ✅ سه سطح شدت (HIGH / MEDIUM / LOW)
- ✅ سه قالب خروجی: کنسول رنگی، JSON و گزارش HTML مستقل و استایل‌دار
- ✅ گزینه‌ی `--fail-on-findings` برای استفاده در پایپ‌لاین‌های CI
- ✅ تحلیل ریسک هوش مصنوعی اختیاری با استفاده از **Claude API** (گزینه‌ی `--ai`)
- ✅ مجموعه تست کامل واحد و CI با GitHub Actions روی پایتون ۳.۹ تا ۳.۱۲

### نصب

```bash
git clone https://github.com/YOUR_USERNAME/secretscope.git
cd secretscope
pip install -r requirements.txt
pip install -e .
```

### نحوه استفاده

```bash
# اسکن یک پوشه و نمایش نتایج رنگی در کنسول
secretscope /path/to/your/repo

# اسکن یک فایل و تولید گزارش HTML
secretscope config.py --output html --output-file report.html

# خروجی JSON برای استفاده در ابزارهای دیگر
secretscope . --output json --output-file findings.json

# حالت CI: کد خروجی ۱ در صورت یافتن مورد مشکوک
secretscope . --fail-on-findings

# غیرفعال کردن بررسی آنتروپی، فقط استفاده از الگوهای شناخته‌شده
secretscope . --no-entropy

# دریافت توضیح ریسک به زبان ساده با هوش مصنوعی (نیازمند ANTHROPIC_API_KEY)
export ANTHROPIC_API_KEY="your-key-here"
secretscope . --ai
```

### اجرای دمو

فایل `examples/vulnerable_sample.py` حاوی کلیدهای جعلی (غیرفعال) برای تمام قوانین شناسایی است تا بلافاصله بتوانید عملکرد ابزار را ببینید:

```bash
python -m secretscope.cli examples/vulnerable_sample.py
```

### اجرای تست‌ها

```bash
python -m unittest discover -s tests -v
```

### سلب مسئولیت

SecretScope یک اسکنر اکتشافی (heuristic) است و کاهش‌دهنده‌ی ریسک محسوب می‌شود، نه یک راه‌حل قطعی. همیشه آن را همراه با روش‌های صحیح مدیریت اطلاعات محرمانه (متغیرهای محیطی، سرویس‌های مدیریت کلید اختصاصی، چرخش دوره‌ای کلیدها) به کار ببرید.

---

## License

MIT — see [LICENSE](LICENSE).
