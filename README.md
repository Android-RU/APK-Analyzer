# 📦 APK Analyzer — анализатор .apk-файлов на Python

`APK Analyzer` — это удобный Python-скрипт для быстрого анализа Android `.apk` файлов. Он извлекает и отображает важную информацию: package name, версии SDK, разрешения, активности и другую полезную информацию.

---

## 🔧 Возможности

- Извлечение **package name**, **versionCode**, **versionName**
- Определение **minSdkVersion** и **targetSdkVersion**
- Получение списка **permissions** и **activities**
- Поиск **main activity**
- Подсчёт **размера .apk файла**
- Сохранение результата в **.json** или **.txt**

---

## 🚀 Установка

Перед запуском установите необходимые зависимости:

```bash
pip install androguard
```

---

## 🖥️ Пример запуска

```bash
python apk_analyzer.py path/to/app.apk
```

Пример вывода:
```
APK Analyzer — Analysis of app.apk

Package Name    : com.example.myapp
Version Name    : 1.0.1
Version Code    : 5
Min SDK Version : 21
Target SDK      : 30
APK Size        : 7.62 MB

Permissions:
 - android.permission.INTERNET
 - android.permission.CAMERA

Activities:
 - com.example.MainActivity
 - com.example.SettingsActivity

Main Activity: com.example.MainActivity
```

---

## ⚙️ Аргументы командной строки

| Флаг               | Описание                                                  |
|--------------------|-----------------------------------------------------------|
| `apk`              | Путь к `.apk` файлу (обязательный аргумент)               |
| `--output`, `-o`   | Сохранить результат в указанный файл                      |
| `--json`           | Сохранять результат в формате JSON                        |

---

### 💾 Примеры с аргументами

Сохранить результат в текстовый файл:

```bash
python apk_analyzer.py app.apk --output result.txt
```

Сохранить в JSON:

```bash
python apk_analyzer.py app.apk --json --output result.json
```

---

## 📁 Структура проекта

```
.
├── apk_analyzer.py    # Основной скрипт анализа
└── README.md          # Этот файл
```

---

## 📝 Лицензия

Этот проект лицензирован под лицензией **MIT**. См. файл `LICENSE` для подробностей.

---

## 🤝 Контакты

Если у вас есть вопросы, предложения или баги — создайте issue или pull request. Добро пожаловать в развитие проекта!
