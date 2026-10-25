# Иконка AllPass

## Концепция A — «Замок-сейф» (основная)

Навесной замок на тёмно-синем скруглённом квадрате. Замочная скважина не нарисована
поверх, а **вырезана до фона**, поэтому просвечивает градиентом и остаётся видимой
даже в маленьком размере.

- фон: диагональный градиент `#1E4E79` → `#0B2133`;
- замок: `#ECF6FF`, мягкая тень вниз, тонкий светлый кант по кромке плитки;
- метафора: и «пароли под замком», и «сейф/хранилище» — два смысла приложения сразу.

Почему так:

- силуэт замка читается в 16 px, где любые буквы и мелкие детали превращаются в кашу;
- вырезанная скважина даёт глубину без второго цвета и без бликов;
- тёмно-синяя гамма не конфликтует с синей подсветкой Windows и не выглядит как
  «ещё один зелёный щит» (KeePass) или «ещё одна синяя буква» (1Password).

Для мелких размеров геометрия пересобрана отдельно, а не просто уменьшена:

| Размер | Что отличается |
|--------|----------------|
| 16–20 px | вместо скважины — одна точка, дужка толще |
| 24–32 px | утолщённая дужка, увеличенная скважина |
| 40 px и выше | обычная геометрия |

## Варианты для сравнения

- **B. Щит** — `variant_b_shield_256.png`. Строже, но ближе к антивирусам, чем к
  менеджерам паролей.
- **C. Ключ** — `variant_c_key_256.png`. Прямее намекает на «ключи от всего» и на
  USB-ключ; хорош как монохромная иконка трея, но в 16 px прорезь ключа исчезает.

## Файлы

| Файл | Назначение |
|------|------------|
| `allpass.ico` | мультиразмерный ICO (16, 20, 24, 32, 40, 48, 64, 96, 128, 256) для `app.rc` |
| `allpass_<N>.png` | отдельные PNG, в том числе для `QIcon`/`QSplashScreen` |
| `allpass.svg` | векторный исходник (README, сайт, печать) |
| `preview.png` | сводное превью: варианты, реальные размеры, светлая и тёмная тема |
| `make_icon.py` | генератор всех файлов (Pillow), там же палитра и пропорции |

## Как подключить в приложение

Уже сделано:

1. `AppCore/app.rc` (только Windows) — иконка exe:

   ```rc
   IDI_ICON1   ICON   DISCARDABLE   "images/appicon/allpass.ico"
   ```

2. `AppCore/main.cpp` — иконка окна из qrc, по одному файлу на размер:

   ```cpp
   QIcon app_icon;
   for (int size : {16, 20, 24, 32, 40, 48, 64, 96, 128, 256}) {
       app_icon.addFile(QStringLiteral(":/images/appicon/allpass_%1.png").arg(size),
                        QSize(size, size));
   }
   QApplication::setWindowIcon(app_icon);
   ```

3. `CMakeLists.txt` — `.rc` подключается только под Windows (`APP_ICON_RC`),
   а под Linux ставится `.desktop` и иконки в hicolor-тему.

### Windows

Иконка exe вшивается ресурсом, смена видна после пересборки. Проводник кэширует
иконки: если осталась старая — переименовать exe/папку сборки или очистить кэш.

### Linux

`.rc` там не работает, зато работают два других механизма:

- **иконка окна (X11)** — из `setWindowIcon`, то есть из qrc; работает даже
  при запуске прямо из папки сборки;
- **панель задач, док, меню приложений** — только из `.desktop`-файла и
  иконки в hicolor-теме.

Поэтому в `main.cpp` под `#ifdef Q_OS_LINUX` дополнительно выставляются

```cpp
QGuiApplication::setDesktopFileName(QStringLiteral("allpass.desktop"));
```

и имя приложения (`WM_CLASS` = `AllPass`, совпадает с `StartupWMClass` в
`packaging/linux/allpass.desktop`). Это важно для Wayland: протокол не передаёт
иконку окна, композитор ищет её сам по `app_id` = имени desktop-файла.

Установка в домашний профиль:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
cmake --install build --prefix ~/.local
gtk-update-icon-cache -f -t ~/.local/share/icons/hicolor 2>/dev/null || true
update-desktop-database ~/.local/share/applications 2>/dev/null || true
```

Появятся `~/.local/bin/AllPass`, `~/.local/share/applications/allpass.desktop` и
`~/.local/share/icons/hicolor/{16x16,…,256x256,scalable}/apps/allpass.{png,svg}`.

Если запускать `AllPass` из папки сборки без установки, иконка будет только в
заголовке окна (X11) — в доке её не будет, потому что системе неоткуда взять
`.desktop`. Минимальный обходной путь — положить `allpass.desktop` в
`~/.local/share/applications` и PNG в
`~/.local/share/icons/hicolor/256x256/apps/allpass.png`, либо просто
`cmake --install`.


## Перегенерация

```powershell
python make_icon.py
```

Нужен только Pillow. Палитра и пропорции — константы `BG_TOP`, `BG_BOTTOM`, `P`,
`P_COMPACT` в начале скрипта.
