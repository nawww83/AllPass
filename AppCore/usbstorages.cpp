#include "usbstorages.h"
#include "collatz_cipher.h"
#include "utils.h"

#include <QDir>
#include <QFileInfo>
#include <QMessageBox>
#include <QSplashScreen>
#include <QVBoxLayout>
#include <qapplication.h>
#include <qevent.h>

#if defined(Q_OS_WIN)
#include <windows.h>
#include <comdef.h>
#include <WbemIdl.h>
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#elif defined(Q_OS_LINUX)
#include <QProcess>
#endif

#include <QVector>
#include <QString>
#include <QPasswordDigestor>

// Метод генерации 256-битного мастер-ключа на основе пин-кода и железа USB
static QByteArray makePinTokenMasterKey(const QString &vid,
                                        const QString &pid,
                                        const QString &serial,
                                        const QByteArray &pinCode)
{
    // Формируем соль из железа флешки
    QString saltStr = QString("%1|%2|%3")
                          .arg(vid.trimmed().toUpper(), pid.trimmed().toUpper(), serial.trimmed());

    QByteArray salt = saltStr.toUtf8();

    // Функция вернет 32-байтный (256 бит) массив
    QByteArray derivedKey
        = QPasswordDigestor::deriveKeyPbkdf2(QCryptographicHash::Sha256,
                                             pinCode,
                                             salt,
                                             500000, // Количество раундов замедления
                                             32      // Размер итогового ключа в байтах (256 бит)
        );

    return derivedKey;
}

#if defined(Q_OS_LINUX)

struct UsbDeviceDetails
{
    QString serial;
    QString vid;
    QString pid;
    QString modelDescription;

    // Добавляем кастомный деструктор для структуры, чтобы она сама себя зачищала
    ~UsbDeviceDetails()
    {
        serial.detach();
        vid.detach();
        pid.detach();
        modelDescription.detach();
        utils::erase_string(serial);
        utils::erase_string(vid);
        utils::erase_string(pid);
        utils::erase_string(modelDescription);
    }

    // Явно разрешаем конструктор перемещения для безопасного возврата из функции
    UsbDeviceDetails() = default;
    UsbDeviceDetails(UsbDeviceDetails &&) = default;
    UsbDeviceDetails &operator=(UsbDeviceDetails &&) = default;
    // Запрещаем копирование, чтобы исключить бесконтрольное размножение соли в RAM
    UsbDeviceDetails(const UsbDeviceDetails &) = delete;
    UsbDeviceDetails &operator=(const UsbDeviceDetails &) = delete;
};

UsbDeviceDetails getUsbDetails(const QStorageInfo &storage)
{
    UsbDeviceDetails details;

    if (!storage.isValid() || !storage.isReady())
        return details;

    QString devicePath = storage.device(); // Например, "/dev/sdb1"
    if (!devicePath.startsWith("/dev/"))
        return details;

    // Логика очистки имени (sdb1 -> sdb)
    QString devName = devicePath.mid(5);
    while (!devName.isEmpty() && devName.back().isDigit()) {
        devName.chop(1);
    }

    QProcess udevadm;
    udevadm.start("udevadm", QStringList() << "info" << "--query=property" << "--name=" + devName);

    if (udevadm.waitForFinished()) {
        QString output = QString::fromUtf8(udevadm.readAllStandardOutput());
        QStringList lines = output.split('\n');

        // Временные переменные парсера
        QString rawVidHex, rawPidHex;
        QString vendorName, modelName;
        QString vendorDb, modelDb;

        for (const QString &line : std::as_const(lines)) {
            if (line.startsWith("ID_SERIAL_SHORT=")) {
                details.serial = line.mid(16).trimmed();
            }
            // Вытаскиваем текстовые имена из базы udev для полной синхронизации с Windows USBSTOR
            else if (line.startsWith("ID_VENDOR_FROM_DATABASE=")) {
                vendorDb = line.mid(24).trimmed();
            } else if (line.startsWith("ID_MODEL_FROM_DATABASE=")) {
                modelDb = line.mid(23).trimmed();
            } else if (line.startsWith("ID_VENDOR=")) {
                vendorName = line.mid(10).trimmed();
            } else if (line.startsWith("ID_MODEL=")) {
                modelName = line.mid(9).trimmed();
            } else if (line.startsWith("ID_VENDOR_ID=")) {
                rawVidHex = line.mid(13).trimmed();
            } else if (line.startsWith("ID_MODEL_ID=")) {
                rawPidHex = line.mid(12).trimmed();
            }
        }

        // --- КРОСС ПЛАТФОРМЕННЫЙ СИНХРОНИЗАТОР СОЛИ ---
        // Отдаем строгий приоритет текстовым именам, как это делает подсистема Windows
        if (!vendorDb.isEmpty())
            details.vid = vendorDb;
        else if (!vendorName.isEmpty())
            details.vid = vendorName;
        else
            details.vid = rawVidHex;

        if (!modelDb.isEmpty())
            details.pid = modelDb;
        else if (!modelName.isEmpty())
            details.pid = modelName;
        else
            details.pid = rawPidHex;

        details.vid = details.vid.toUpper();
        details.pid = details.pid.toUpper();

        // Принудительно изолируем возвращаемые строки в куче
        details.serial.detach();
        details.vid.detach();
        details.pid.detach();

        // --- КРИТИЧЕСКОЕ ВЫЖИГАНИЕ ПРОМЕЖУТОЧНОЙ ПАМЯТИ В RAM ---
        rawVidHex.detach();
        rawPidHex.detach();
        vendorName.detach();
        modelName.detach();
        vendorDb.detach();
        modelDb.detach();

        utils::erase_string(rawVidHex);
        utils::erase_string(rawPidHex);
        utils::erase_string(vendorName);
        utils::erase_string(modelName);
        utils::erase_string(vendorDb);
        utils::erase_string(modelDb);
    }

    return details; // Сработает NRVO/Move-возврат структуры
}

#endif

#if defined(Q_OS_WIN)
void UsbStorages::fill_usb_info(const QString& root_path)
{
    m_hardwareSerial.clear();
    m_vid.clear();
    m_pid.clear();
    QString driveLetter = root_path.left(2).toUpper(); // Например, "E:"
    // Инициализируем COM в режиме APARTMENTTHREADED (совместимом с главным потоком Qt)
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    // Переменная будет истинной, если COM успешно создана сейчас (S_OK) или уже была создана Qt ранее (S_FALSE)
    bool coInitialized = (hr == S_OK || hr == S_FALSE);

    if (coInitialized) {
        // Инициализируем безопасность. Если Qt уже сделал это — функция вернет ошибку,
        // но для локального WMI-опроса это не помешает, поэтому результат hr_sec мы не блокируем.
        CoInitializeSecurity(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT,
                             RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);

        IWbemLocator *pLoc = nullptr;
        hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID *)&pLoc);

        if (SUCCEEDED(hr)) {
            IWbemServices *pSvc = nullptr;
            BSTR bstrNetworkPath = SysAllocString(L"ROOT\\CIMV2");

            hr = pLoc->ConnectServer(bstrNetworkPath, nullptr, nullptr, nullptr, 0, nullptr, nullptr, &pSvc);

            if (SUCCEEDED(hr)) {
                hr = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                                       RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);

                if (SUCCEEDED(hr)) {
                    IEnumWbemClassObject* pEnumerator = nullptr;
                    BSTR bstrWQL = SysAllocString(L"WQL");
                    BSTR bstrQuery = SysAllocString(L"SELECT SerialNumber, PNPDeviceID, DeviceID FROM Win32_DiskDrive");

                    hr = pSvc->ExecQuery(bstrWQL, bstrQuery,
                                         WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &pEnumerator);

                    if (SUCCEEDED(hr)) {
                        IWbemClassObject *pclsObj = nullptr;
                        ULONG uReturn = 0;

                        while (SUCCEEDED(pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn)) && uReturn > 0) {
                            VARIANT vtDeviceID;
                            pclsObj->Get(L"DeviceID", 0, &vtDeviceID, 0, 0);
                            QString wmiDeviceId = QString::fromWCharArray(vtDeviceID.bstrVal);
                            VariantClear(&vtDeviceID);

                            // Получаем PHYSICALDRIVE номер для нашей буквы через WinAPI
                            QString volumePath = QString("\\\\.\\%1").arg(driveLetter);
                            HANDLE hVolume = CreateFileW(reinterpret_cast<LPCWSTR>(volumePath.utf16()),
                                                         0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                                         nullptr, OPEN_EXISTING, 0, nullptr);

                            bool isTargetDrive = false;
                            if (hVolume != INVALID_HANDLE_VALUE) {
                                STORAGE_DEVICE_NUMBER deviceNumber;
                                DWORD bytesReturned = 0;
                                if (DeviceIoControl(hVolume, IOCTL_STORAGE_GET_DEVICE_NUMBER,
                                                    nullptr, 0, &deviceNumber, sizeof(deviceNumber),
                                                    &bytesReturned, nullptr)) {
                                    QString targetExt = QString("PHYSICALDRIVE%1").arg(deviceNumber.DeviceNumber);
                                    if (wmiDeviceId.contains(targetExt, Qt::CaseInsensitive)) {
                                        isTargetDrive = true;
                                    }
                                }
                                CloseHandle(hVolume);
                            }

                            if (isTargetDrive) {
                                VARIANT vtProp;

                                // Читаем серийный номер железа
                                if (SUCCEEDED(pclsObj->Get(L"SerialNumber", 0, &vtProp, 0, 0)) && vtProp.vt == VT_BSTR) {
                                    m_hardwareSerial = QString::fromWCharArray(vtProp.bstrVal).trimmed();
                                }
                                VariantClear(&vtProp);

                                // Читаем VID и PID из строки PnP
                                if (SUCCEEDED(pclsObj->Get(L"PNPDeviceID", 0, &vtProp, 0, 0)) && vtProp.vt == VT_BSTR) {
                                    QString pnpId = QString::fromWCharArray(vtProp.bstrVal).toUpper();

                                    // Вариант 1: Строка содержит стандартный формат USB (например, USB\VID_0781&PID_5581)
                                    if (pnpId.contains("VID_")) {
                                        int vidIdx = pnpId.indexOf("VID_");
                                        if (vidIdx != -1) m_vid = pnpId.mid(vidIdx + 4, 4);
                                        int pidIdx = pnpId.indexOf("PID_");
                                        if (pidIdx != -1) m_pid = pnpId.mid(pidIdx + 4, 4);
                                    }
                                    // Вариант 2: Строка от накопителя USBSTOR (например, USBSTOR\DISK&VEN_SANDISK&PROD_CRUZER&REV_1.0\...)
                                    else if (pnpId.contains("VEN_") || pnpId.contains("PROD_")) {
                                        // Извлекаем VEN_ (Производитель) и PROD_ (Продукт)
                                        int venIdx = pnpId.indexOf("VEN_");
                                        int prodIdx = pnpId.indexOf("PROD_");
                                        int revIdx = pnpId.indexOf("&REV_");

                                        if (venIdx != -1 && prodIdx != -1) {
                                            // Вырезаем чистое имя производителя (оно ограничено знаком &)
                                            QString vendorName = pnpId.mid(venIdx + 4, prodIdx - (venIdx + 5));
                                            // Вырезаем чистое имя модели продукта
                                            QString productName = (revIdx != -1) ? pnpId.mid(prodIdx + 5, revIdx - (prodIdx + 5))
                                                                                 : pnpId.mid(prodIdx + 5).split('\\').first();

                                            // Поскольку USBSTOR заменяет шестнадцатеричные VID/PID на текстовые имена бренда,
                                            // выведем их в интерфейс вместо сырых HEX-чисел, чтобы пользователю было понятнее
                                            m_vid = vendorName.trimmed();
                                            m_pid = productName.trimmed();
                                        }
                                    }
                                }
                                VariantClear(&vtProp);

                                pclsObj->Release();
                                break;
                            }

                            pclsObj->Release();
                        }
                        pEnumerator->Release();
                    }
                    SysFreeString(bstrWQL);
                    SysFreeString(bstrQuery);
                }
                pSvc->Release();
            }
            SysFreeString(bstrNetworkPath);
            pLoc->Release();
        }

        // Деинициализацию вызываем только если мы сами успешно открыли COM-сессию (S_OK)
        if (hr == S_OK) {
            CoUninitialize();
        }
    }
}
#endif

/**
 * @brief Прямое чтение токенов с USB-носителя.
 * @param root_path Корень usb-токена.
 * @return Валидный вектор сырых байтовых массивов Base64.
 */
static QVector<QByteArray> read_tokens(const QString &root_path)
{
    QDir usbDir(root_path);
    QVector<QByteArray> tokens;

    // Фильтруем поиск только по файлам *.enc в корне диска
    QStringList filters{"*.enc"};
    usbDir.setNameFilters(filters);
    usbDir.setFilter(QDir::Files | QDir::NoDotAndDotDot);

    QFileInfoList fileList = usbDir.entryInfoList();
    if (fileList.isEmpty()) {
        return tokens;
    }

    for (const QFileInfo &file_info : std::as_const(fileList)) {
        QFile file(file_info.absoluteFilePath());

        // Открываем строго в бинарном режиме ReadOnly (без текстового перекодирования)
        if (file.open(QIODevice::ReadOnly)) {
            QByteArray base64Bytes = file.readAll();
            file.close();

            if (!base64Bytes.isEmpty()) {
                // Принудительно изолируем массив в куче, чтобы владение было монопольным
                base64Bytes.detach();

                // Добавляем токен в вектор
                tokens.append(base64Bytes);

                // Гарантированно выжигаем локальную переменную
                utils::erase_bytes(base64Bytes);
            }
        }
    }
    return tokens;
}

#if defined(Q_OS_WIN)
#include <dbt.h> // Необходим для макросов работы с устройствами
#endif

UsbStorages::UsbStorages(std::string_view pin, QWidget *parent)
    : QMainWindow(parent)
{
    m_pinBuffer = QByteArray(pin.data(), static_cast<int>(pin.length()));
}

UsbStorages::UsbStorages(std::string_view pin,
                         const QString &token_name,
                         const QByteArray &data,
                         QWidget *parent)
    : m_tokenName{token_name}
    , m_data{data}
    , QMainWindow(parent)
{
    m_pinBuffer = QByteArray(pin.data(), static_cast<int>(pin.length()));

    setWindowTitle("USB-накопители");
    resize(400, 500);

    auto *centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);

    auto *mainLayout = new QVBoxLayout(centralWidget);

    m_driveListWidget = new QListWidget(this);
    mainLayout->addWidget(new QLabel("Доступные съемные диски:", this));
    mainLayout->addWidget(m_driveListWidget);

    m_serialLabel = new QTextBrowser(this);
    m_serialLabel->setOpenLinks(false); // Отключаем переход по ссылкам, если они будут
    m_serialLabel->setReadOnly(true);    // Разрешаем выделение и копирование, но запрещаем ввод текста
    m_serialLabel->setUndoRedoEnabled(false);
    m_serialLabel->setStyleSheet(
        "font-family: 'Courier New', monospace;"
        "font-size: 13px;"
        "color: #2c3e50;"
        "background-color: #f8f9fa;"
        "border: 1px solid #e2e8f0;"
        "padding: 10px;"
        "border-radius: 4px;"
        );
    mainLayout->addWidget(m_serialLabel);

    m_save_keyButton = new QPushButton("Сохранить ключ", this);
    mainLayout->addWidget(m_save_keyButton);
    m_save_keyButton->setEnabled(false);

    // Сначала соединяем сигналы и слоты
    connect(m_save_keyButton, &QPushButton::clicked, this, &UsbStorages::saveKey);
    connect(m_driveListWidget, &QListWidget::currentRowChanged, this, &UsbStorages::onDriveSelected);

    // Блокируем сигналы виджета перед первичным сканированием,
    // чтобы currentRowChanged не вызвался до полной готовности конструктора
    m_driveListWidget->blockSignals(true);
    refreshDrives();
    m_driveListWidget->blockSignals(false);

    // Если диски были найдены, вручную выбираем первый элемент, чтобы обновить UI
    if (m_driveListWidget->count() > 0 && m_driveListWidget->isEnabled()) {
        m_driveListWidget->setCurrentRow(0);
        m_save_keyButton->setEnabled(true);
    }
}

UsbStorages::~UsbStorages()
{
    // 1. Принудительно изолируем конфиденциальные контейнеры перед выжиганием.
    // Это гарантирует, что erase_bytes/erase_string очистят монопольные буферы
    // и никогда не повредят общую память интерфейса Qt!
    m_data.detach();
    m_pinBuffer.detach();
    m_hardwareSerial.detach();
    m_vid.detach();
    m_pid.detach();

    // 2. Гарантированно уничтожаем ключевой материал и соль PBKDF2 нулями по точному .size()
    utils::erase_bytes(m_data);
    utils::erase_bytes(m_pinBuffer);
    utils::erase_string(m_hardwareSerial);
    utils::erase_string(m_vid);
    utils::erase_string(m_pid);
}

QVector<QByteArray> UsbStorages::tryToReadKey()
{
    auto allDrives = QStorageInfo::mountedVolumes();
    QVector<QByteArray> tokens;

    for (const QStorageInfo &storage : std::as_const(allDrives)) {
        if (!storage.isValid() || !storage.isReady())
            continue;

        bool isRemovable = false;
#if defined(Q_OS_WIN)
        if (GetDriveTypeW(reinterpret_cast<LPCWSTR>(storage.rootPath().utf16()))
            == DRIVE_REMOVABLE) {
            isRemovable = true;
        }
#elif defined(Q_OS_LINUX)
        if (storage.rootPath().startsWith("/media") || storage.rootPath().startsWith("/run/media")) {
            isRemovable = true;
        }
#endif
        if (isRemovable) {
            m_rootPath = storage.rootPath();
#if defined(Q_OS_LINUX)
            auto usb_details = getUsbDetails(storage);
            m_hardwareSerial = usb_details.serial;
            m_vid = usb_details.vid;
            m_pid = usb_details.pid;
#else
            fill_usb_info(m_rootPath);
#endif
            QVector<QByteArray> usb_keys = read_tokens(m_rootPath);
            QByteArray strongMasterKey = makePinTokenMasterKey(m_vid,
                                                               m_pid,
                                                               m_hardwareSerial,
                                                               m_pinBuffer);

            for (const QByteArray &usb_key_bytes : std::as_const(usb_keys)) {
                // 1. Явно создаем Unicode-строку для совместимости с сигнатурой decrypt
                QString usb_key_str = QString::fromUtf8(usb_key_bytes);

                // 2. Передаем её в шифратор
                QByteArray data = CollatzCipher256::decrypt(usb_key_str, strongMasterKey);

                // Очищаем временную строку secrets СРАЗУ же, как только получили данные.
                // Метод detach() гарантирует монопольность, а erase_string стирает её в RAM нулями.
                usb_key_str.detach();
                utils::erase_string(usb_key_str);

                // Ограничиваем максимальный размер токена для защиты от мусорных данных (1 МБ)
                if (data.isEmpty() || data.size() > 1024 * 1024) {
                    utils::erase_bytes(data);
                    continue;
                }

                constexpr size_t hashes_total_size = 3 * sizeof(lfsr_hash::u128); // 48 байт
                constexpr size_t crc_size = 32; // 32 байта (SHA-256)
                const int variable_data_size = data.size() - hashes_total_size - crc_size;

                if (variable_data_size <= 0) {
                    utils::erase_bytes(data);
                    continue;
                }

                // КРИТИЧЕСКАЯ ОПТИМИЗАЦИЯ КУЧИ: Разрываем связи и фиксируем парсер
                data.detach();

                // Проверяем SHA-256 напрямую по памяти оригинального буфера без выделения промежуточных массивов
                QByteArray calculated_crc
                    = QCryptographicHash::hash(QByteArray::fromRawData(data.constData(),
                                                                       hashes_total_size
                                                                           + variable_data_size),
                                               QCryptographicHash::Sha256);

                // Constant-Time сверка контрольной суммы (SHA-256)
                if (std::memcmp(data.constData() + data.size() - crc_size,
                                calculated_crc.constData(),
                                crc_size)
                    != 0) {
                    utils::erase_bytes(calculated_crc);
                    utils::erase_bytes(data);
                    continue;
                }

                utils::erase_bytes(calculated_crc);

                // Отрезаем публичный тег CRC с хвоста
                data.resize(hashes_total_size + variable_data_size);

                // Добавляем очищенный валидный токен в результирующий вектор
                tokens.append(data);
                utils::erase_bytes(data);
            }
            for (QByteArray &k : usb_keys) {
                utils::erase_bytes(k);
            }
            utils::erase_bytes(strongMasterKey);
        }
    }
    return tokens;
}

void UsbStorages::saveKey()
{
    m_save_keyButton->setEnabled(false);
    QSplashScreen *splash = new QSplashScreen();
    QFont splashFont;
    splashFont.setBold(true);
    splashFont.setPixelSize(18);
    splash->setFont(splashFont);
    splash->setWindowFlags(splash->windowFlags() | Qt::WindowStaysOnTopHint);
    splash->showMessage(QString::fromUtf8("Подождите..."), Qt::AlignCenter, Qt::blue);
    splash->show();
    qApp->processEvents(QEventLoop::ExcludeUserInputEvents);

    // 1. Генерируем 256-битный мастер-ключ через PBKDF2
    QByteArray strongMasterKey = makePinTokenMasterKey(m_vid, m_pid, m_hardwareSerial, m_pinBuffer);

    // Получаем зашифрованный токен Base64
    QString usb_key = CollatzCipher256::encrypt(m_data, strongMasterKey);

    // Незамедлительно уничтожаем PBKDF2 мастер-ключ системными нулями
    utils::erase_bytes(strongMasterKey);

    splash->close();
    splash->deleteLater();

    // Преобразуем строку токена в чистый однобайтовый ASCII-массив для записи на диск
    QByteArray usb_key_bytes = usb_key.toUtf8();

    // КРИТИЧЕСКАЯ ОЧИСТКА: Нам больше не нужна Unicode-строка в куче, выжигаем её на месте
    usb_key.detach();
    utils::erase_string(usb_key);

    // 2. Запись на носитель в чистом бинарном режиме (без QTextStream)
    QString fullPath = QDir::cleanPath(m_rootPath + QDir::separator() + m_tokenName);
    QFile file(fullPath);

    // Открываем файл в строго бинарном режиме WriteOnly (без флага Text)
    if (file.open(QIODevice::WriteOnly)) {
        // Принудительно изолируем байты перед физической записью на сектор флешки
        usb_key_bytes.detach();

        file.write(usb_key_bytes);
        file.close();

        QMessageBox::information(this, tr("Успех"), tr("Крипто-токен записан."));
    } else {
        QMessageBox::warning(this,
                             tr("Ошибка файла"),
                             tr("Крипто-токен не может быть записан на носитель."));
    }

    // 3. Гарантированно выжигаем ASCII-копию токена в куче системными нулями
    utils::erase_bytes(usb_key_bytes);

    m_save_keyButton->setEnabled(true);
}

void UsbStorages::refreshDrives()
{
    m_driveListWidget->clear();
    m_drives.clear();
    m_serialLabel->setHtml("<span style='color: #7f8c8d;'>Выберите диск из списка выше...</span>");

    auto allDrives = QStorageInfo::mountedVolumes();

    for (const QStorageInfo &storage : std::as_const(allDrives)) {
        if (!storage.isValid() || !storage.isReady())
            continue;

        bool isRemovable = false;

#if defined(Q_OS_WIN)
        if (GetDriveTypeW(reinterpret_cast<LPCWSTR>(storage.rootPath().utf16()))
            == DRIVE_REMOVABLE) {
            isRemovable = true;
        }
#elif defined(Q_OS_LINUX)
        if (storage.rootPath().startsWith("/media") || storage.rootPath().startsWith("/run/media")) {
            isRemovable = true;
        }
#endif
        if (isRemovable) {
            m_drives.append(storage);

            QString displayName = storage.name().isEmpty() ? "Физический диск" : storage.name();

            // Вытаскиваем сырой тип файловой системы
            QByteArray fsTypeBytes = storage.fileSystemType();
            QString fsTypeStr = QString::fromUtf8(fsTypeBytes);
            QString rootPathStr = storage.rootPath();

            // Формируем текст элемента списка
            QString itemText = QString("%1 (%2) [%3]").arg(displayName, rootPathStr, fsTypeStr);

            // Принудительно разрываем связи строки перед добавлением в UI виджет
            itemText.detach();
            m_driveListWidget->addItem(itemText);

            // --- ГАРАНТИРОВАННОЕ ВЫЖИГАНИЕ ВРЕМЕННЫХ СТРОК ИЗ КУЧИ ---
            fsTypeStr.detach();
            rootPathStr.detach();
            itemText.detach();

            utils::erase_bytes(fsTypeBytes);
            utils::erase_string(fsTypeStr);
            utils::erase_string(rootPathStr);
            utils::erase_string(itemText);
        }
    }

    if (m_drives.isEmpty()) {
        m_driveListWidget->addItem("Съемные диски не найдены");
        m_driveListWidget->setEnabled(false);
    } else {
        m_driveListWidget->setEnabled(true);
    }
}

void UsbStorages::onDriveSelected(int index)
{
    if (index < 0 || index >= m_drives.size())
        return;

    const QStorageInfo &storage = m_drives.at(index);
    m_rootPath = storage.rootPath(); // Например, "E:/"

    // Сразу принудительно изолируем пути перед обновлением данных
    m_rootPath.detach();

#if defined(Q_OS_LINUX)
    // Ограничиваем область видимости структуры usb_details
    {
        auto usb_details = getUsbDetails(storage);

        // Перезаписываем поля класса
        m_hardwareSerial = usb_details.serial;
        m_vid = usb_details.vid;
        m_pid = usb_details.pid;
    }
#else
    fill_usb_info(m_rootPath);
#endif

    // КРИТИЧЕСКИЙ БАРЬЕР: Намертво изолируем новые данные соли флешки в куче.
    // Теперь поля класса владеют памятью монопольно, и повторные клики/деструктор
    // никогда не спровоцируют конфликты аллокатора или Invalid Pointer!
    m_hardwareSerial.detach();
    m_vid.detach();
    m_pid.detach();

    // Формируем красивый HTML-блок с CSS-стилями и визуальными разделителями
    QString resultText
        = QString(
              "<div style='line-height: 1.5;'>"
              "  <div style='margin-bottom: 8px;'>"
              "    <span style='color: #7f8c8d; font-weight: bold;'>📝 Аппаратный SN:</span><br>"
              "    <span style='color: #2c3e50; font-size: 14px; font-weight: bold; font-family: "
              "monospace;'>%1</span>"
              "  </div>"
              "  <hr style='border: 0; border-top: 1px dashed #dcdde1; margin: 8px 0;'>"
              "  <div style='display: flex; justify-content: space-between;'>"
              "    <div style='width: 48%; float: left;'>"
              "      <span style='color: #7f8c8d; font-weight: bold;'>🏭 Vendor ID "
              "(VID):</span><br>"
              "      <span style='color: #2980b9; font-size: 14px; font-weight: bold; font-family: "
              "monospace;'>%2</span>"
              "    </div>"
              "    <div style='width: 48%; float: right;'>"
              "      <span style='color: #7f8c8d; font-weight: bold;'>📦 Product ID "
              "(PID):</span><br>"
              "      <span style='color: #27ae60; font-size: 14px; font-weight: bold; font-family: "
              "monospace;'>%3</span>"
              "    </div>"
              "  </div>"
              "  <div style='clear: both;'></div>"
              "</div>")
              .arg(m_hardwareSerial, m_vid, m_pid); // Передаем исправленные строки отображения

    // Принудительно отвязываем сформированный HTML от внутренних буферов QString перед выводом
    resultText.detach();
    m_serialLabel->setHtml(resultText);

    // ГАРАНТИРОВАННОЕ ВЫЖИГАНИЕ: Полностью уничтожаем текстовый шаблон соли в RAM системными нулями
    utils::erase_string(resultText);
}

#if defined(Q_OS_WIN)
bool UsbStorages::nativeEvent(const QByteArray &eventType, void *message, qintptr *result)
{
    Q_UNUSED(eventType);
    Q_UNUSED(result);

    MSG *msg = static_cast<MSG *>(message);

    // WM_DEVICECHANGE сообщает об изменении в составе оборудования
    if (msg->message == WM_DEVICECHANGE) {
        // DBT_DEVICEARRIVAL - устройство вставлено
        // DBT_DEVICEREMOVECOMPLETE - устройство извлечено
        if (msg->wParam == DBT_DEVICEARRIVAL || msg->wParam == DBT_DEVICEREMOVECOMPLETE) {
            // Запускаем обновление списка флешек автоматически
            refreshDrives();
        }
    }

    return false; // Возвращаем false, чтобы Qt тоже мог обработать это событие, если нужно
}
#endif

void UsbStorages::closeEvent(QCloseEvent *event)
{
    // Испускаем сигнал для QEventLoop, сообщая, что код в лямбде может продолжать работу
    emit sig_finished();
    event->accept(); // Разрешаем закрытие окна
}
