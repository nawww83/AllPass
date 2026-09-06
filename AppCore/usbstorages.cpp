#include "usbstorages.h"
#include "collatz_cipher.h"
#include "utils.h"

#include <QDir>
#include <QElapsedTimer>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QMessageBox>
#include <QStorageInfo>
#include <QVBoxLayout>
#include <qevent.h>

#if defined(Q_OS_WIN)
#include <windows.h>
#include <comdef.h>
#include <WbemIdl.h>
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#elif defined(Q_OS_LINUX) || defined(Q_OS_MAC)
#include <QProcess>
#endif

#include <QByteArray>
#include <QPasswordDigestor>

// Метод генерации 256-битного мастер-ключа на основе ПИН-кода и железа USB
QString makePinTokenMasterKey(const QString &vid,
                              const QString &pid,
                              const QString &serial,
                              const QString &pinCode)
{
    // 1. Формируем уникальную криптографическую соль из железа флешки
    QString saltStr = QString("%1|%2|%3")
                          .arg(vid.trimmed().toUpper(), pid.trimmed().toUpper(), serial.trimmed());

    QByteArray salt = saltStr.toUtf8();
    QByteArray pin = pinCode.toUtf8();

    // 2. Запускаем PBKDF2 (500 000 итераций)
    // Функция вернет абсолютно уникальный 32-байтный (256 бит) массив
    QByteArray derivedKey
        = QPasswordDigestor::deriveKeyPbkdf2(QCryptographicHash::Sha256,
                                             pin,
                                             salt,
                                             500000, // Количество раундов замедления
                                             32      // Размер итогового ключа в байтах (256 бит)
                                             );

    // Переводим в hex-строку, чтобы передать в наш CollatzCipher256
    return QString::fromUtf8(derivedKey.toHex());
}


#if defined(Q_OS_LINUX)

struct UsbDeviceDetails
{
    QString serial;
    QString vid;
    QString pid;
    QString modelDescription;
};

UsbDeviceDetails getUsbDetails(const QString &rootPath)
{
    UsbDeviceDetails details;

    // 1. Берем имя устройства напрямую из Qt (замена findmnt)
    QStorageInfo storage(rootPath);
    if (!storage.isValid() || !storage.isReady())
        return details;

    QString devicePath = storage.device(); // Получаем, например, "/dev/sdb1"
    if (!devicePath.startsWith("/dev/"))
        return details;

    // 2. Ваша родная и проверенная логика очистки имени (sdb1 -> sdb)
    QString devName = devicePath.mid(5);
    while (!devName.isEmpty() && devName.back().isDigit()) {
        devName.chop(1);
    }

    // 3. Вызываем udevadm для очищенного имени диска
    QProcess udevadm;
    udevadm.start("udevadm", QStringList() << "info" << "--query=property" << "--name=" + devName);

    if (udevadm.waitForFinished()) {
        QString output = QString::fromUtf8(udevadm.readAllStandardOutput());
        QStringList lines = output.split('\n');
        QString rawVidHex, rawPidHex;
        QString vendorName, modelName;
        for (const QString &line : std::as_const(lines)) {
            if (line.startsWith("ID_SERIAL_SHORT=")) {
                details.serial = line.mid(16).trimmed();
            }
            // Читаем текстовое имя бренда (как VEN_ в Windows)
            else if (line.startsWith("ID_VENDOR=")) {
                vendorName = line.mid(10).trimmed();
            }
            // Читаем текстовое имя модели (как PROD_ в Windows)
            else if (line.startsWith("ID_MODEL=")) {
                modelName = line.mid(9).trimmed();
            }
            // Параллельно сохраняем HEX-коды на случай, если текста не будет
            else if (line.startsWith("ID_VENDOR_ID=")) {
                rawVidHex = line.mid(13).trimmed().toUpper();
            } else if (line.startsWith("ID_MODEL_ID=")) {
                rawPidHex = line.mid(12).trimmed().toUpper();
            }
        }
        // Полная синхронизация с Windows:
        if (!vendorName.isEmpty()) {
            details.vid = vendorName.toUpper();
        } else if (!rawVidHex.isEmpty()) {
            details.vid = rawVidHex; // Если текста нет, пишем hex-код производителя
        }

        if (!modelName.isEmpty()) {
            details.pid = modelName.toUpper();
        } else if (!rawPidHex.isEmpty()) {
            details.pid = rawPidHex; // Если текста нет, пишем hex-код модели
        }
    }

    return details;
}

#endif


void UsbStorages::fill_usb_info(const QStorageInfo& storage)
{
    const auto& root_path = storage.rootPath();
    m_hardwareSerial.clear();
    m_vid.clear();
    m_pid.clear();
#if defined(Q_OS_WIN)
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
#elif defined(Q_OS_LINUX)
    auto usb_details = getUsbDetails(root_path);
    m_hardwareSerial = usb_details.serial;
    m_vid = usb_details.vid;
    m_pid = usb_details.pid;

#elif defined(Q_OS_MAC)
    return; // Не реализовано, потому что не на чем тестировать.
#endif
}

static QString read_token(const QString& root_path)
{
    QDir usbDir(root_path);

    // 1. Фильтруем поиск только по файлам *.enc в корне диска
    QStringList filters;
    filters << "*.enc";
    usbDir.setNameFilters(filters);
    usbDir.setFilter(QDir::Files | QDir::NoDotAndDotDot);

    QFileInfoList fileList = usbDir.entryInfoList();
    if (fileList.isEmpty()) {
        return QString();
    }

    // Берем первый подходящий файл
    QString filePath = fileList.first().absoluteFilePath();

    QFile file(filePath);
    QString base64Text;
    // 2. Считываем данные через QTextStream
    if (file.open(QFile::ReadOnly | QFile::Text)) { // Флаг QFile::Text важен для корректного перевода строк (\r\n)
        QTextStream stream(&file);
        // Читаем всё содержимое текстового файла в виде QString
        base64Text = stream.readAll();
        file.close();
    } else {
        return QString();
    }
    return base64Text;
}

#if defined(Q_OS_WIN)
#include <dbt.h> // Необходим для макросов работы с устройствами

UsbStorages::UsbStorages(const QString &pin, QWidget *parent)
    : m_pinCode{pin},
    QMainWindow(parent)
{
}

UsbStorages::UsbStorages(const QString &pin, const QString &token_name, const QByteArray &data, QWidget *parent)
    : m_pinCode{pin},
    m_tokenName{token_name},
    m_data{data},
    QMainWindow(parent)
{
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
    utils::erase_string(m_pinCode);
    utils::erase_string(m_hardwareSerial);
    utils::erase_bytes(m_data);
}

QByteArray UsbStorages::tryToReadKey()
{
    auto allDrives = QStorageInfo::mountedVolumes();

    for (const QStorageInfo &storage : std::as_const( allDrives )) {
        if (!storage.isValid() || !storage.isReady())
            continue;

        bool isRemovable = false;

#if defined(Q_OS_WIN)
        UINT driveType = GetDriveTypeW(reinterpret_cast<LPCWSTR>(storage.rootPath().utf16()));
        if (driveType == DRIVE_REMOVABLE) {
            isRemovable = true;
        }
#elif defined(Q_OS_LINUX)
        if (storage.rootPath().startsWith("/media") || storage.rootPath().startsWith("/run/media")) {
            isRemovable = true;
        }
#elif defined(Q_OS_MAC)
        if (storage.rootPath().startsWith("/Volumes") && storage.rootPath() != "/Volumes/Macintosh HD") {
            isRemovable = true;
        }
#else
        if (storage.isReadOnly()) {
            isRemovable = true;
        }
#endif

        if (isRemovable) {
            m_rootPath = storage.rootPath();
            fill_usb_info(storage);
            QString usb_key = read_token(m_rootPath);
            QString strongMasterKey = makePinTokenMasterKey(m_vid, m_pid, m_hardwareSerial, m_pinCode);
            QByteArray data = CollatzCipher256::decrypt(usb_key, strongMasterKey);
            utils::erase_string(strongMasterKey);
            utils::erase_string(usb_key);

            constexpr size_t single_hash_size = sizeof(lfsr_hash::u128); // 16 байт
            constexpr size_t hashes_total_size = 3 * single_hash_size;   // 48 байт
            constexpr size_t crc_size = 32;                              // 32 байта (SHA-256)
            constexpr size_t expected_total_size = hashes_total_size + crc_size; // 80 байт

            // 2. ВАЛИДАЦИЯ КОНТРОЛЬНОЙ СУММЫ (CRC)
            // Вырезаем первые 48 байт хэшей
            QByteArray data_part = data.left(hashes_total_size);
            // Вырезаем последние 32 байта сохраненного CRC
            QByteArray saved_crc = data.right(crc_size);

            // Вычисляем SHA-256 от прочитанных хэшей
            QByteArray calculated_crc = QCryptographicHash::hash(data_part, QCryptographicHash::Sha256);

            // Сверяем контрольные суммы
            if (saved_crc != calculated_crc) {
                utils::erase_bytes(data_part);
                utils::erase_bytes(saved_crc);
                utils::erase_bytes(calculated_crc);
                continue;
            }

            // Выжигаем временные проверочные массивы из ОЗУ
            utils::erase_bytes(saved_crc);
            utils::erase_bytes(calculated_crc);
            return data_part;
        }
    } // loop
    return QByteArray();
}

void UsbStorages::saveKey()
{
    m_save_keyButton->setEnabled(false);
    // Заставляем Qt немедленно перерисовать кнопку на экране.
    qApp->processEvents(QEventLoop::ExcludeUserInputEvents); // [Qt]

    // Генерируем 256-битный мастер-ключ через PBKDF2
    QString strongMasterKey = makePinTokenMasterKey(m_vid, m_pid, m_hardwareSerial, m_pinCode);
    QString usb_key = CollatzCipher256::encrypt(m_data, strongMasterKey);
    utils::erase_string(strongMasterKey);

    QString fullPath = QDir::cleanPath(m_rootPath + QDir::separator() + m_tokenName);
    QFile file(fullPath);
    if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QTextStream out(&file);
        out << usb_key;
        file.close();
        QMessageBox::information(this,
                             tr("Успех"),
                             tr("Крипто-токен записан."));
    } else {
        QMessageBox::warning(this,
                             tr("Ошибка файла"),
                             tr("Крипто-токен не может быть записан на носитель."));
    }
    utils::erase_string(usb_key);
    m_save_keyButton->setEnabled(true);
}

void UsbStorages::refreshDrives()
{
    m_driveListWidget->clear();
    m_drives.clear();
    m_serialLabel->setHtml("<span style='color: #7f8c8d;'>Выберите диск из списка выше...</span>");

    auto allDrives = QStorageInfo::mountedVolumes();

    for (const QStorageInfo &storage : std::as_const( allDrives )) {
        if (!storage.isValid() || !storage.isReady())
            continue;

        bool isRemovable = false;

#if defined(Q_OS_WIN)
        UINT driveType = GetDriveTypeW(reinterpret_cast<LPCWSTR>(storage.rootPath().utf16()));
        if (driveType == DRIVE_REMOVABLE) {
            isRemovable = true;
        }
#elif defined(Q_OS_LINUX)
        if (storage.rootPath().startsWith("/media") || storage.rootPath().startsWith("/run/media")) {
            isRemovable = true;
        }
#elif defined(Q_OS_MAC)
        if (storage.rootPath().startsWith("/Volumes") && storage.rootPath() != "/Volumes/Macintosh HD") {
            isRemovable = true;
        }
#else
        if (storage.isReadOnly()) {
            isRemovable = true;
        }
#endif

        if (isRemovable) {
            m_drives.append(storage);

            QString displayName = storage.name().isEmpty() ? "Физический диск" : storage.name();

            // Передаем все три аргумента в один вызов .arg() через запятую
            QString itemText = QString("%1 (%2) [%3]")
                                   .arg(displayName, storage.rootPath(), QString::fromUtf8(storage.fileSystemType()));


            m_driveListWidget->addItem(itemText);
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
    if (index < 0 || index >= m_drives.size()) return;

    const QStorageInfo &storage = m_drives.at(index);
    m_rootPath = storage.rootPath(); // Например, "E:/"

    fill_usb_info(storage);

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

    m_serialLabel->setHtml(resultText);
}


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

void UsbStorages::closeEvent(QCloseEvent *event)
{
    // Испускаем сигнал для QEventLoop, сообщая, что код в лямбде может продолжать работу
    emit sig_finished();
    event->accept(); // Разрешаем закрытие окна
}
#endif