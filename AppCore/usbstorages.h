#ifndef USBSTORAGES_H
#define USBSTORAGES_H

#include <QMainWindow>
#include <QStorageInfo>
#include <QListWidget>
#include <QLabel>
#include <QPushButton>
#include <QList>
#include <QTextBrowser>
#include <QByteArray>
#include <QVector>

class UsbStorages : public QMainWindow
{
    Q_OBJECT
public:
    /**
     * @brief Конструктор на чтение токена.
     * @param pin
     * @param parent
     */
    UsbStorages(std::string_view pin, QWidget *parent = nullptr);

    /**
     * @brief Конструктор на запись токена.
     * @param pin
     * @param token_name
     * @param data
     * @param parent
     */
    UsbStorages(std::string_view pin,
                const QString &token_name,
                const QByteArray &data,
                QWidget *parent = nullptr);
    ~UsbStorages();

    /**
     * @brief Чтение ключей *.enc с usb-носителей (автовыбор носителя и файла в корне носителя).
     * @return Валидные (прошедшие CRC) ключи.
     */
    QVector<QByteArray> tryToReadKey();

signals:
    void sig_finished();

private slots:
    void saveKey();
    void refreshDrives();
    void onDriveSelected(int index);

protected:
#if defined(Q_OS_WIN)
    // Метод для перехвата системных сообщений Windows
    bool nativeEvent(const QByteArray &eventType, void *message, qintptr *result) override;
#endif
    void closeEvent(QCloseEvent *event) override;

private:
    QListWidget *m_driveListWidget;
    QTextBrowser *m_serialLabel;
    QPushButton *m_save_keyButton;
    QList<QStorageInfo> m_drives;

    QString m_rootPath;
    std::string_view m_pinCode;
    const QString m_tokenName;
    QByteArray m_data;

    QString m_hardwareSerial;
    QString m_vid;
    QString m_pid;

    void fill_usb_info(const QString &root_path);
};

#endif // USBSTORAGES_H
