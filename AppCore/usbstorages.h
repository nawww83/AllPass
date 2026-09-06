#ifndef USBSTORAGES_H
#define USBSTORAGES_H

#include <QMainWindow>
#include <QStorageInfo>
#include <QListWidget>
#include <QLabel>
#include <QPushButton>
#include <QList>
#include <QTextBrowser>

class UsbStorages : public QMainWindow
{
    Q_OBJECT
public:
    UsbStorages(const QString& pin, QWidget *parent = nullptr);
    UsbStorages(const QString& pin, const QString& token_name, const QByteArray& data, QWidget *parent = nullptr);
    ~UsbStorages();

    QByteArray tryToReadKey();

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
    QString m_pinCode;
    const QString m_tokenName;
    QByteArray m_data;

    QString m_hardwareSerial;
    QString m_vid;
    QString m_pid;

    void fill_usb_info(const QStorageInfo& storage);
};

#endif // USBSTORAGES_H
