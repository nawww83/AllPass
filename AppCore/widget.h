#ifndef WIDGET_H
#define WIDGET_H

#include <QAction>
#include <QClipboard>
#include <QDialog>
#include <QDialogButtonBox>
#include <QEvent>
#include <QFontMetrics>
#include <QFutureWatcher>
#include <QHBoxLayout>
#include <QKeyEvent>
#include <QLineEdit>
#include <QMimeData>
#include <QPushButton>
#include <QRegularExpression>
#include <QRegularExpressionValidator>
#include <QTableWidget>
#include <QTextEdit>
#include <QVBoxLayout>
#include <QWidget>

#include <algorithm>
#include <vector>

#include "global_data.h"
#include "utils.h"

QT_BEGIN_NAMESPACE
namespace Ui {
class Widget;
}
QT_END_NAMESPACE

class Widget : public QWidget
{
    Q_OBJECT

public:
    Widget(QWidget *parent = nullptr);
    ~Widget();

    bool eventFilter(QObject *object, QEvent *event) override;

    void closeEvent(QCloseEvent* event) override;

private slots:
    void on_btn_generate_clicked();

    void on_spbx_pass_len_valueChanged(int arg1);

    void on_spbx_pass_len_editingFinished();

    void btn_recover_from_backup_clicked();

    void btn_new_storage_with_transfer_clicked();

    void btn_create_usb_key_clicked();

    void btn_clear_table_clicked();

    void tableWidget_customContextMenuRequested(const QPoint &pos);

    void tableWidget_itemChanged(QTableWidgetItem *item);

    void finish_password_generator();

    void input_master_phrase();

    void update_master_phrase();

    void set_master_key();

    void finish_master_key();

    void discard_master_key();

    void insert_new_password();

    void copy_to_clipboard();

    void delete_row();

    void update_pass();

    void show_pass_date();

    bool save_to_store();

    void load_storage();

    void update_number_of_rows();

    void update_table_info();

    void highlight_items();

signals:
    void master_phrase_ready();

    void master_phrase_discarded();

    void passwords_ready();

    void master_key_set();

    void row_deleted();

    void row_inserted();

    void table_changed();

protected:

private:
    Ui::Widget *ui;
    QFutureWatcher<lfsr_rng::Generators> watcher_seed_pass_gen;
    QFutureWatcher<lfsr_rng::Generators> watcher_seed_enc_gen;
    QFutureWatcher<lfsr_rng::Generators> watcher_seed_dec_gen;
    QFutureWatcher<lfsr_rng::Generators> watcher_seed_enc_inner_gen;
    QFutureWatcher<lfsr_rng::Generators> watcher_seed_dec_inner_gen;
    QFutureWatcher<QVector<lfsr8::u64>> watcher_passwords;
    QAction *copyAct;
    QAction *removeAct;
    QAction *updatePassAct;
    QAction *showPassDateAct;
    QPushButton *btn_recover_from_backup;
    QPushButton *btn_create_usb_key;
    QPushButton *btn_new_storage_with_transfer;
    QPushButton *btn_clear_table;

    QMetaObject::Connection m_masterPhraseConn;
    QMetaObject::Connection m_tempConn;

    bool is_modified = false;
};

class SecureTextEdit : public QTextEdit
{
    Q_OBJECT
public:
    explicit SecureTextEdit(QWidget *parent = nullptr)
        : QTextEdit(parent)
    {
        // 1. Запрещаем Drag-and-Drop, чтобы текст нельзя было «утащить» мышкой
        setAcceptDrops(false);

        // 2. Отключаем контекстное меню (копирование, вырезание, Undo/Redo)
        setContextMenuPolicy(Qt::NoContextMenu);

        // 3. Отключаем историю отмены на уровне документа Qt
        document()->setUndoRedoEnabled(false);

        // 4. Защита от систем доступности (Accessibility API / экранные дикторы)
        setAccessibleName(QString());
        setAccessibleDescription(QString());

        // Отключаем стандартный double-click, который пытается выделить слово
        // (выделять маскированные звездочки пользователю не нужно)
        setReadOnly(false);
    }

    ~SecureTextEdit() override
    {
        // Принудительно выжигаем память при уничтожении виджета
        if (!m_secureBuffer.empty()) {
            std::fill(m_secureBuffer.begin(), m_secureBuffer.end(), L'\0');
        }
    }

    // Возвращает мастер-фразу в UTF-8 (для хэширования)
    QByteArray getSecureData() const
    {
        if (m_secureBuffer.empty())
            return QByteArray();

        // Преобразуем накопленный wchar_t (UTF-16/32) в QString, а затем в UTF-8 байты
        QString str = QString::fromWCharArray(m_secureBuffer.data(),
                                              static_cast<int>(m_secureBuffer.size()));
        QByteArray bytes = str.toUtf8();

        // Немедленно выжигаем временную QString в памяти
        // (метод utils::erase_string должен принудительно занулять внутренний буфер)
        utils::erase_string(str);

        return bytes;
    }

    // Безопасное и гарантированное зануление памяти
    void secureClear()
    {
        // Блокируем сигналы, чтобы не провоцировать лишние перерисовки
        blockSignals(true);

        // 1. Выжигаем скрытый буфер в RAM нулями
        if (!m_secureBuffer.empty()) {
            std::fill(m_secureBuffer.begin(), m_secureBuffer.end(), L'\0');
            m_secureBuffer.clear();
        }

        // 2. Выжигаем визуальный буфер QTextEdit
        // Сначала заполняем мусором той же длины, затем очищаем
        int len = document()->toPlainText().length();
        if (len > 0) {
            QString junk(len, 'X');
            setPlainText(junk);
            utils::erase_string(junk);
        }
        clear();

        blockSignals(false);
    }

    bool is_closing() const { return mIsClosing; }

signals:
    void sig_closing();

protected:
    std::vector<wchar_t> m_secureBuffer; // Безопасное хранилище Unicode-символов
    bool mIsClosing = false;

    virtual void closeEvent(QCloseEvent *event) override final
    {
        mIsClosing = true;
        emit sig_closing();
        QTextEdit::closeEvent(event);
        mIsClosing = false;
    }

    // Перехватываем ввод с клавиатуры до того, как Qt отобразит его на экране
    virtual void keyPressEvent(QKeyEvent *event) override
    {
        // Разрешаем навигацию стрелками, но блокируем выделение через Shift
        if (event->modifiers() & Qt::ShiftModifier) {
            if (event->key() == Qt::Key_Left || event->key() == Qt::Key_Right
                || event->key() == Qt::Key_Up || event->key() == Qt::Key_Down
                || event->key() == Qt::Key_Home || event->key() == Qt::Key_End) {
                event->ignore();
                return;
            }
        }

        // Обработка Backspace (удаление символа)
        if (event->key() == Qt::Key_Backspace) {
            if (!m_secureBuffer.empty()) {
                m_secureBuffer.pop_back();
                // Синхронизируем отображение: удаляем одну звездочку на экране
                QTextEdit::keyPressEvent(event);
            }
            return;
        }

        // Перевод строки (Enter / Return) — отображаем как есть для структуры
        if (event->key() == Qt::Key_Return || event->key() == Qt::Key_Enter) {
            m_secureBuffer.push_back(L'\n');
            QTextEdit::keyPressEvent(event);
            return;
        }

        // Горячие клавиши: полностью блокируем Ctrl+C / Ctrl+X / Ctrl+Z / Ctrl+Y
        if (event->modifiers() & Qt::ControlModifier) {
            if (event->key() == Qt::Key_C || event->key() == Qt::Key_X || event->key() == Qt::Key_Z
                || event->key() == Qt::Key_Y) {
                event->ignore();
                return;
            }
            // Разрешаем Ctrl+V (Вставка), но обрабатываем её безопасно (см. ниже insertFromMimeData)
            if (event->key() == Qt::Key_V) {
                QTextEdit::keyPressEvent(event);
                return;
            }
        }

        // Обработка ввода обычного печатного Unicode-символа
        QString text = event->text();
        if (!text.isEmpty()) {
            wchar_t ch = text.at(0).unicode();

            // Игнорируем управляющие символы системных клавиш
            if (ch >= 32 || ch == L'\t') {
                m_secureBuffer.push_back(ch);

                // Вместо реального символа подсовываем Qt маскирующую звездочку
                QKeyEvent fakeEvent(event->type(), Qt::Key_Asterisk, event->modifiers(), "*");
                QTextEdit::keyPressEvent(&fakeEvent);

                utils::erase_string(text);
                return;
            }
        }

        // Все остальные служебные клавиши (Home, End, стрелки без Shift) обрабатываем штатно
        QTextEdit::keyPressEvent(event);
    }

    // Безопасный перехват вставки (Paste) из буфера обмена
    virtual void insertFromMimeData(const QMimeData *source) override
    {
        if (source->hasText()) {
            QString pastedText = source->text();
            if (pastedText.isEmpty())
                return;

            QString maskedText;
            maskedText.reserve(pastedText.length());

            // Разбираем вставленный Unicode-текст посимвольно
            for (int i = 0; i < pastedText.length(); ++i) {
                wchar_t ch = pastedText.at(i).unicode();
                m_secureBuffer.push_back(ch);

                // Сохраняем структуру переноса строк, остальное маскируем
                if (ch == L'\n' || ch == L'\r') {
                    maskedText.append(pastedText.at(i));
                } else {
                    maskedText.append('*');
                }
            }

            // Вставляем в видимое поле только звездочки
            insertPlainText(maskedText);

            // Немедленно очищаем буферную переменную из памяти
            utils::erase_string(pastedText);
        }
    }
};

template<int pin_len>
class MyDialog : public QDialog
{
public:
    MyDialog(const QString &title = QString::fromUtf8("Введите PIN-код"), QWidget *parent = nullptr)
        : QDialog(parent)
    {
        static_assert(pin_len > 0, "PIN length must be greater than 0");

        setWindowTitle(title);
        this->setStyleSheet("QDialog { background-color: #F8F9FA; }");

        QVBoxLayout *mainLayout = new QVBoxLayout(this);
        mainLayout->setContentsMargins(24, 24, 24, 24);
        mainLayout->setSpacing(20);

        QHBoxLayout *pinLayout = new QHBoxLayout();
        pinLayout->setSpacing(8);

        QRegularExpression rgx(R"(^[0-9]$)");
        QRegularExpressionValidator *digitValidator = new QRegularExpressionValidator(rgx, this);

        pin_fields.reserve(pin_len);

        QString lineEditStyle = "QLineEdit {"
                                "    border: 2px solid #D0D5DD;"
                                "    border-radius: 8px;"
                                "    background-color: #FFFFFF;"
                                "    color: #1D2939;"
                                "    font-size: 18px;"
                                "    font-weight: bold;"
                                "}"
                                "QLineEdit:focus {"
                                "    border: 2px solid #7F56D9;"
                                "    background-color: #F9F5FF;"
                                "}"
                                "QLineEdit:disabled {"
                                "    background-color: #F2F4F7;"
                                "    border-color: #EAECF0;"
                                "}";

        for (int i = 0; i < pin_len; ++i) {
            QLineEdit *le = new QLineEdit(this);
            le->setEchoMode(QLineEdit::Password);
            le->setValidator(digitValidator);
            le->setAlignment(Qt::AlignCenter);
            le->setMaxLength(1);
            le->setFixedSize(40, 48);
            le->setStyleSheet(lineEditStyle);

            // Отключаем контекстное меню, чтобы ПИН-код
            // нельзя было скопировать или вызвать стандартные действия Undo/Redo мыщью
            le->setContextMenuPolicy(Qt::NoContextMenu);
            le->installEventFilter(this);

            // Валидация кнопки OK теперь проверяет isEmpty() полей напрямую,
            // не считывая текст в кучу и не размножая копии ПИН-кода в RAM.
            connect(le, &QLineEdit::textChanged, this, [this, i](const QString &text) {
                updateOkButtonState();
                if (!text.isEmpty() && i < pin_len - 1) {
                    pin_fields[i + 1]->setFocus();
                    pin_fields[i + 1]->selectAll();
                }
            });

            pinLayout->addWidget(le);
            pin_fields.push_back(le);
        }

        pinLayout->setAlignment(Qt::AlignCenter);
        mainLayout->addLayout(pinLayout);

        buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);

        buttonBox->setStyleSheet(
            "QPushButton {"
            "    padding: 6px 16px;"
            "    border-radius: 6px;"
            "    font-size: 14px;"
            "    font-weight: 500;"
            "}"
            "QPushButton[text='OK'] { background-color: #7F56D9; color: white; border: none; }"
            "QPushButton[text='OK']:hover { background-color: #6941C6; }"
            "QPushButton[text='OK']:disabled { background-color: #E4E7EC; color: #98A2B3; }"
            "QPushButton[text='Cancel'] { background-color: white; color: #344054; border: 1px "
            "solid #D0D5DD; }"
            "QPushButton[text='Cancel']:hover { background-color: #F9FAFB; }");

        connect(buttonBox, &QDialogButtonBox::accepted, this, &QDialog::accept);
        connect(buttonBox, &QDialogButtonBox::rejected, this, &QDialog::reject);

        mainLayout->addWidget(buttonBox);

        QFontMetrics fm(this->font());
        int titleWidth = fm.horizontalAdvance(title) + 100;
        if (titleWidth > this->sizeHint().width()) {
            this->setMinimumWidth(titleWidth);
        }

        updateOkButtonState();

        if (!pin_fields.empty()) {
            pin_fields[0]->setFocus();
        }
    }

    // Безопасное извлечение ПИН-кода (вызывается один раз при нажатии OK)
    PinCode get_secure_pin() const
    {
        PinCode secure_pin;

        for (size_t i = 0; i < pin_fields.size() && i < constants::pin_code_len; ++i) {
            QString text = pin_fields[i]->text();

            if (!text.isEmpty()) {
                secure_pin.mPinCode[i] = text[0].digitValue();
            } else {
                secure_pin.mPinCode[i] = -1;
            }

            utils::erase_string(text);
        }

        return secure_pin;
    }

    // Безопасное затирание визуальных полей
    void clear_pin()
    {
        for (auto *le : pin_fields) {
            // Принудительно забиваем внутренний буфер виджета нулями перед очисткой
            QString zeroStr("0");
            le->setText(zeroStr);
            le->clear();
            utils::erase_string(zeroStr);
        }
        if (!pin_fields.empty()) {
            pin_fields[0]->setFocus();
        }
        updateOkButtonState();
    }

protected:
    bool eventFilter(QObject *watched, QEvent *event) override
    {
        if (event->type() == QEvent::KeyPress) {
            QKeyEvent *keyEvent = static_cast<QKeyEvent *>(event);
            QLineEdit *currentLe = qobject_cast<QLineEdit *>(watched);

            if (currentLe && keyEvent->key() == Qt::Key_Backspace) {
                auto it = std::find(pin_fields.begin(), pin_fields.end(), currentLe);
                if (it != pin_fields.end()) {
                    int index = std::distance(pin_fields.begin(), it);

                    if (currentLe->text().isEmpty() && index > 0) {
                        pin_fields[index - 1]->setFocus();
                        pin_fields[index - 1]->clear();
                        return true;
                    }
                }
            }
        }
        return QDialog::eventFilter(watched, event);
    }

private:
    void updateOkButtonState()
    {
        if (QPushButton *okButton = buttonBox->button(QDialogButtonBox::Ok)) {
            bool allFilled = true;
            for (const auto *le : pin_fields) {
                if (le->text().isEmpty()) {
                    allFilled = false;
                    break;
                }
            }
            okButton->setEnabled(allFilled);
        }
    }

    std::vector<QLineEdit *> pin_fields;
    QDialogButtonBox *buttonBox = nullptr;
};

#endif // WIDGET_H
