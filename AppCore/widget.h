#ifndef WIDGET_H
#define WIDGET_H

#include <QAction>
#include <QCheckBox>
#include <QClipboard>
#include <QDialog>
#include <QDialogButtonBox>
#include <QEvent>
#include <QFontMetrics>
#include <QFutureWatcher>
#include <QHBoxLayout>
#include <QKeyEvent>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QRegularExpression>
#include <QRegularExpressionValidator>
#include <QTableWidget>
#include <QTimer>
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

    void update_master_phrase();

    // Показывает диалог ввода мастер-фразы. Пустой QByteArray — пользователь отменил.
    // repeat_only == true — повторный ввод для подтверждения нового хранилища.
    QByteArray ask_master_phrase(bool repeat_only = false);

    void set_master_key();

    void finish_master_key();

    void discard_master_key();

    void insert_new_password();

    void copy_to_clipboard();

    void delete_row();

    void update_pass();

    void show_pass();

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
    QFutureWatcher<std::shared_ptr<lfsr_rng::Generators>> watcher_seed_pass_gen;
    QFutureWatcher<std::shared_ptr<lfsr_rng::Generators>> watcher_seed_enc_gen;
    QFutureWatcher<std::shared_ptr<lfsr_rng::Generators>> watcher_seed_dec_gen;
    QFutureWatcher<std::shared_ptr<lfsr_rng::Generators>> watcher_seed_enc_inner_gen;
    QFutureWatcher<std::shared_ptr<lfsr_rng::Generators>> watcher_seed_dec_inner_gen;
    QFutureWatcher<QVector<lfsr8::u64>> watcher_passwords;
    QAction *copyAct;
    QAction *removeAct;
    QAction *updatePassAct;
    QAction *showPassAct;
    QAction *showPassDateAct;
    QPushButton *btn_recover_from_backup;
    QPushButton *btn_create_usb_key;
    QPushButton *btn_new_storage_with_transfer;
    QPushButton *btn_clear_table;

    bool is_modified = false;

    // Автоконвертация старой базы (v3.00/v3.01) в текущий формат.
    // Хэши исправленного формата считаются в момент ввода мастер-фразы,
    // пока её байты ещё находятся в памяти; сама конвертация выполняется
    // после успешной загрузки таблицы.
    bool mConversionPending = false;
    lfsr_hash::u128 mConversionEnc{0, 0};
    lfsr_hash::u128 mConversionInner{0, 0};
    bool mStorageConverted = false;
    // Имя, которое база должна носить в текущем формате (fixed). Пусто при
    // открытии по USB-токену: без мастер-фразы его не вычислить.
    QString mFixedStorageName;
    bool mStorageRenamed = false;
    // Текущая попытка открытия использует USB-токен (нужно для отката
    // на ввод мастер-фразы, если ключ устарел).
    bool mUsedUsbToken = false;

    void convert_legacy_storage();
    void migrate_storage_name();
};

// Однострочное поле мастер-фразы: ввод, курсор, выделение, вставка и IME
// обрабатываются штатным QLineEdit, поэтому Unicode (включая иероглифы и
// эмодзи) работает корректно. Копирование/вырезание запрещены, чтобы фраза
// не утекла в буфер обмена.
class PhraseLineEdit : public QLineEdit
{
public:
    explicit PhraseLineEdit(QWidget *parent = nullptr)
        : QLineEdit(parent)
    {
        setContextMenuPolicy(Qt::NoContextMenu);
        setDragEnabled(false);
        setAcceptDrops(false);
        setClearButtonEnabled(false);
        setMaxLength(4096);
    }

protected:
    void keyPressEvent(QKeyEvent *event) override
    {
        if (event->modifiers() & Qt::ControlModifier) {
            if (event->key() == Qt::Key_C || event->key() == Qt::Key_X) {
                event->ignore();
                return;
            }
        }
        QLineEdit::keyPressEvent(event);
    }
};

// Код текущей раскладки клавиатуры (например, "RU"/"EN") для диалога
// мастер-фразы. Пустая строка, если определить не удалось (не Windows).
QString current_keyboard_layout_code();

// Диалог ввода мастер-фразы.
// repeat_only == false — обычный ввод: фраза видна, есть переключатель «скрыть».
// repeat_only == true  — повторный ввод при создании нового хранилища.
class MasterPhraseDialog : public QDialog
{
    Q_OBJECT
public:
    explicit MasterPhraseDialog(bool repeat_only, QWidget *parent = nullptr)
        : QDialog(parent)
    {
        setWindowTitle(repeat_only ? tr("Подтверждение мастер-фразы")
                                   : tr("Ввод мастер-фразы"));
        setModal(true);

        auto *layout = new QVBoxLayout(this);

        auto *hint = new QLabel(
            repeat_only
                ? tr("Хранилище с такой фразой не найдено — будет создано новое.\n"
                     "Повторите мастер-фразу, чтобы исключить опечатку.")
                : tr("Мастер-фраза нигде не хранится: восстановить забытую фразу невозможно."),
            this);
        hint->setWordWrap(true);
        layout->addWidget(hint);

        m_edit = new PhraseLineEdit(this);
        m_edit->setPlaceholderText(repeat_only ? tr("Повторите мастер-фразу")
                                               : tr("Мастер-фраза"));
        layout->addWidget(m_edit);

        m_hide = new QCheckBox(tr("Скрыть фразу"), this);
        m_layout = new QLabel(this);
        m_layout->setStyleSheet(QStringLiteral("color: #667085;"));
        auto *options = new QHBoxLayout;
        options->addWidget(m_hide);
        options->addStretch();
        options->addWidget(m_layout);
        layout->addLayout(options);

        connect(m_hide, &QCheckBox::toggled, this, [this](bool hidden) {
            m_edit->setEchoMode(hidden ? QLineEdit::Password : QLineEdit::Normal);
            // Клик по галке забирает фокус у поля ввода. Возвращаем его,
            // чтобы можно было продолжать печатать фразу, не хватая мышь.
            m_edit->setFocus();
        });

        // Раскладку нельзя отследить событием Qt — опрашиваем её нечасто,
        // пока диалог открыт (переключение Alt+Shift/Win+Space видно сразу).
        auto *layout_timer = new QTimer(this);
        layout_timer->setInterval(200);
        connect(layout_timer, &QTimer::timeout, this, [this] { update_layout_label(); });
        layout_timer->start();
        update_layout_label();

        auto *buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
        layout->addWidget(buttons);
        connect(buttons, &QDialogButtonBox::accepted, this, &MasterPhraseDialog::on_accept);
        connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);

        m_edit->setFocus();
        resize(520, sizeHint().height());
    }

    // Возвращает фразу в UTF-8 и сразу очищает поле.
    QByteArray take_phrase()
    {
        const QByteArray bytes = m_edit->text().toUtf8();
        m_edit->clear();
        return bytes;
    }

private slots:
    void on_accept()
    {
        if (m_edit->text().isEmpty()) {
            QMessageBox::warning(this, tr("Мастер-фраза"),
                                 tr("Мастер-фраза не может быть пустой."));
            m_edit->setFocus();
            return;
        }
        accept();
    }

private:
    void update_layout_label()
    {
        const QString code = current_keyboard_layout_code();
        m_layout->setText(code.isEmpty() ? QString() : tr("Раскладка: %1").arg(code));
    }

    PhraseLineEdit *m_edit = nullptr;
    QCheckBox *m_hide = nullptr;
    QLabel *m_layout = nullptr;
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
