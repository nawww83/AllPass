#ifndef WIDGET_H
#define WIDGET_H

#include <QWidget>
#include <QTableWidget>
#include <QTextEdit>
#include <QFutureWatcher>
#include <QAction>
#include <QLineEdit>
#include <QVBoxLayout>
#include <QDialog>
#include <QDialogButtonBox>
#include <QPushButton>
#include <QFontMetrics>
#include <QRegularExpression>
#include <QRegularExpressionValidator>
#include <QHBoxLayout>
#include <QKeyEvent>
#include <QEvent>
#include <vector>

#include "stream_cipher.h"

QT_BEGIN_NAMESPACE
namespace Ui {
class Widget;
}
QT_END_NAMESPACE

class Widget : public QWidget
{
    Q_OBJECT

public:
    Widget(QString pin, QWidget *parent = nullptr);
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

class MyTextEdit : public QTextEdit
{
    Q_OBJECT
public:
    explicit MyTextEdit(QWidget *parent = nullptr) : QTextEdit(parent) {}

    bool is_closing() const {
        return mIsClosing;
    }

signals:
    void sig_closing();

protected:
    bool mIsClosing = false;
    virtual void closeEvent(QCloseEvent *event) override final
    {
        mIsClosing = true;
        emit sig_closing();
        QTextEdit::closeEvent(event);
        mIsClosing = false;
    }
};


template <int pin_len>
class MyDialog : public QDialog
{
public:
    MyDialog(const QString& title = QString::fromUtf8("Введите PIN-код"), QWidget *parent = nullptr)
        : QDialog(parent)
    {
        static_assert(pin_len > 0, "PIN length must be greater than 0");

        setWindowTitle(title);

        // Стилизуем само диалоговое окно (опционально)
        this->setStyleSheet("QDialog { background-color: #F8F9FA; }");

        QVBoxLayout *mainLayout = new QVBoxLayout(this);
        mainLayout->setContentsMargins(24, 24, 24, 24); // Отступы от краев окна
        mainLayout->setSpacing(20);

        QHBoxLayout *pinLayout = new QHBoxLayout();
        pinLayout->setSpacing(8); // Расстояние между ячейками

        QRegularExpression rgx(R"(^[0-9]$)");
        QRegularExpressionValidator *digitValidator = new QRegularExpressionValidator(rgx, this);

        pin_fields.reserve(pin_len);

        // CSS-стиль для ячеек ввода
        QString lineEditStyle =
            "QLineEdit {"
            "    border: 2px solid #D0D5DD;" // Серый бордюр в обычном состоянии
            "    border-radius: 8px;"        // Скругление углов
            "    background-color: #FFFFFF;" // Белый фон
            "    color: #1D2939;"            // Цвет символа
            "    font-size: 18px;"           // Крупный шрифт (точки пароля будут четкими)
            "    font-weight: bold;"
            "}"
            "QLineEdit:focus {"
            "    border: 2px solid #7F56D9;" // Фиолетовая подсветка при фокусе
            "    background-color: #F9F5FF;" // Едва заметный фоновый оттенок при фокусе
            "}"
            "QLineEdit:disabled {"
            "    background-color: #F2F4F7;" // Цвет, если поле заблокировано
            "    border-color: #EAECF0;"
            "}";

        for (int i = 0; i < pin_len; ++i) {
            QLineEdit *le = new QLineEdit(this);
            le->setEchoMode(QLineEdit::Password);
            le->setValidator(digitValidator);
            le->setAlignment(Qt::AlignCenter);
            le->setMaxLength(1);

            // Задаем комфортный размер ячейки (чуть больше, чтобы CSS смотрелся хорошо)
            le->setFixedSize(40, 48);

            // Применяем CSS-стиль к каждой ячейке
            le->setStyleSheet(lineEditStyle);

            le->installEventFilter(this);

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

        // Стилизуем кнопки Ok и Cancel, чтобы они соответствовали дизайну
        buttonBox->setStyleSheet(
            "QPushButton {"
            "    padding: 6px 16px;"
            "    border-radius: 6px;"
            "    font-size: 14px;"
            "    font-weight: 500;"
            "}"
            "QPushButton[text='OK'] {" // Стиль для кнопки подтверждения
            "    background-color: #7F56D9;"
            "    color: white;"
            "    border: none;"
            "}"
            "QPushButton[text='OK']:hover {"
            "    background-color: #6941C6;"
            "}"
            "QPushButton[text='OK']:disabled {"
            "    background-color: #E4E7EC;"
            "    color: #98A2B3;"
            "}"
            "QPushButton[text='Cancel'] {" // Стиль для кнопки отмены
            "    background-color: white;"
            "    color: #344054;"
            "    border: 1px solid #D0D5DD;"
            "}"
            "QPushButton[text='Cancel']:hover {"
            "    background-color: #F9FAFB;"
            "}"
            );

        connect(buttonBox, &QDialogButtonBox::accepted, this, &QDialog::accept);
        connect(buttonBox, &QDialogButtonBox::rejected, this, &QDialog::reject);

        mainLayout->addWidget(buttonBox);

        // Расчет ширины окна под заголовок (с учетом увеличенных полей)
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

    QString get_pin() const {
        QString fullPin;
        for (const auto *le : pin_fields) {
            fullPin.append(le->text());
        }
        return fullPin;
    }

    void clear_pin() {
        for (auto *le : pin_fields) {
            le->clear();
        }
        if (!pin_fields.empty()) {
            pin_fields[0]->setFocus();
        }
    }

protected:
    bool eventFilter(QObject *watched, QEvent *event) override {
        if (event->type() == QEvent::KeyPress) {
            QKeyEvent *keyEvent = static_cast<QKeyEvent*>(event);
            QLineEdit *currentLe = qobject_cast<QLineEdit*>(watched);

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
    void updateOkButtonState() {
        if (QPushButton *okButton = buttonBox->button(QDialogButtonBox::Ok)) {
            okButton->setEnabled(get_pin().length() == pin_len);
        }
    }

    std::vector<QLineEdit*> pin_fields;
    QDialogButtonBox *buttonBox = nullptr;
};

#endif // WIDGET_H
