#ifndef WIDGET_H
#define WIDGET_H

#include <QWidget>
#include <QTextEdit>
#include <QFutureWatcher>
#include <QAction>
#include <QLineEdit>
#include <QVBoxLayout>
#include <QDialog>
#include <QDialogButtonBox>
#include <qregularexpression.h>
#include <qvalidator.h>

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
    Widget(QString &&pin, QWidget *parent = nullptr);
    ~Widget();

    bool eventFilter(QObject *object, QEvent *event) override;

private slots:
    void seed_pass_has_been_set();

    void on_btn_input_master_phrase_clicked();

    void on_btn_generate_clicked();

    void update_master_phrase();

    void set_master_key();

    void copy_clipboard();

    void delete_row();

    void update_pass();

    void tableWidget_customContextMenuRequested(const QPoint &pos);

    void on_spbx_pass_len_valueChanged(int arg1);

    void on_spbx_pass_len_editingFinished();

    void on_btn_add_empty_row_clicked();

    void save_to_store();

    void load_storage();

signals:
    void master_phrase_ready();

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

class MyDialog : public QDialog
{
    Q_OBJECT
public:
    MyDialog(QWidget *parent = nullptr) : QDialog(parent)
    {
        setWindowTitle("Enter your 4-digits PIN");
        QVBoxLayout *layout = new QVBoxLayout;

        le_pin = new QLineEdit(this);
        le_pin->setEchoMode(QLineEdit::Password);
        static QRegularExpression rgx("[0-9]{4}");
        QValidator *comValidator = new QRegularExpressionValidator(rgx, this);
        le_pin->setValidator(comValidator);

        layout->addWidget(le_pin);
        le_pin->setText("");

        buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok
                                         | QDialogButtonBox::Cancel);

        connect(buttonBox, &QDialogButtonBox::accepted, this, &QDialog::accept);
        connect(buttonBox, &QDialogButtonBox::rejected, this, &QDialog::reject);

        layout->addWidget(buttonBox);
        setLayout(layout);

        le_pin->setFocus();
    }
    QString get_pin() const {
        return le_pin ? le_pin->text() : "";
    }
    void clear_pin() {
        le_pin->clear();
    }

private:
    QLineEdit* le_pin = nullptr;
    QDialogButtonBox *buttonBox;
};

#endif // WIDGET_H
