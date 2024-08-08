#ifndef WIDGET_H
#define WIDGET_H

#include <QWidget>
#include <QTextEdit>
#include <QFutureWatcher>
#include <QAction>

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
    Widget(QWidget *parent = nullptr);
    ~Widget();

private slots:
    void seed_has_been_set();

    void values_have_been_generated();

    void on_btn_input_master_phrase_clicked();

    void on_btn_generate_clicked();

    void update_master_phrase();

    void set_master_key();

    void on_spbx_pass_len_valueChanged(int arg1);

    void on_spbx_N_values_valueChanged(int arg1);

    void on_spbx_pass_len_editingFinished();

    void on_tableWidget_customContextMenuRequested(const QPoint &pos);

signals:
    void master_phrase_ready();

protected:
#ifndef QT_NO_CONTEXTMENU
    void contextMenuEvent(QContextMenuEvent *event) override;
#endif // QT_NO_CONTEXTMENU

private:
    Ui::Widget *ui;
    QFutureWatcher<lfsr_rng::Generators> watcher_seed;
    QFutureWatcher<QVector<lfsr8::u64>> watcher_generate;
    QAction *newAct;
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

#endif // WIDGET_H
