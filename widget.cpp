/**
 * @author nawww83@gmail.com
 */

#include "widget.h"
#include "./ui_widget.h"

#include <random> // std::random_device

#include <QMessageBox>
#include <QMenu>
#include <QContextMenuEvent>
#include <QIcon>
#include <QClipboard>

#include "passitemdelegate.h"
#include "utils.h"
#include "constants.h"
#include "storagemanager.h"

static int g_current_password_len;
Q_GLOBAL_STATIC( StorageManager, storage_manager);

namespace {
    namespace pointers {
        MyTextEdit* txt_edit_master_phrase = nullptr;
        QTableWidgetItem* selected_context_item = nullptr;
    }
}

Widget::Widget(QString&& pin, QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Widget)
{
    utils::fill_pin(std::move(pin));
    ui->setupUi(this);
    QString title = QString::fromUtf8("AllPass 128-bit ");
    QString version = QString(VERSION).remove(g_version_prefix);
    title.append(version);
    title.append(QString::fromUtf8(" - Менеджер паролей"));
    this->setWindowTitle( title );

    pointers::txt_edit_master_phrase = new MyTextEdit();
    pointers::txt_edit_master_phrase->setWindowTitle(QString::fromUtf8("Ввод мастер-фразы"));
    pointers::txt_edit_master_phrase->setStyleSheet("color: white; background-color: black; font: 14px;");
    pointers::txt_edit_master_phrase->setVisible(false);

    connect(pointers::txt_edit_master_phrase, &MyTextEdit::sig_closing, this, &Widget::update_master_phrase);
    connect(this, &Widget::master_phrase_ready, this, &Widget::set_master_key);

    ui->spbx_pass_len->setSingleStep(constants::pass_len_step);
    g_current_password_len = ui->spbx_pass_len->value();

    ui->btn_generate->setText(labels::gen_pass_txt);
    ui->btn_generate->setEnabled(false);
    ui->btn_add_empty_row->setEnabled(false);

    ui->tableWidget->setSortingEnabled(false);
    QStringList table_header {QString::fromUtf8("Логин"), QString::fromUtf8("Пароль"), QString::fromUtf8("Комментарии")};
    ui->tableWidget->setHorizontalHeaderLabels(table_header);
    ui->tableWidget->verticalHeader()->setVisible(false);
    ui->tableWidget->setColumnWidth(0, 200);
    ui->tableWidget->setColumnWidth(1, 200);
    ui->tableWidget->setColumnWidth(2, 370);
    PassEditDelegate* pass_delegate = new PassEditDelegate(g_asterics, this);
    ui->tableWidget->setItemDelegateForColumn(constants::pswd_column_idx, pass_delegate);
    ui->tableWidget->installEventFilter(this);
    ui->tableWidget->setEditTriggers(QAbstractItemView::DoubleClicked);
    ui->tableWidget->setContextMenuPolicy(Qt::CustomContextMenu);
    ui->tableWidget->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->tableWidget->horizontalHeader()->setStretchLastSection(true);
    connect(ui->tableWidget, &QTableWidget::customContextMenuRequested, this, &Widget::tableWidget_customContextMenuRequested);
    copyAct = new QAction(QIcon(),
                         tr("&Копировать ячейку"), this);
    copyAct->setShortcuts(QKeySequence::Copy);
    connect(copyAct, &QAction::triggered, this, &Widget::copy_clipboard);
    removeAct = new QAction(QIcon(),
                          tr("&Удалить строку"), this);
    removeAct->setShortcuts(QKeySequence::Delete);
    connect(removeAct, &QAction::triggered, this, &Widget::delete_row);
    updatePassAct = new QAction(QIcon(),
                                tr("&Обновить пароль"), this);
    connect(updatePassAct, &QAction::triggered, this, &Widget::update_pass);

    connect(&watcher_seed_pass_gen, &QFutureWatcher<lfsr_rng::Generators>::finished, this, &Widget::seed_pass_has_been_set);

    ui->btn_input_master_phrase->setFocus();
}

Widget::~Widget()
{
    save_to_store();
    delete ui;
}

static bool question_message_box(const QString& title, const QString& question) {
    QMessageBox mb(QMessageBox::Question,
                   title,
                   question);
    QPushButton* yes_button = mb.addButton(QObject::tr("Да"), QMessageBox::YesRole);
    QPushButton* no_button = mb.addButton(QObject::tr("Нет"), QMessageBox::NoRole);
    mb.setDefaultButton(no_button);
    mb.exec();
    return mb.clickedButton() == yes_button;
}

bool Widget::eventFilter(QObject *object, QEvent *event)
{
    static bool foundCopy = false;
    if (event->type() == QEvent::KeyPress)
    {
        QKeyEvent* pKeyEvent = static_cast<QKeyEvent*>(event);
        if (pKeyEvent->matches(QKeySequence::Copy))
        {
            foundCopy = true;
            return true;
        }
        else
        {
            foundCopy = false;
        }
        if (pKeyEvent->key() == Qt::Key_Delete && ui->tableWidget->hasFocus())
        {
            const int rows = ui->tableWidget->rowCount();
            delete_row();
            return rows != ui->tableWidget->rowCount();
        }
    }
    if (event->type() == QEvent::KeyRelease)
    {
        QKeyEvent* pKeyEvent = static_cast<QKeyEvent*>(event);
        if (foundCopy)
        {
            pointers::selected_context_item = ui->tableWidget->currentItem();
            copy_clipboard();
            foundCopy = false;
            return true;
        }
        if (pKeyEvent->matches(QKeySequence::Copy))
        {
            return true;
        }
    }
    return QWidget::eventFilter(object, event);
}

void Widget::copy_clipboard() {
    if (!pointers::selected_context_item) {
        return;
    }
    QClipboard * clipboard = QApplication::clipboard();
    if (pointers::selected_context_item->column() == constants::pswd_column_idx) {
        clipboard->setText(pointers::selected_context_item->data(Qt::UserRole).toString());
    } else {
        clipboard->setText(pointers::selected_context_item->text());
    }
    pointers::selected_context_item = nullptr;
}

void Widget::delete_row() {
    if (!question_message_box(
            tr("Удаление текущей строки"),
            tr("Вы действительно хотите удалить выделенную строку?")))
    {
        return;
    }
    if (!pointers::selected_context_item) {
        const int row = ui->tableWidget->currentRow();
        ui->tableWidget->removeRow(row);
        return;
    }
    ui->tableWidget->removeRow(pointers::selected_context_item->row());
    pointers::selected_context_item = nullptr;
}

void Widget::update_pass() {
    if (!pointers::selected_context_item) {
        return;
    }
    if (pointers::selected_context_item->column() == constants::pswd_column_idx) {
        if (!pointers::selected_context_item->data(Qt::UserRole).toString().isEmpty()) {
            if (!question_message_box(
                    tr("Замена текущего пароля новым"),
                    tr("Вы действительно хотите заменить выделенный пароль новым?")))
            {
                return;
            }
        }
        QString&& pswd = utils::get_password(g_current_password_len);
        if (pswd.length() < g_current_password_len) {
            utils::request_passwords(watcher_passwords, g_current_password_len);
            pswd = utils::get_password(g_current_password_len);
        }
        pointers::selected_context_item->setData(Qt::DisplayRole, g_asterics);
        pointers::selected_context_item->setData(Qt::UserRole, pswd);
        QMessageBox mb;
        mb.information(this, QString::fromUtf8("Успех"),
                       QString::fromUtf8("Пароль был обновлен"));
    } else {
        ;
    }
    pointers::selected_context_item = nullptr;
}

void Widget::seed_pass_has_been_set()
{
    password::pass_gen = watcher_seed_pass_gen.result();
    QMessageBox mb;
    if (!password::pass_gen.is_succes())
    {
        mb.warning(this, QString::fromUtf8("Неудача"),
                   QString::fromUtf8("Ключ не был установлен: попробуйте ввести другую мастер-фразу."));
    } else {
        QString&& storage_name = storage_manager->Name();
        if (!storage_name.isEmpty()) {
            mb.information(this, QString::fromUtf8("Успех"),
                           QString::fromUtf8("Ключ был установлен"));
            ui->tableWidget->clearContents();
            while (ui->tableWidget->rowCount() > 0) {
                ui->tableWidget->removeRow(0);
            }
            load_storage();
            storage_name = storage_manager->Name();
            if (!storage_name.isEmpty()) {
                ui->btn_input_master_phrase->setText(QString::fromUtf8("Активное хранилище: %1").arg(storage_name));
            } else {
                ui->btn_input_master_phrase->setText(QString::fromUtf8("Активное хранилище: повреждено"));
            }
            ui->btn_generate->setEnabled(!storage_name.isEmpty());
            ui->btn_add_empty_row->setEnabled(!storage_name.isEmpty());
            ui->btn_generate->setFocus();
            ui->btn_generate->setText(labels::gen_pass_txt);
        }
    }
}

void Widget::on_btn_input_master_phrase_clicked()
{
    pointers::txt_edit_master_phrase->setVisible(true);
    pointers::txt_edit_master_phrase->resize(400, 250);
    pointers::txt_edit_master_phrase->setFocus();
}

void Widget::update_master_phrase()
{
    QString text {pointers::txt_edit_master_phrase->toPlainText()};
    pointers::txt_edit_master_phrase->clear();
    if (text.isEmpty()) {
        return;
    }
    ui->btn_input_master_phrase->setEnabled(false);
    lfsr_hash::u128 hash = utils::gen_hash_for_pass_gen(text, std::random_device{}());
    utils::fill_key_by_hash128(hash);
    // Clear
    #pragma optimize( "", off )
        hash.first = 0; hash.second = 0;
    #pragma optimize( "", on )
    {
        lfsr_hash::u128 hash_fs = utils::gen_hash_for_storage(text);
        storage_manager->SetName( utils::generate_storage_name(hash_fs) );
        lfsr_hash::u128 hash_enc = utils::gen_hash_for_encryption(text);
        lfsr_rng::STATE st1 = utils::fill_state_by_hash(hash_enc);
        watcher_seed_enc_gen.setFuture(password::worker->seed(st1));
        watcher_seed_dec_gen.setFuture(password::worker->seed(st1));

        lfsr_hash::u128 hash_enc_inner = utils::gen_hash_for_inner_encryption(text);
        lfsr_rng::STATE st2 = utils::fill_state_by_hash(hash_enc_inner);
        watcher_seed_enc_inner_gen.setFuture(password::worker->seed(st2));
        watcher_seed_dec_inner_gen.setFuture(password::worker->seed(st2));
        // Clear
        #pragma optimize( "", off )
            hash_fs = {0, 0};
            hash_enc = {0, 0};
            hash_enc_inner = {0, 0};
            for (auto& el : text) {
                el = '\0';
            }
        #pragma optimize( "", on )
        utils::clear_lfsr_rng_state(st1);
        utils::clear_lfsr_rng_state(st2);

        watcher_seed_enc_gen.waitForFinished();
        watcher_seed_dec_gen.waitForFinished();
        watcher_seed_enc_inner_gen.waitForFinished();
        watcher_seed_dec_inner_gen.waitForFinished();

        storage_manager->SetEncGammaGenerator(watcher_seed_enc_gen.result());
        storage_manager->SetDecGammaGenerator(watcher_seed_dec_gen.result());
        storage_manager->SetEncInnerGammaGenerator(watcher_seed_enc_inner_gen.result());
        storage_manager->SetDecInnerGammaGenerator(watcher_seed_dec_inner_gen.result());
    }
    emit master_phrase_ready();
}

void Widget::set_master_key()
{
    lfsr_rng::STATE st; // key => state => generator
    for (int i=0; i<password::key->N(); ++i) {
        st[i] = password::key->get_key(i);
    }
    watcher_seed_pass_gen.setFuture( password::worker->seed(st) );
    utils::clear_main_key();
    utils::clear_lfsr_rng_state(st);
}

void Widget::on_btn_generate_clicked()
{
    if (!watcher_seed_pass_gen.isFinished()) {
        qDebug() << "Rejected: PRNG is not initialized yet!";
        return;
    }
    if (constants::num_of_passwords < 1) {
        qDebug() << "Rejected: not correct password length!";
        return;
    }
    if (!password::pass_gen.is_succes()) {
        qDebug() << "Rejected: set the master phrase first!";
        return;
    }
    ui->btn_generate->setText(labels::wait_txt);
    ui->btn_generate->setEnabled(false);
    QString&& pswd = utils::get_password(g_current_password_len);
    if (pswd.length() < g_current_password_len) {
        utils::request_passwords(watcher_passwords, g_current_password_len);
        pswd = utils::get_password(g_current_password_len);
    }
    ui->tableWidget->insertRow(ui->tableWidget->rowCount());
    const int row = ui->tableWidget->rowCount() - 1;
    QTableWidgetItem* item = new QTableWidgetItem();
    item->setData(Qt::DisplayRole, g_asterics);
    item->setData(Qt::UserRole, pswd);
    ui->tableWidget->setItem(row, constants::pswd_column_idx, item);
    ui->tableWidget->resizeColumnToContents(constants::pswd_column_idx);
    ui->btn_generate->setText(labels::gen_pass_txt);
    ui->btn_generate->setEnabled(true);
    ui->btn_generate->setFocus();
}

void Widget::on_spbx_pass_len_valueChanged(int arg1)
{
    g_current_password_len = arg1 - (arg1 % constants::pass_len_step);
}

void Widget::on_spbx_pass_len_editingFinished()
{
    if (ui->spbx_pass_len->value() != g_current_password_len)
        ui->spbx_pass_len->setValue(g_current_password_len);
}

void Widget::tableWidget_customContextMenuRequested(const QPoint &pos)
{
    pointers::selected_context_item = ui->tableWidget->itemAt(pos);
    if (!pointers::selected_context_item) {
        QMenu menu;
        menu.addAction(removeAct);
        menu.exec(ui->tableWidget->mapToGlobal(pos));
        return;
    }
    QMenu menu;
    menu.addAction(copyAct);
    menu.addAction(removeAct);
    if (pointers::selected_context_item->column() == constants::pswd_column_idx) {
        menu.addAction(updatePassAct);
    }
    menu.exec(ui->tableWidget->mapToGlobal(pos));
}

void Widget::on_btn_add_empty_row_clicked()
{
    ui->tableWidget->insertRow(ui->tableWidget->rowCount());
    ui->tableWidget->setItem(ui->tableWidget->rowCount()-1, constants::pswd_column_idx, new QTableWidgetItem(""));
}

void Widget::save_to_store()
{
    const QTableWidget* const table = ui->tableWidget;
    storage_manager->SaveToStorage(table);
}

void Widget::load_storage()
{
    QTableWidget* const table = ui->tableWidget;
    storage_manager->LoadFromStorage(table);
}
