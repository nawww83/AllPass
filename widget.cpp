/**
 * @author nawww83@gmail.com
 */

#include "widget.h"
#include "./ui_widget.h"

#include <qtimer.h>
#include <random> // std::random_device

#include <QMessageBox>
#include <QMenu>
#include <QContextMenuEvent>
#include <QPixmap>
#include <QIcon>
#include <QClipboard>

#include "passitemdelegate.h"
#include "utils.h"
#include "constants.h"
#include "storagemanager.h"


static int g_current_password_len;
static int g_new_storage_with_transfer_mode = false;
Q_GLOBAL_STATIC( StorageManager, storage_manager);

namespace {
    namespace pointers {
        MyTextEdit* txt_edit_master_phrase = nullptr;
        QTableWidgetItem* selected_context_table_item = nullptr;
    }
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

static void information_message_box(const QString& title, const QString& message) {
    QMessageBox mb(QMessageBox::Information, title, message);
    mb.exec();
}

static void warning_message_box(const QString& title, const QString& message) {
    QMessageBox mb(QMessageBox::Warning, title, message);
    mb.exec();
}

static void critical_message_box(const QString& title, const QString& message) {
    QMessageBox mb(QMessageBox::Critical, title, message);
    mb.exec();
}

// Очистить содержимое таблицы, сохраняя ее структуру.
static void clear_table(QTableWidget* widget) {
    widget->clearContents();
    while (widget->rowCount() > 0) {
        widget->removeRow(0);
    }
}

#define construct_recover_button(button) \
    button = new QPushButton(); \
    if (!button) { \
        critical_message_box( \
            QString::fromUtf8("Ошибка создания кнопки"), \
            QString::fromUtf8("Нулевой указатель QPushButton.")); \
    } else { \
        const QPixmap icon_map(":/icons8-restore-page-24.png"); \
        button->setIcon(QIcon(icon_map)); \
        button->setIconSize(icon_map.rect().size()); \
        button->setEnabled(false); \
        button->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed); \
        button->setToolTip( \
            QString::fromUtf8("Восстановить данные из активного хранилища, icons8.com")); \
        ui->horizontalLayout->addWidget(button); \
        connect(button, &QPushButton::clicked, this, &Widget::btn_recover_from_backup_clicked); \
    }

#define construct_create_new_storage_button(button) \
button = new QPushButton(); \
    if (!button) { \
        critical_message_box( \
                              QString::fromUtf8("Ошибка создания кнопки"), \
                              QString::fromUtf8("Нулевой указатель QPushButton.")); \
} else { \
        const QPixmap icon_map(":/icons8-key-24.png"); \
        button->setIcon(QIcon(icon_map)); \
        button->setIconSize(icon_map.rect().size()); \
        button->setEnabled(false); \
        button->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed); \
        button->setToolTip( \
            QString::fromUtf8("Создать новое хранилище с переносом данных, icons8.com")); \
        ui->horizontalLayout->addWidget(button); \
        connect(button, &QPushButton::clicked, this, &Widget::btn_new_storage_with_transfer_clicked); \
}

#define construct_clear_table_button(button) \
button = new QPushButton(); \
    if (!button) { \
        critical_message_box( \
                              QString::fromUtf8("Ошибка создания кнопки"), \
                              QString::fromUtf8("Нулевой указатель QPushButton.")); \
} else { \
        const QPixmap icon_map(":/icons8-clear-24.png"); \
        button->setIcon(QIcon(icon_map)); \
        button->setIconSize(icon_map.rect().size()); \
        button->setEnabled(false); \
        button->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed); \
        button->setToolTip( \
            QString::fromUtf8("Очистить текущую таблицу, icons8.com")); \
        ui->horizontalLayout->addWidget(button); \
        connect(button, &QPushButton::clicked, this, &Widget::btn_clear_table_clicked); \
}

#define configure_table(widget) \
    widget->setTabKeyNavigation(false); \
    widget->setFocusPolicy(Qt::StrongFocus); \
    widget->setSortingEnabled(false); \
    QStringList table_header {QString::fromUtf8("Логин"), QString::fromUtf8("Пароль"), QString::fromUtf8("Комментарии")}; \
    widget->setHorizontalHeaderLabels(table_header); \
    widget->verticalHeader()->setVisible(false); \
    widget->setColumnWidth(0, 210); \
    widget->setColumnWidth(1, 200); \
    widget->setColumnWidth(2, 370); \
    PassEditDelegate* pass_delegate = new PassEditDelegate(g_asterics, this); \
    widget->setItemDelegateForColumn(constants::pswd_column_idx, pass_delegate); \
    widget->installEventFilter(this); \
    widget->setEditTriggers(QAbstractItemView::DoubleClicked); \
    widget->setContextMenuPolicy(Qt::CustomContextMenu); \
    widget->setSelectionMode(QAbstractItemView::SingleSelection); \
    widget->horizontalHeader()->setStretchLastSection(true); \
    connect(widget, &QTableWidget::customContextMenuRequested, this, &Widget::tableWidget_customContextMenuRequested);

#define configure_actions \
    copyAct = new QAction(QIcon(), \
                          tr("&Копировать ячейку"), this); \
    copyAct->setShortcuts(QKeySequence::Copy); \
    connect(copyAct, &QAction::triggered, this, &Widget::copy_to_clipboard); \
    removeAct = new QAction(QIcon(), \
                            tr("&Удалить строку"), this); \
    removeAct->setShortcuts(QKeySequence::Delete); \
    connect(removeAct, &QAction::triggered, this, &Widget::delete_row); \
    updatePassAct = new QAction(QIcon(), \
                                tr("&Обновить пароль"), this); \
    connect(updatePassAct, &QAction::triggered, this, &Widget::update_pass);



Widget::Widget(QString&& pin, QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Widget)
{
    utils::fill_pin(std::move(pin));
    ui->setupUi(this);
    QString app_title = QString::fromUtf8("AllPass 128-bit ");
    QString current_version = QString(VERSION_LABEL).remove(g_version_prefix);
    app_title.append(current_version);
    app_title.append(QString::fromUtf8(" - Менеджер паролей"));
    this->setWindowTitle( app_title );

    pointers::txt_edit_master_phrase = new MyTextEdit();
    pointers::txt_edit_master_phrase->setWindowTitle(QString::fromUtf8("Ввод мастер-фразы"));
    pointers::txt_edit_master_phrase->setStyleSheet("color: white; background-color: black; font: 14px;");
    pointers::txt_edit_master_phrase->setVisible(false);

    connect(pointers::txt_edit_master_phrase, &MyTextEdit::sig_closing, this, &Widget::update_master_phrase);
    connect(this, &Widget::master_phrase_ready, this, &Widget::set_master_key);
    connect(this, &Widget::master_key_set, this, &Widget::finish_master_key);
    connect(this, &Widget::master_phrase_discarded, this, &Widget::discard_master_key);
    connect(this, &Widget::passwords_ready, this, &Widget::insert_new_password);
    connect(this, &Widget::row_deleted, this, &Widget::update_number_of_rows);
    connect(this, &Widget::row_inserted, this, &Widget::update_number_of_rows);
    connect(this, &Widget::table_changed, this, &Widget::update_table_info);

    ui->spbx_pass_len->setSingleStep(constants::pass_len_step);
    g_current_password_len = ui->spbx_pass_len->value();

    ui->btn_generate->setText(labels::gen_pass_txt);
    ui->btn_generate->setEnabled(false);

    construct_recover_button(btn_recover_from_backup);

    construct_create_new_storage_button(btn_new_storage_with_transfer);

    construct_clear_table_button(btn_clear_table);

    configure_table(ui->tableWidget);

    configure_actions;

    connect(&watcher_seed_pass_gen, &QFutureWatcher<lfsr_rng::Generators>::finished, this, &Widget::finish_password_generator);

    QTimer::singleShot(0, this, [&]{ input_master_phrase(); });
}

Widget::~Widget()
{
    save_to_store();
    delete ui;
}

bool Widget::eventFilter(QObject *object, QEvent *event)
{
    static bool found_copy = false;
    if (event->type() == QEvent::KeyPress)
    {
        QKeyEvent* pKeyEvent = static_cast<QKeyEvent*>(event);
        if (pKeyEvent->matches(QKeySequence::Copy))
        {
            found_copy = true;
            return true;
        }
        else
        {
            found_copy = false;
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
        if (found_copy)
        {
            pointers::selected_context_table_item = ui->tableWidget->currentItem();
            copy_to_clipboard();
            found_copy = false;
            return true;
        }
        if (pKeyEvent->matches(QKeySequence::Copy))
        {
            return true;
        }
    }
    return QWidget::eventFilter(object, event);
}

void Widget::closeEvent(QCloseEvent *event)
{
    event->ignore();
    if (question_message_box(tr("Подтверждение выхода"),
                             tr("Закрыть приложение? Текущие данные в таблице при этом будут\
                                сохранены на диск."))) {
        event->accept();
    }
}

void Widget::copy_to_clipboard() {
    if (!pointers::selected_context_table_item) {
        return;
    }
    QClipboard * clipboard = QApplication::clipboard();
    if (pointers::selected_context_table_item->column() == constants::pswd_column_idx) {
        clipboard->setText(pointers::selected_context_table_item->data(Qt::UserRole).toString());
    } else {
        clipboard->setText(pointers::selected_context_table_item->text());
    }
    pointers::selected_context_table_item = nullptr;
}

void Widget::delete_row() {
    if (!question_message_box(
            tr("Удаление текущей строки"),
            tr("Вы действительно хотите удалить выделенную строку?")))
    {
        return;
    }
    const int row = !pointers::selected_context_table_item ? ui->tableWidget->currentRow() :
                        pointers::selected_context_table_item->row();
    ui->tableWidget->removeRow(row);
    pointers::selected_context_table_item = nullptr;
    emit row_deleted();
}

void Widget::update_pass() {
    if (!pointers::selected_context_table_item) {
        return;
    }
    if (pointers::selected_context_table_item->column() == constants::pswd_column_idx) {
        if (!pointers::selected_context_table_item->data(Qt::UserRole).toString().isEmpty()) {
            if (!question_message_box(
                    tr("Замена текущего пароля новым"),
                    tr("Вы действительно хотите заменить выделенный пароль новым?")))
            {
                return;
            }
        }
        QString&& pswd = utils::try_to_get_password(g_current_password_len);
        if (pswd.length() < g_current_password_len) {
            utils::request_passwords(watcher_passwords, g_current_password_len);
            pswd = utils::try_to_get_password(g_current_password_len);
        }
        pointers::selected_context_table_item->setData(Qt::DisplayRole, g_asterics);
        pointers::selected_context_table_item->setData(Qt::UserRole, pswd);
        information_message_box(QString::fromUtf8("Успех"),
                                QString::fromUtf8("Пароль был обновлен"));
    } else {
        ;
    }
    pointers::selected_context_table_item = nullptr;
}

void Widget::finish_master_key()
{
    QString storage_name = storage_manager->Name();
    if (!storage_name.isEmpty() && storage_manager->IsSuccess()) {
        information_message_box(QString::fromUtf8("Успех"),
                                QString::fromUtf8("Ключ был установлен"));
        clear_table(ui->tableWidget);
        load_storage();
        storage_name = storage_manager->Name();
        if (!storage_name.isEmpty()) {
            ui->lbl_active_storage->setText(QString::fromUtf8(" Активное хранилище: %1").arg(storage_name));
        } else {
            ui->lbl_active_storage->setText(QString::fromUtf8(" Активное хранилище: недоступно."));
        }
    } else {
        warning_message_box(QString::fromUtf8("Неудача"),
                            QString::fromUtf8("Ключ не был установлен."));
    }
}

void Widget::finish_password_generator()
{
    password::pass_gen = watcher_seed_pass_gen.result();
    if (password::pass_gen.is_succes())
    {
        ui->btn_generate->setEnabled(true);
        ui->btn_generate->setFocus();
        ui->btn_generate->setText(labels::gen_pass_txt);
    } else {
        ui->btn_generate->setEnabled(false);
        warning_message_box(QString::fromUtf8("Неудача"),
                   QString::fromUtf8("Генератор паролей не был установлен."));
    }
}

void Widget::input_master_phrase()
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
        emit master_phrase_discarded();
        return;
    }
    storage_manager->BeforeUpdate();
    {
        lfsr_hash::u128 hash = utils::gen_hash_for_pass_gen(text, std::random_device{}());
        utils::fill_key_by_hash128(hash);
        utils::clear_lfsr_hash(hash);
    }
    {
        lfsr_hash::u128 hash_fs = utils::gen_hash_for_storage(text);
        storage_manager->SetName( utils::generate_storage_name(hash_fs) );
        utils::clear_lfsr_hash(hash_fs);
    }
    {
        lfsr_hash::u128 hash_enc = utils::gen_hash_for_encryption(text);
        lfsr_rng::STATE state = utils::fill_state_by_hash(hash_enc);
        watcher_seed_enc_gen.setFuture(password::worker->seed(state));
        watcher_seed_dec_gen.setFuture(password::worker->seed(state));

        lfsr_hash::u128 hash_enc_inner = utils::gen_hash_for_inner_encryption(text);
        lfsr_rng::STATE state_inner = utils::fill_state_by_hash(hash_enc_inner);
        watcher_seed_enc_inner_gen.setFuture(password::worker->seed(state_inner));
        watcher_seed_dec_inner_gen.setFuture(password::worker->seed(state_inner));

        utils::clear_lfsr_hash(hash_enc);
        utils::clear_lfsr_hash(hash_enc_inner);
        utils::clear_lfsr_rng_state(state);
        utils::clear_lfsr_rng_state(state_inner);

        watcher_seed_enc_gen.waitForFinished();
        watcher_seed_dec_gen.waitForFinished();
        watcher_seed_enc_inner_gen.waitForFinished();
        watcher_seed_dec_inner_gen.waitForFinished();

        storage_manager->SetEncGammaGenerator(watcher_seed_enc_gen.result());
        storage_manager->SetDecGammaGenerator(watcher_seed_dec_gen.result());
        storage_manager->SetEncInnerGammaGenerator(watcher_seed_enc_inner_gen.result());
        storage_manager->SetDecInnerGammaGenerator(watcher_seed_dec_inner_gen.result());
    }
    storage_manager->AfterUpdate();
    if (g_new_storage_with_transfer_mode && storage_manager->WasUpdated()) {
        const QTableWidget* const table = ui->tableWidget;
        storage_manager->SaveToStorage(table);
        g_new_storage_with_transfer_mode = false;
    }

    utils::erase_string(text);
    emit master_phrase_ready();
}

void Widget::set_master_key()
{
    lfsr_rng::STATE state; // key => state => password generator
    for (int i=0; i<password::key->N(); ++i) {
        state[i] = password::key->get_key(i);
    }
    watcher_seed_pass_gen.setFuture( password::worker->seed(state) );
    utils::clear_main_key();
    utils::clear_lfsr_rng_state(state);
    emit master_key_set();
}

void Widget::discard_master_key()
{
    if (g_new_storage_with_transfer_mode) {
        warning_message_box(QString::fromUtf8(""),
                            QString::fromUtf8("Ввод мастер-фразы был отменен. Изменений не будет."));
        utils::restore_pin();
    }
    g_new_storage_with_transfer_mode = false;
}

void Widget::insert_new_password()
{
    QString pswd = utils::try_to_get_password(g_current_password_len);
    if (pswd.length() < g_current_password_len) {
        utils::request_passwords(watcher_passwords, g_current_password_len);
        pswd = utils::try_to_get_password(g_current_password_len);
    }
    ui->tableWidget->insertRow(ui->tableWidget->rowCount());
    const int row = ui->tableWidget->rowCount() - 1;
    QTableWidgetItem* item = new QTableWidgetItem();
    item->setData(Qt::DisplayRole, g_asterics);
    item->setData(Qt::UserRole, pswd);
    ui->tableWidget->setItem(row, constants::pswd_column_idx, item);
    ui->tableWidget->resizeColumnToContents(constants::pswd_column_idx);
    ui->tableWidget->scrollToBottom();
    ui->btn_generate->setText(labels::gen_pass_txt);
    ui->btn_generate->setEnabled(true);
    ui->btn_generate->setFocus();
    emit row_inserted();
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
    emit passwords_ready();
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
    if (!ui->tableWidget->currentItem()) {
        return;
    }
    pointers::selected_context_table_item = ui->tableWidget->itemAt(pos);
    if (!pointers::selected_context_table_item) {
        if (ui->tableWidget->currentItem()->isSelected()) {
            QMenu menu;
            menu.addAction(removeAct);
            menu.exec(ui->tableWidget->mapToGlobal(pos));
        }
        return;
    }
    QMenu menu;
    menu.addAction(copyAct);
    menu.addAction(removeAct);
    if (pointers::selected_context_table_item &&
            pointers::selected_context_table_item->column() == constants::pswd_column_idx) {
        menu.addAction(updatePassAct);
    }
    menu.exec(ui->tableWidget->mapToGlobal(pos));
}

void Widget::save_to_store()
{
    const QTableWidget* const table = ui->tableWidget;
    storage_manager->SaveToStorage(table);
}

void Widget::load_storage()
{
    QTableWidget* const table = ui->tableWidget;
    const Loading_Errors loading_status = storage_manager->LoadFromStorage(table);
    qDebug() << "Loading status: " << int(loading_status);
    bool try_load_from_backup = false;
    bool was_failure = false;
    switch (loading_status) {
        case Loading_Errors::OK:
        case Loading_Errors::EMPTY_TABLE:
        case Loading_Errors::TABLE_IS_NOT_EMPTY:
            break;
        case Loading_Errors::NEW_STORAGE:
            try_load_from_backup = true;
            break;
        case Loading_Errors::CANNOT_BE_OPENED:
        case Loading_Errors::CRC_FAILURE:
        case Loading_Errors::UNRECOGNIZED:
            warning_message_box(QString::fromUtf8("Ошибка загрузки из основного хранилища."),
                       QString::fromUtf8("Не удалось загрузить/распознать основное хранилище: \
                                        данные будут загружены из резервной копии."));
            try_load_from_backup = true;
            was_failure = true;
            break;
        case Loading_Errors::EMPTY_ENCRYPTION:
            critical_message_box(QString::fromUtf8("Ошибка шифрования."),
                        QString::fromUtf8("Неизвестная ошибка шифрования."));
            storage_manager->SetName("");
            return;
            break;
        case Loading_Errors::EMPTY_STORAGE:
            critical_message_box(QString::fromUtf8("Ошибка имени хранилища."),
                        QString::fromUtf8("Пустое хранилище: не удалось сформировать имя хранилища."));
            storage_manager->SetName("");
            return;
            break;
        case Loading_Errors::UNKNOWN_FORMAT:
            critical_message_box(QString::fromUtf8("Ошибка формата."),
                        QString::fromUtf8("Неизвестная версия формата."));
            storage_manager->SetName("");
            return;
            break;
        default:
            critical_message_box(QString::fromUtf8("Ошибка обработки результата загрузки."),
                        QString::fromUtf8("Неизвестный тип результата загрузки хранилища."));
            storage_manager->SetName("");
            return;
            break;
    }
    if (try_load_from_backup) {
        const Loading_Errors loading_status_backup = storage_manager->LoadFromStorage(table, true);
        qDebug() << "Backup loading status: " << int(loading_status_backup);
        switch (loading_status_backup) {
            case Loading_Errors::OK:
            case Loading_Errors::EMPTY_TABLE:
            case Loading_Errors::TABLE_IS_NOT_EMPTY:
                warning_message_box(QString::fromUtf8("Загрузка из резервного хранилища."),
                       QString::fromUtf8("Данные загружены из резервной копии."));
                break;
            case Loading_Errors::NEW_STORAGE:
                if (!was_failure) {
                    information_message_box(QString::fromUtf8("Успех."),
                               QString::fromUtf8("Создано новое хранилище."));
                } else {
                    critical_message_box(QString::fromUtf8("Ошибка загрузки резервного хранилища."),
                           QString::fromUtf8("Отсутствует файл резервной копии. \
                            Заполните новую таблицу или вручную восстановите хранилище из собственной копии."));
                }
                break;
            case Loading_Errors::CANNOT_BE_OPENED:
            case Loading_Errors::CRC_FAILURE:
            case Loading_Errors::UNRECOGNIZED:
                critical_message_box(QString::fromUtf8("Ошибка загрузки резервного хранилища."),
                           QString::fromUtf8("Ошибка при загрузки файла из резервной копии. \
                            Заполните новую таблицу или вручную восстановите хранилище из собственной копии."));
                break;
            case Loading_Errors::EMPTY_ENCRYPTION:
                critical_message_box(QString::fromUtf8("Ошибка шифрования."),
                            QString::fromUtf8("Неизвестная ошибка шифрования."));
                storage_manager->SetName("");
                return;
                break;
            case Loading_Errors::EMPTY_STORAGE:
                critical_message_box(QString::fromUtf8("Ошибка имени хранилища."),
                            QString::fromUtf8("Пустое резервное хранилище: не удалось сформировать имя хранилища."));
                storage_manager->SetName("");
                return;
                break;
            case Loading_Errors::UNKNOWN_FORMAT:
                critical_message_box(QString::fromUtf8("Ошибка формата."),
                            QString::fromUtf8("Неизвестная версия формата в резервном хранилище."));
                storage_manager->SetName("");
                return;
                break;
            default:
                critical_message_box(QString::fromUtf8("Ошибка обработки результата загрузки."),
                            QString::fromUtf8("Неизвестный тип результата загрузки резервного хранилища."));
                storage_manager->SetName("");
                return;
                break;
        }
    }
    emit table_changed();
}

void Widget::btn_recover_from_backup_clicked()
{
    if (!question_message_box(
            tr("Восстановление текущей таблицы."),
            tr("Вы действительно хотите восстановить таблицу из текущего хранилища? \
                    После успешного ввода пин-кода текущая таблица будет перезаписана.")))
    {
        return;
    }
    MyDialog dialog;
    int result = dialog.exec();
    if (result == QDialog::Accepted) {
        ;
    } else {
        return;
    }
    QString pin {dialog.get_pin()};
    dialog.clear_pin();
    if (!utils::check_pin(std::move(pin))) {
        warning_message_box(QString::fromUtf8(""),
                            QString::fromUtf8("Введен неверный пин-код. Изменений не будет."));
        return;
    }

    const QTableWidget* const ro_table = ui->tableWidget;
    const bool save_to_temporary_file = true;
    storage_manager->SaveToStorage(ro_table, save_to_temporary_file);

    QTableWidget* const table = ui->tableWidget;
    clear_table(table);
    const bool load_from_backup = true;
    const Loading_Errors loading_status_backup = storage_manager->LoadFromStorage(table, load_from_backup);
    qDebug() << "Recovering from backup: loading status: " << int(loading_status_backup);
    switch (loading_status_backup) {
        case Loading_Errors::OK:
            emit table_changed();
            information_message_box(QString::fromUtf8("Успех."),
                   QString::fromUtf8("Данные загружены из текущего хранилища."));
            storage_manager->RemoveTmpFile();
            return;
            break;
        case Loading_Errors::EMPTY_TABLE:
            warning_message_box(QString::fromUtf8("Пустое ранилище."),
                                QString::fromUtf8("Пропуск загрузки копии из-за пустых данных."));
            break;
        case Loading_Errors::TABLE_IS_NOT_EMPTY:
            critical_message_box(QString::fromUtf8("Ошибка загрузки хранилища."),
                                 QString::fromUtf8("Ошибочный пропуск загрузки хранилища из-за непустой таблицы."));
            break;
        case Loading_Errors::NEW_STORAGE:
            warning_message_box(QString::fromUtf8("Отсутствие активного хранилища."),
                                QString::fromUtf8("Пропуск загрузки из-за отсутствия хранилища."));
            break;
        case Loading_Errors::CANNOT_BE_OPENED:
        case Loading_Errors::CRC_FAILURE:
        case Loading_Errors::UNRECOGNIZED:
            critical_message_box(QString::fromUtf8("Ошибка загрузки хранилища."),
                       QString::fromUtf8("Ошибка при загрузки файла текущего хранилища."));
            break;
        case Loading_Errors::EMPTY_ENCRYPTION:
            critical_message_box(QString::fromUtf8("Ошибка шифрования."),
                        QString::fromUtf8("Неизвестная ошибка шифрования."));
            storage_manager->SetName("");
            break;
        case Loading_Errors::EMPTY_STORAGE:
            critical_message_box(QString::fromUtf8("Ошибка имени хранилища."),
                        QString::fromUtf8("Пустое хранилище: не удалось сформировать имя хранилища."));
            storage_manager->SetName("");
            break;
        case Loading_Errors::UNKNOWN_FORMAT:
            critical_message_box(QString::fromUtf8("Ошибка формата."),
                        QString::fromUtf8("Неизвестная версия формата хранилища."));
            break;
        default:
            critical_message_box(QString::fromUtf8("Ошибка обработки результата загрузки."),
                        QString::fromUtf8("Неизвестный тип результата загрузки хранилища."));
            storage_manager->SetName("");
            break;
    }
    // Отмена восстановления.
    storage_manager->LoadFromStorage(table);
    storage_manager->RemoveTmpFile();
}

void Widget::btn_new_storage_with_transfer_clicked() {
    if (!question_message_box(
            tr("Создание нового хранилища с переносом данных."),
            tr("Вы действительно хотите создать новое хранилище и скопировать туда текущую таблицу?")))
    {
        return;
    }

    MyDialog dialog(QString::fromUtf8("Введите новый PIN-код"));
    int result = dialog.exec();
    if (result == QDialog::Accepted) {
        ;
    } else {
        warning_message_box(QString::fromUtf8(""),
                            QString::fromUtf8("Ввод пин-кода был отменен. Изменений не будет."));
        return;
    }
    QString pin {dialog.get_pin()};
    dialog.clear_pin();
    if (pin.size() != constants::pin_code_len) {
        QMessageBox mb(QMessageBox::Critical,
                       QString::fromUtf8("Ошибка PIN-кода"),
                       QString::fromUtf8("PIN-код должен быть любым 4-значным числом"));
        mb.exec();
        return;
    }

    g_new_storage_with_transfer_mode = true;
    utils::back_up_pin();
    utils::fill_pin(std::move(pin));

    warning_message_box(QString::fromUtf8(""),
                            QString::fromUtf8("После ввода новой мастер-фразы будет активировано новое хранилище. \
                                              Однако, старое при этом будет доступно. Вы можете его удалить вручную. \
                                            Если фраза введена не будет, то изменений не произойдет."));

    input_master_phrase();
}

void Widget::btn_clear_table_clicked()
{
    if (!question_message_box(
            tr("Очистка текущей таблицы."),
            tr("Вы действительно хотите очистить текущую таблицу? После успешного\
                    ввода пин-кода текущая таблица будет очищена. В случае необходимости\
                     ее можно восстановить из текущего хранилища, не закрывая приложения.")))
    {
        return;
    }
    MyDialog dialog;
    int result = dialog.exec();
    if (result == QDialog::Accepted) {
        ;
    } else {
        return;
    }
    QString pin {dialog.get_pin()};
    dialog.clear_pin();
    if (!utils::check_pin(std::move(pin))) {
        warning_message_box(QString::fromUtf8(""),
                            QString::fromUtf8("Введен неверный пин-код. Изменений не будет."));
        return;
    }
    clear_table(ui->tableWidget);

    emit table_changed();
}

void Widget::update_number_of_rows()
{
    ui->lbl_number_of_rows->setText(QString::fromUtf8("Количество записей: %1").arg(ui->tableWidget->rowCount()));
}

void Widget::update_table_info()
{
    ui->tableWidget->resizeColumnToContents(constants::pswd_column_idx);
    ui->tableWidget->sortByColumn(constants::comments_column_idx, Qt::SortOrder::AscendingOrder);
    btn_recover_from_backup->setEnabled(storage_manager->BackupFileIsExist());
    btn_new_storage_with_transfer->setEnabled(true);
    btn_clear_table->setEnabled(true);

    update_number_of_rows();
}
