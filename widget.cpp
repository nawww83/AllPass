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
#include <QDate>

#include "passitemdelegate.h"
#include "utils.h"
#include "storagemanager.h"


static int g_current_password_len;
static int g_new_storage_with_transfer_mode = false;
static int g_table_is_loading = false;
Q_GLOBAL_STATIC( StorageManager, storage_manager);

/**
 * @brief Создавать перед массовым обновлением таблицы.
 * Запрещает автоматическую реакцию на изменение содержимого ячеек.
 */
class TableLoadingRAII {
public:
    explicit TableLoadingRAII() noexcept {g_table_is_loading = true;};
    ~TableLoadingRAII(){g_table_is_loading = false;};
};

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
    TableLoadingRAII lock;
    widget->clearContents();
    while (widget->rowCount() > 0)
        widget->removeRow(0);
}

// Подсветить пароль если просрочен; вернуть в дефолтное значение цвета, если нет.
static void highlight_pswd(QTableWidget* widget, int row, const QDate& current_date) {
    TableLoadingRAII lock;
    auto date_item = widget->item(row, constants::date_column_idx);
    auto pswd_item = widget->item(row, constants::pswd_column_idx);
    if (!date_item || !pswd_item) return;
    const auto& date = QDate::fromString(date_item->text(), "yyyy.MM.dd");
    if (!date.isValid()) return;
    const auto delta = current_date.toJulianDay() - date.toJulianDay(); // Разница в датах.
    const qint64 basic_interval = 365; // Базовый интервал (в днях). В данном случае это год.
    if ((delta > (basic_interval*3)/4) && (delta < basic_interval)) { // (75..100)% от года - желтый.
        pswd_item->setBackground(Qt::yellow);
        qDebug() << "Highlight item yellow: " << delta;
    }
    else if (delta >= basic_interval) { // Более 100% от года - красный.
        pswd_item->setBackground(Qt::red);
        qDebug() << "Highlight item red: " << delta;
    } else {
        pswd_item->setBackground(QBrush{});
    }
}

#define construct_recover_button(button) \
    button = new QPushButton(); \
    if (!button) { \
        critical_message_box( \
            QString::fromUtf8("Ошибка создания кнопки"), \
            QString::fromUtf8("Нулевой указатель QPushButton.")); \
    } else { \
        const QPixmap icon_map("://images/icons8-restore-page-24.png"); \
        button->setIcon(QIcon(icon_map)); \
        button->setIconSize(icon_map.rect().size()); \
        button->setEnabled(false); \
        button->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed); \
        button->setToolTip( \
            QString::fromUtf8("Восстановить данные из активного хранилища (icons8.com)")); \
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
        const QPixmap icon_map("://images/icons8-key-24.png"); \
        button->setIcon(QIcon(icon_map)); \
        button->setIconSize(icon_map.rect().size()); \
        button->setEnabled(false); \
        button->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed); \
        button->setToolTip( \
            QString::fromUtf8("Создать новое хранилище с переносом данных (icons8.com)")); \
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
        const QPixmap icon_map("://images/icons8-clear-24.png"); \
        button->setIcon(QIcon(icon_map)); \
        button->setIconSize(icon_map.rect().size()); \
        button->setEnabled(false); \
        button->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed); \
        button->setToolTip( \
            QString::fromUtf8("Очистить текущую таблицу (icons8.com)")); \
        ui->horizontalLayout->addWidget(button); \
        connect(button, &QPushButton::clicked, this, &Widget::btn_clear_table_clicked); \
}

#define configure_table(widget) \
    widget->setTabKeyNavigation(false); \
    widget->setFocusPolicy(Qt::StrongFocus); \
    widget->setSortingEnabled(false); \
    QStringList table_header {QString::fromUtf8("Логин"), QString::fromUtf8("Пароль"), QString::fromUtf8("Комментарии"), QString::fromUtf8("Дата")}; \
    widget->setHorizontalHeaderLabels(table_header); \
    widget->verticalHeader()->setVisible(false); \
    widget->setColumnWidth(0, 210); \
    widget->setColumnWidth(1, 200); \
    widget->setColumnWidth(2, 370); \
    widget->setColumnHidden(constants::date_column_idx, true); \
    PassEditDelegate* pass_delegate = new PassEditDelegate(g_asterics, this); \
    widget->setItemDelegateForColumn(constants::pswd_column_idx, pass_delegate); \
    widget->installEventFilter(this); \
    widget->setEditTriggers(QAbstractItemView::DoubleClicked); \
    widget->setContextMenuPolicy(Qt::CustomContextMenu); \
    widget->setSelectionMode(QAbstractItemView::SingleSelection); \
    widget->horizontalHeader()->setSectionResizeMode(constants::comments_column_idx, QHeaderView::Stretch); \
    connect(widget, &QTableWidget::customContextMenuRequested, this, &Widget::tableWidget_customContextMenuRequested); \
    connect(widget, &QTableWidget::itemChanged, this, &Widget::tableWidget_itemChanged);

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
    connect(updatePassAct, &QAction::triggered, this, &Widget::update_pass); \
    showPassDateAct = new QAction(QIcon(), \
                                tr("&Показать дату изменения пароля"), this); \
    connect(showPassDateAct, &QAction::triggered, this, &Widget::show_pass_date);

#ifdef QT_DEBUG
/**
 * @brief Тест на корректность функций "вперед-назад" генераторов гаммы.
 */
static int run_test() {
    const int offset = 120'000;
    QFutureWatcher<lfsr_rng::Generators> watcher_enc;
    lfsr_rng::STATE state_inner {2929 ,
                                14359 ,
                                45922 ,
                                39695 ,
                                53744 ,
                                53089 ,
                                18177 ,
                                45209 };
    watcher_enc.setFuture(password::worker->seed(state_inner));
    watcher_enc.waitForFinished();
    Encryption mEnc;
    mEnc.gamma_gen = watcher_enc.result();
    const int base_size = 64;
    const auto init_value = mEnc.gamma_gen.peek_u64();
    qDebug() << "1: " << mEnc.gamma_gen.peek_u64() << ", " << mEnc.counter;
    uint64_t tmp;
    for (int i = 0; i < offset; ++i) {
        mEnc.gamma_gen.next_u64();
        mEnc.counter++;
    }
    for (int i = 0; i < base_size - 1; ++i) {
        mEnc.gamma_gen.next_u64();
        mEnc.counter++;
    }
    {
        tmp = mEnc.gamma_gen.next_u64();
        mEnc.counter++;
    }
    qDebug() << "2: " << tmp << ", " << mEnc.counter;
    for (int i = 0; i < (base_size + offset); ++i) {
        tmp = mEnc.gamma_gen.back_u64();
        mEnc.counter--;
    }
    qDebug() << "1: " << tmp << ", " << mEnc.counter;
    return (init_value == mEnc.gamma_gen.peek_u64()) ? 0 : -1;
}
#endif


Widget::Widget(QString&& pin, QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Widget)
{
    #ifdef QT_DEBUG
    const auto result = run_test();
    if (result < 0) {
        critical_message_box("", QString::fromUtf8("Не пройден критический тест."));
        return;
    }
    #endif

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
        QString pswd = utils::try_to_get_password(g_current_password_len);
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

void Widget::show_pass_date()
{
    if (!pointers::selected_context_table_item) {
        return;
    }
    QString date{};
    if (pointers::selected_context_table_item->column() == constants::pswd_column_idx) {
        const int row = pointers::selected_context_table_item->row();
        auto date_item = ui->tableWidget->item(row, constants::date_column_idx);
        if (date_item) {
            date = date_item->text();
        }
        if (!date.isEmpty()) {
            information_message_box(QString::fromUtf8(""), QString::fromUtf8("Дата обновления пароля: %1").arg(date));
        } else {
            information_message_box(QString::fromUtf8(""), QString::fromUtf8("Нет информации по дате."));
        }
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

        storage_manager->RemoveTmpFile();

        load_storage();
        emit table_changed();

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
        const auto& name = utils::generate_storage_name(hash_fs);
        storage_manager->SetName( name );
        storage_manager->SetTmpName( name );
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
    {
        QTableWidgetItem* item = new QTableWidgetItem();
        item->setData(Qt::DisplayRole, g_asterics);
        item->setData(Qt::UserRole, pswd);
        ui->tableWidget->setItem(row, constants::pswd_column_idx, item);
    }
    {
        const auto& date = QDate::currentDate().toString("yyyy.MM.dd");
        QTableWidgetItem* item = new QTableWidgetItem();
        item->setText(date);
        ui->tableWidget->setItem(row, constants::date_column_idx, item);
        qDebug() << "Set date: " << date;
    }

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
        menu.addAction(showPassDateAct);
    }
    menu.exec(ui->tableWidget->mapToGlobal(pos));
}

void Widget::tableWidget_itemChanged(QTableWidgetItem *item)
{
    if (!item || g_table_is_loading) {
        return;
    }
    if (item->column() == constants::pswd_column_idx) {
        const auto& date = QDate::currentDate().toString("yyyy.MM.dd");
        const int row = item->row();
        auto date_item = ui->tableWidget->item(row, constants::date_column_idx);
        if (date_item) {
            date_item->setText(date);
            qDebug() << "Set date: " << date;
            const auto& current_date = QDate::currentDate();
            highlight_pswd(ui->tableWidget, row, current_date);
        }
    }
}

void Widget::save_to_store()
{
    const QTableWidget* const table = ui->tableWidget;
    storage_manager->SaveToStorage(table);
}

void Widget::load_storage()
{
    QTableWidget* const table = ui->tableWidget;
    clear_table(table);
    TableLoadingRAII lock;
    const auto loading_status = storage_manager->LoadFromStorage(table);
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
            warning_message_box(QString::fromUtf8("Ошибка загрузки хранилища."),
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
        TableLoadingRAII lock;
        const auto loading_status_backup = storage_manager->LoadFromStorage(table, FileTypes::BACKUP);
        qDebug() << "Backup loading status: " << int(loading_status_backup);
        switch (loading_status_backup) {
            case Loading_Errors::OK:
            case Loading_Errors::EMPTY_TABLE:
            case Loading_Errors::TABLE_IS_NOT_EMPTY:
                warning_message_box(QString::fromUtf8("Загрузка из резервного хранилища."),
                       QString::fromUtf8("Данные загружены из резервной копии."));
                break;
            case Loading_Errors::NEW_STORAGE:
                if (!was_failure && !storage_manager->TmpFileIsExist()) {
                    information_message_box(QString::fromUtf8("Успех."),
                               QString::fromUtf8("Создано новое хранилище."));
                } else if (storage_manager->TmpFileIsExist()) {
                    storage_manager->SetTryToLoadFromTmp();
                    return;
                }
                break;
            case Loading_Errors::CANNOT_BE_OPENED:
            case Loading_Errors::CRC_FAILURE:
            case Loading_Errors::UNRECOGNIZED:
                warning_message_box(QString::fromUtf8("Ошибка загрузки хранилища."),
                           QString::fromUtf8("Ошибка при загрузки файла из резервной копии."));
                storage_manager->SetName("");
                return;
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

    load_storage();

    if (storage_manager->IsTryToLoadFromTmp()) {
        // Аварийная отмена восстановления.
        warning_message_box(QString::fromUtf8("Ошибка хранилища."),
                             QString::fromUtf8("Таблица будет возвращена к исходному состоянию."));
        QTableWidget* const table = ui->tableWidget;
        clear_table(table);
        TableLoadingRAII lock;
        const auto loading_status_revert = storage_manager->LoadFromStorage(table, FileTypes::TEMPORARY);
        qDebug() << "Revert: loading status: " << int(loading_status_revert);
        if (loading_status_revert != Loading_Errors::OK) {
            critical_message_box(QString::fromUtf8("Ошибка хранилища."),
                                 QString::fromUtf8("Невосстановимая ошибка. Восстановите файл хранилища из Вашей копии\
                                                     и перезапустите программу."));
            storage_manager->SetName("");
        }
    }
    emit table_changed();
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

void Widget::highlight_items()
{
    const auto& current_date = QDate::currentDate();
    QTableWidget* const table = ui->tableWidget;
    for( int row = 0; row < table->rowCount(); ++row )
        highlight_pswd(table, row, current_date);
}

void Widget::update_table_info()
{
    ui->tableWidget->resizeColumnToContents(constants::pswd_column_idx);
    ui->tableWidget->sortByColumn(constants::comments_column_idx, Qt::SortOrder::AscendingOrder);
    btn_recover_from_backup->setEnabled(storage_manager->BackupFileIsExist() || storage_manager->FileIsExist());
    btn_new_storage_with_transfer->setEnabled(true);
    btn_clear_table->setEnabled(true);

    storage_manager->RemoveTmpFile();
    storage_manager->SetTryToLoadFromTmp(false);

    update_number_of_rows();
    highlight_items(); // Подсветить просроченные пароли.
}
