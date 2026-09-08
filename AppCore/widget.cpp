/**
 * @author nawww83@gmail.com
 */

#include "widget.h"

#include <qtimer.h>
#include <random> // std::random_device

#include <QMessageBox>
#include <QMenu>
#include <QContextMenuEvent>
#include <QPixmap>
#include <QIcon>
#include <QClipboard>
#include <QDate>
#include <QElapsedTimer>

#include "AppCore/ui_widget.h"
#include "passitemdelegate.h"
#include "storagemanager.h"
#include "usbstorages.h"
#include "utils_global.h"

static int g_current_password_len;
static int g_new_storage_with_transfer_mode = false;
static int g_table_is_loading = false;
static int g_use_usb_token = false;
Q_GLOBAL_STATIC(QByteArray, g_usb_hashes);
Q_GLOBAL_STATIC(StorageManager, storage_manager);

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

enum class ExitAction {
    SaveAndExit,
    DiscardAndExit,
    Cancel
};

static ExitAction before_exit_message_box(const QString& title, const QString& question) {
    QMessageBox mb(QMessageBox::Question, title, question);

    // Использование правильных ролей для кнопок
    QPushButton* saveButton = mb.addButton(QObject::tr("Да (сохранить)"), QMessageBox::AcceptRole);
    QPushButton* discardButton = mb.addButton(QObject::tr("Нет (не сохранять)"), QMessageBox::DestructiveRole);

    mb.addButton(QObject::tr("Отмена"), QMessageBox::RejectRole);

    // Устанавливаем кнопку по умолчанию (на неё будет реагировать Enter)
    mb.setDefaultButton(saveButton);
    saveButton->setFocus();

    mb.exec();

    // Проверяем, какая кнопка была нажата
    if (mb.clickedButton() == saveButton) {
        return ExitAction::SaveAndExit;
    }
    if (mb.clickedButton() == discardButton) {
        return ExitAction::DiscardAndExit;
    }

    // Если нажата кнопка «Отмена», закрыт крестик или нажат Esc
    return ExitAction::Cancel;
}

static bool question_message_box(const QString& title, const QString& question) {
    QMessageBox mb(QMessageBox::Question, title, question);

    QPushButton* yes_button = mb.addButton(QObject::tr("Да"), QMessageBox::DestructiveRole);
    QPushButton* no_button = mb.addButton(QObject::tr("Нет"), QMessageBox::AcceptRole);

    mb.setDefaultButton(no_button);
    no_button->setFocus();

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
do { \
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
                QString::fromUtf8("Восстановить данные из active-хранилища (icons8.com)")); \
            ui->horizontalLayout->addWidget(button); \
            connect(button, &QPushButton::clicked, this, &Widget::btn_recover_from_backup_clicked); \
    } \
} while(0)

#define construct_create_new_storage_button(button) \
do { \
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
                QString::fromUtf8("Перенести данные в новое хранилище (icons8.com)")); \
            ui->horizontalLayout->addWidget(button); \
            connect(button, &QPushButton::clicked, this, &Widget::btn_new_storage_with_transfer_clicked); \
    } \
} while(0)

#define construct_clear_table_button(button) \
do { \
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
    } \
} while(0)

#define construct_create_usb_key_button(button) \
do { \
        button = new QPushButton(); \
        if (!button) { \
            critical_message_box( \
                                  QString::fromUtf8("Ошибка создания кнопки"), \
                                  QString::fromUtf8("Нулевой указатель QPushButton.")); \
    } else { \
            const QPixmap icon_map("://images/icons8-usb-logo-24.png"); \
            button->setIcon(QIcon(icon_map)); \
            button->setIconSize(icon_map.rect().size()); \
            button->setEnabled(false); \
            button->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed); \
            button->setToolTip( \
                QString::fromUtf8("Записать мастер-фразу (ключ) на usb-носитель (icons8.com)")); \
            ui->horizontalLayout->addWidget(button); \
            connect(button, &QPushButton::clicked, this, &Widget::btn_create_usb_key_clicked); \
    } \
} while(0)

#define configure_table(widget) \
    do { \
        widget->setTabKeyNavigation(false); \
        widget->setFocusPolicy(Qt::ClickFocus); \
        widget->setSortingEnabled(false); \
\
        QStringList table_header{QString::fromUtf8("Логин"), \
                                 QString::fromUtf8("Пароль"), \
                                 QString::fromUtf8("Комментарии"), \
                                 QString::fromUtf8("Дата")}; \
        widget->setColumnCount(table_header.size()); \
        widget->setHorizontalHeaderLabels(table_header); \
        widget->verticalHeader()->setVisible(false); \
\
        widget->setColumnWidth(0, 210); \
        widget->setColumnWidth(1, 200); \
        widget->setColumnHidden(constants::date_column_idx, true); \
        widget->horizontalHeader()->setSectionResizeMode(constants::comments_column_idx, \
                                                         QHeaderView::Stretch); \
\
        PassEditDelegate *global_delegate = new PassEditDelegate(widget); \
        widget->setItemDelegate(global_delegate); \
\
        widget->installEventFilter(this); \
        widget->viewport()->installEventFilter(this); \
        widget->setEditTriggers(QAbstractItemView::DoubleClicked); \
        widget->setContextMenuPolicy(Qt::CustomContextMenu); \
\
        /* Отключаем деструктивный системный механизм выделения Qt 6.11 */ \
        widget->setSelectionMode(QAbstractItemView::NoSelection); \
        widget->setSelectionBehavior(QAbstractItemView::SelectItems); \
        widget->setStyleSheet( \
            "QTableWidget { outline: 0; } QTableWidget::item { border: none; }"); \
\
        connect(widget, \
                &QTableWidget::customContextMenuRequested, \
                this, \
                &Widget::tableWidget_customContextMenuRequested); \
        connect(widget, &QTableWidget::itemChanged, this, &Widget::tableWidget_itemChanged); \
\
        /* Синхронно обновляем таблицу при перемещении фокуса (клик по любой ячейке) */ \
        connect(widget->selectionModel(), \
                &QItemSelectionModel::currentChanged, \
                this, \
                [wPtr = widget](const QModelIndex &current, const QModelIndex &previous) { \
                    Q_UNUSED(previous); \
                    if (current.isValid() && wPtr) { \
                        /* update() может быть оптимизирован Qt, viewport()->repaint() принудительно перерисует экран */ \
                        wPtr->viewport()->repaint(); \
                    } \
                }); \
\
        /* Двойной клик по-прежнему открывает полноценный рабочий редактор */ \
        connect(widget, &QTableWidget::itemDoubleClicked, this, [](QTableWidgetItem *item) { \
            if (item && item->tableWidget() && item->column() == constants::pswd_column_idx) { \
                item->tableWidget()->editItem(item); \
            } \
        }); \
    } while (0)

#define configure_actions \
do { \
        copyAct = new QAction(QIcon(), \
                              tr("&Копировать ячейку"), this); \
        copyAct->setShortcuts(QKeySequence::Copy); \
        copyAct->setShortcutContext(Qt::WidgetWithChildrenShortcut); /* <--- ДОБАВИТЬ */ \
        connect(copyAct, &QAction::triggered, this, &Widget::copy_to_clipboard); \
    \
        removeAct = new QAction(QIcon(), \
                                tr("&Удалить строку"), this); \
        removeAct->setShortcut(QKeySequence::Delete); /* Лучше setShortcut вместо setShortcuts */ \
        removeAct->setShortcutContext(Qt::WidgetWithChildrenShortcut); /* <--- ДОБАВИТЬ */ \
        connect(removeAct, &QAction::triggered, this, &Widget::delete_row); \
    \
        updatePassAct = new QAction(QIcon(), \
                                    tr("&Обновить пароль"), this); \
        connect(updatePassAct, &QAction::triggered, this, &Widget::update_pass); \
    \
        showPassDateAct = new QAction(QIcon(), \
                                      tr("&Показать дату изменения пароля"), this); \
        connect(showPassDateAct, &QAction::triggered, this, &Widget::show_pass_date); \
} while(0)


#ifdef QT_DEBUG
/**
 * @brief Тест на корректность функций "вперед-назад" генераторов гаммы с проверкой значений.
 */
static int run_test() {
    constexpr int offset = 120'000;
    constexpr int base_size = 64;
    const int total_steps = offset + base_size;

    QFutureWatcher<lfsr_rng::Generators> watcher_enc;
    lfsr_rng::STATE state_inner {2929, 14359, 45922, 39695, 53744, 53089, 18177, 45209};

    watcher_enc.setFuture(password::worker->seed(state_inner));
    watcher_enc.waitForFinished();

    Encryption mEnc;
    mEnc.gamma_gen = watcher_enc.result();

    // Запоминаем самое первое число
    const uint64_t init_value = mEnc.gamma_gen.peek_u64();
    qDebug() << "1: " << init_value << ", " << mEnc.counter;

    // Массив для фиксации ВСЕХ сгенерированных чисел при движении вперед
    QVector<uint64_t> forward_history;
    forward_history.reserve(total_steps);

    // Шаг 1: Сдвиг вперед на величину offset
    for (int i = 0; i < offset; ++i) {
        forward_history.append(mEnc.gamma_gen.next_u64());
        mEnc.counter++;
    }

    // Шаг 2: Сдвиг вперед на (base_size - 1)
    for (int i = 0; i < base_size - 1; ++i) {
        forward_history.append(mEnc.gamma_gen.next_u64());
        mEnc.counter++;
    }

    // Шаг 3: Последний одиночный сдвиг вперед с фиксацией пикового значения
    uint64_t tmp = mEnc.gamma_gen.next_u64();
    forward_history.append(tmp);
    mEnc.counter++;
    qDebug() << "2: " << tmp << ", " << mEnc.counter;

    // Шаг 4: Откат назад с жесткой сверкой значений на каждом шаге
    bool values_match = true;
    for (int i = 0; i < total_steps; ++i) {
        tmp = mEnc.gamma_gen.back_u64();
        mEnc.counter--;

        // Индекс исторического числа при движении назад (идет от конца к началу)
        int history_idx = total_steps - 1 - i;
        if (tmp != forward_history[history_idx]) {
            qDebug() << "ERROR: Значение при откате не совпало на шаге" << i
                     << "Ожидалось:" << forward_history[history_idx] << "Получено:" << tmp;
            values_match = false;
        }
    }

    const uint64_t final_peek = mEnc.gamma_gen.peek_u64();
    qDebug() << "3: " << tmp << ", " << mEnc.counter;

    // Условия успешности теста:
    // 1. Начальное состояние совпало с финальным
    // 2. ВСЕ числа при откате назад бит-в-бит совпали с историей движения вперед
    if (init_value == final_peek && values_match) {
        qDebug() << "SUCCESS: Тест генератора успешно пройден!";
        return 0;
    } else {
        qDebug() << "FAILURE: Тест провален. Состояние или значения нарушены.";
        return -1;
    }
}
#endif

Widget::Widget(QWidget *parent)
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

    m_masterPhraseConn = connect(pointers::txt_edit_master_phrase, &MyTextEdit::sig_closing, this, &Widget::update_master_phrase);
    connect(this, &Widget::master_phrase_ready, this, &Widget::set_master_key);
    connect(this, &Widget::master_key_set, this, &Widget::finish_master_key);
    connect(this, &Widget::master_phrase_discarded, this, &Widget::discard_master_key);
    connect(this, &Widget::passwords_ready, this, &Widget::insert_new_password);
    connect(this, &Widget::row_deleted, this, &Widget::update_number_of_rows);
    connect(this, &Widget::row_inserted, this, &Widget::update_number_of_rows);
    connect(this, &Widget::table_changed, this, &Widget::update_table_info);

    ui->spbx_pass_len->setSingleStep(constants::password_len_step);
    g_current_password_len = ui->spbx_pass_len->value();

    ui->btn_generate->setText(QString::fromUtf8("\xE2\x9E\x95")); // "+" sign
    ui->btn_generate->setEnabled(false);

    // Ловим клики по пустому фону самого окна
    this->installEventFilter(this);
    this->setFocusPolicy(Qt::ClickFocus);

    construct_recover_button(btn_recover_from_backup);

    construct_create_usb_key_button(btn_create_usb_key);

    construct_create_new_storage_button(btn_new_storage_with_transfer);

    construct_clear_table_button(btn_clear_table);

    configure_table(ui->tableWidget);

    configure_actions;

    ui->tableWidget->addAction(copyAct);
    ui->tableWidget->addAction(removeAct);

    connect(&watcher_seed_pass_gen, &QFutureWatcher<lfsr_rng::Generators>::finished, this, &Widget::finish_password_generator);

#if defined(Q_OS_LINUX) || defined(Q_OS_WIN)
    QString temp_pin_str;
    for (int i = 0; i < constants::pin_code_len; ++i) {
        if (password::pin_code.mPinCode.at(i) >= 0) {
            temp_pin_str.append(QString::number(password::pin_code.mPinCode.at(i)));
        }
    }
    auto stack_pin_str = password::pin_code.to_numeric_string();
    UsbStorages usb_storages{std::string_view{stack_pin_str.data(), stack_pin_str.size()}};
    *g_usb_hashes = usb_storages.tryToReadKey();
    stack_pin_str.fill('\0');
    if (!g_usb_hashes->isEmpty()) {
        g_use_usb_token = true;
        update_master_phrase();
        g_use_usb_token = false;
        return;
    }
#endif
    g_use_usb_token = false;
    QTimer::singleShot(0, this, [&]{ input_master_phrase(); });
}

Widget::~Widget()
{
    delete ui;
}

bool Widget::eventFilter(QObject *object, QEvent *event)
{
    if (event->type() == QEvent::MouseButtonPress) {
        QMouseEvent *mouseEvent = static_cast<QMouseEvent *>(event);

        if (object == ui->tableWidget || object == ui->tableWidget->viewport()) {
            QModelIndex index = ui->tableWidget->indexAt(mouseEvent->pos());

            if (!index.isValid()) {
                // Пользователь кликнул по ПУСТОМУ месту таблицы
                ui->tableWidget->setCurrentIndex(QModelIndex());

                // Очищаем состояние фокуса ячеек
                ui->tableWidget->setCurrentCell(-1, -1);
                ui->tableWidget->clearSelection();

                ui->tableWidget->viewport()->repaint();

                ui->tableWidget->clearFocus();
                this->setFocus();
                return true;
            }
        }
        // Клик по фону самого окна
        else if (object == this) {
            // Точно так же штатно закрываем редактор перед сбросом фокуса таблицы
            ui->tableWidget->setCurrentIndex(QModelIndex());

            ui->tableWidget->setCurrentCell(-1, -1);
            ui->tableWidget->clearSelection();
            ui->tableWidget->clearFocus();
            this->setFocus();
            ui->tableWidget->viewport()->repaint();
            return true;
        }
    }

    return QWidget::eventFilter(object, event);
}

void Widget::closeEvent(QCloseEvent *event)
{
    // Проверяем, были ли вообще изменения.
    // Если таблица не менялась (is_modified == false), просто закрываем приложение без лишних вопросов!
    if (!this->is_modified) {
        event->accept();
        return;
    }

    // 1. Спрашиваем пользователя только если есть несохраненные данные
    ExitAction action = before_exit_message_box(
        tr("Подтверждение выхода"),
        tr("Сохранить изменения в таблице перед выходом?")
        );

    if (action == ExitAction::SaveAndExit) {
        // 2. Пытаемся сохранить
        if (save_to_store()) {
            event->accept(); // Сохранение успешно, закрываем
        } else {
            // Если сохранение сорвалось (например, диск защищен от записи или ошибка валидации),
            // мы обязаны предупредить пользователя, почему окно не закрылось
            QMessageBox::critical(this, tr("Ошибка"), tr("Не удалось сохранить данные. Выход отменен."));
            event->ignore();
        }
    }
    else if (action == ExitAction::DiscardAndExit) {
        event->accept(); // Закрываем без сохранения
    }
    else {
        event->ignore(); // Пользователь нажал "Отмена" или Esc
    }
}

void Widget::copy_to_clipboard()
{
    QTableWidgetItem* item_to_copy = pointers::selected_context_table_item;
    QModelIndex current_index = ui->tableWidget->currentIndex();

    // Если контекстный указатель пуст (нажали Ctrl+C на клавиатуре)
    if (!item_to_copy && current_index.isValid()) {
        item_to_copy = ui->tableWidget->item(current_index.row(), current_index.column());
    }

    // Если элемента в памяти нет, но индекс валиден — вытаскиваем текст и колонку напрямую из модели
    QString direct_text;
    int target_column = -1;
    int target_row = -1;

    if (item_to_copy) {
        direct_text = item_to_copy->data(Qt::DisplayRole).toString();
        target_column = item_to_copy->column();
        // target_row = item_to_copy->row();
    } else if (current_index.isValid()) {
        direct_text = current_index.data(Qt::DisplayRole).toString();
        target_column = current_index.column();
        // target_row = current_index.row();
    }

    // Если копировать абсолютно нечего — выходим
    if (direct_text.isEmpty() && !item_to_copy) {
        pointers::selected_context_table_item = nullptr;
        return;
    }

    QClipboard *clipboard = QApplication::clipboard();

    // Ищем и корректно сбрасываем старый таймер, если он есть
    QTimer *oldTimer = this->findChild<QTimer *>("clipboard_timer");
    if (oldTimer) {
        QPersistentModelIndex oldIndex = oldTimer->property("pIndex").value<QPersistentModelIndex>();
        if (oldIndex.isValid()) {
            auto oldItem = ui->tableWidget->item(oldIndex.row(), oldIndex.column());
            if (oldItem) {
                TableLoadingRAII lock;
                oldItem->setData(roles::AnimationRole, QVariant());
            }
            highlight_pswd(ui->tableWidget, oldIndex.row(), QDate::currentDate());
        }
        oldTimer->stop();
        oldTimer->deleteLater();
        oldTimer->setObjectName("");
    }

    // Проверяем колонку (из item или напрямую из индекса)
    if (target_column == constants::pswd_column_idx) {
        clipboard->setText(direct_text);

        // Получаем индекс модели
        QModelIndex modelIndex = item_to_copy ?
                                     ui->tableWidget->model()->index(item_to_copy->row(), item_to_copy->column()) :
                                     current_index;

        QPersistentModelIndex pIndex(modelIndex);
        int timeoutMs = 30 * 1000;
        int intervalMs = 50;

        QTimer *timer = new QTimer(this);
        timer->setObjectName("clipboard_timer");
        timer->setProperty("pIndex", QVariant::fromValue(pIndex));

        // Создаем таймер прямо на стеке
        QElapsedTimer elapsedTimer;
        elapsedTimer.start();

        // Передаем elapsedTimer по значению [=] внутрь лямбды. Никаких smart-pointers не нужно.
        connect(timer, &QTimer::timeout, this, [this, pIndex, clipboard, timer, timeoutMs, elapsedTimer, direct_text]() mutable {
            if (!pIndex.isValid()) {
                timer->stop();
                timer->deleteLater();
                return;
            }

            auto currentItem = ui->tableWidget->item(pIndex.row(), pIndex.column());

            // Если объект item пропал или ещё не создался, мы все равно можем обновлять ячейку через её индекс!
            qint64 elapsed = elapsedTimer.elapsed();

            if (elapsed < timeoutMs) {
                double progress = 1.0 - (static_cast<double>(elapsed) / timeoutMs);

                QLinearGradient gradient(0, 0, 1, 0);
                gradient.setCoordinateMode(QGradient::ObjectBoundingMode);
                gradient.setColorAt(0, QColor(255, 170, 0));
                gradient.setColorAt(progress, QColor(255, 170, 0));
                gradient.setColorAt(qMin(progress + 0.001, 1.0), Qt::transparent);

                if (currentItem) {
                    TableLoadingRAII lock;
                    currentItem->setData(roles::AnimationRole, QBrush(gradient));
                } else {
                    // Если итема нет, пишем градиент в модель напрямую по индексу
                    TableLoadingRAII lock;
                    ui->tableWidget->model()->setData(pIndex, QBrush(gradient), roles::AnimationRole);
                }

                ui->tableWidget->viewport()->update(ui->tableWidget->visualRect(pIndex));
            } else {
                timer->stop();
                timer->deleteLater();

                if (currentItem) {
                    TableLoadingRAII lock;
                    currentItem->setData(roles::AnimationRole, QVariant());
                } else {
                    TableLoadingRAII lock;
                    ui->tableWidget->model()->setData(pIndex, QVariant(), roles::AnimationRole);
                }

                highlight_pswd(ui->tableWidget, pIndex.row(), QDate::currentDate());

                // Очищаем буфер только если там всё ещё лежит наш пароль
                if (clipboard->text() == direct_text) {
                    clipboard->clear();
                    if (this->isActiveWindow()) {
                        QMessageBox::information(this,
                                                 tr("Безопасность"),
                                                 tr("Буфер обмена очищен."));
                    }
                }
            }
        });

        timer->start(intervalMs);
    } else {
        // Если это не пароль, просто копируем текст
        clipboard->setText(item_to_copy ? item_to_copy->text() : direct_text);
    }

    pointers::selected_context_table_item = nullptr;
}


void Widget::delete_row() {
    // Вычисляем индекс строки для удаления
    const int row = !pointers::selected_context_table_item ? ui->tableWidget->currentRow() :
                        pointers::selected_context_table_item->row();

    // Если строка не выбрана (индекс -1), ничего не делаем и выходим
    if (row < 0 || row >= ui->tableWidget->rowCount()) {
        return;
    }

    // Спрашиваем пользователя только тогда, когда строка действительно есть
    if (!question_message_box(
            tr("Удаление текущей строки"),
            tr("Вы действительно хотите удалить выделенную строку?")))
    {
        return;
    }

    // Безопасное удаление с блокировкой сигналов
    ui->tableWidget->blockSignals(true);
    ui->tableWidget->removeRow(row);
    ui->tableWidget->blockSignals(false);

    this->is_modified = true;
    pointers::selected_context_table_item = nullptr;

    emit row_deleted();
}

void Widget::update_pass()
{
    if (!pointers::selected_context_table_item) {
        return;
    }

    if (pointers::selected_context_table_item->column() == constants::pswd_column_idx) {

        // Безопасно читаем старый пароль для проверки на пустоту
        QString old_data = pointers::selected_context_table_item->data(Qt::DisplayRole).toString();
        if (!old_data.isEmpty()) {
            if (!question_message_box(
                    tr("Замена текущего пароля новым"),
                    tr("Вы действительно хотите заменить выделенный пароль новым?"))) {
                utils::erase_string(old_data); // Затираем временную копию старого пароля
                return;
            }
        }
        utils::erase_string(old_data); // Очищаем старый пароль из RAM, если пользователь согласился

        const int pass_level = ui->cmbbx_password_level->currentIndex();

        // Запрашиваем пароль из буфера
        QString pswd = utils_global::try_to_get_password(g_current_password_len, pass_level);

        // Если буфер пуст или вернул обрубок,
        // полностью сбрасываем строку перед повторным запросом
        if (pswd.length() < g_current_password_len) {
            utils::erase_string(pswd); // Уничтожаем дефектную строку

            // Наполняем буфер заново (синхронно дожидаясь через waitForFinished)
            utils_global::request_passwords(watcher_passwords, g_current_password_len);

            // Пробуем получить пароль еще раз в чистую строку
            pswd = utils_global::try_to_get_password(g_current_password_len, pass_level);
        }

        // Записываем чистый пароль в модель ячейки
        pointers::selected_context_table_item->setData(Qt::DisplayRole, pswd);
        pointers::selected_context_table_item->setData(Qt::EditRole, pswd);

        // Принудительно выжигаем нулями локальную копию
        // переменной pswd в стеке UI-потока перед выходом из функции!
        utils::erase_string(pswd);

        information_message_box(QString::fromUtf8("Успех"),
                                QString::fromUtf8("Пароль был обновлен"));
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

        this->is_modified = false;

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
    pointers::txt_edit_master_phrase->activateWindow();
    pointers::txt_edit_master_phrase->raise();
    pointers::txt_edit_master_phrase->setFocus();
}

void Widget::update_master_phrase()
{
    QString text;
    if (!g_use_usb_token) {
        text = pointers::txt_edit_master_phrase->toPlainText();
        pointers::txt_edit_master_phrase->clear();
        if (text.isEmpty()) {
            emit master_phrase_discarded();
            return;
        }
    }
    // Структура для возврата трех хэшей одновременно
    struct DecoupledHashes {
        lfsr_hash::u128 storage;
        lfsr_hash::u128 encryption;
        lfsr_hash::u128 inner_encryption;
    };
    constexpr size_t single_hash_size = sizeof(lfsr_hash::u128); // 16 байт
    constexpr size_t total_expected_size = 3 * single_hash_size; // 48 байт

    DecoupledHashes result = { {0,0}, {0,0}, {0,0} };
    const char *src_ptr = g_usb_hashes->constData();

    // Извлекаем первый хэш (Хэш Хранилища) — смещение 0 байт
    std::copy_n(src_ptr, single_hash_size, reinterpret_cast<char*>(&result.storage));

    // Извлекаем второй хэш (Хэш Шифрования) — смещение 16 байт
    std::copy_n(src_ptr + single_hash_size, single_hash_size, reinterpret_cast<char*>(&result.encryption));

    // Извлекаем третий хэш (Внутренний Хэш Шифрования) — смещение 32 байта
    std::copy_n(src_ptr + (2 * single_hash_size), single_hash_size, reinterpret_cast<char*>(&result.inner_encryption));

    storage_manager->BeforeUpdate();
    {
        lfsr_hash::u128 hash
            = utils_global::gen_hash_for_pass_gen(text, std::random_device{}()); // каждый раз разный
        utils_global::fill_key_by_hash128(hash);
        utils::clear_lfsr_hash(hash);
    }
    {
        lfsr_hash::u128 hash_fs = g_use_usb_token
                                      ? result.storage
                                      : utils_global::gen_hash_for_storage(text); // на usb-токен
        const auto &name = utils_global::generate_storage_name(hash_fs);
        storage_manager->SetName( name );
        storage_manager->SetTmpName( name );
        utils::clear_lfsr_hash(hash_fs);
    }
    {
        lfsr_hash::u128 hash_enc = g_use_usb_token
                                       ? result.encryption
                                       : utils_global::gen_hash_for_encryption(text); // на usb-токен
        lfsr_rng::STATE state = utils::fill_state_by_hash(hash_enc);
        watcher_seed_enc_gen.setFuture(password::worker->seed(state));
        watcher_seed_dec_gen.setFuture(password::worker->seed(state));

        lfsr_hash::u128 hash_enc_inner = g_use_usb_token
                                             ? result.inner_encryption
                                             : utils_global::gen_hash_for_inner_encryption(
                                                   text); // на usb-токен
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
    utils::erase_bytes(*g_usb_hashes);
    utils::clear_lfsr_hash(result.encryption);
    utils::clear_lfsr_hash(result.inner_encryption);
    utils::clear_lfsr_hash(result.storage);
    emit master_phrase_ready();
}

void Widget::set_master_key()
{
    lfsr_rng::STATE state; // key => state => password generator
    for (int i=0; i<password::key->N(); ++i) {
        state[i] = password::key->get_key(i);
    }
    watcher_seed_pass_gen.setFuture( password::worker->seed(state) );
    password::key->clear();
    utils::clear_lfsr_rng_state(state);
    emit master_key_set();
}

void Widget::discard_master_key()
{
    if (g_new_storage_with_transfer_mode) {
        warning_message_box(QString::fromUtf8(""),
                            QString::fromUtf8("Ввод мастер-фразы был отменен. Изменений не будет."));
        utils_global::restore_pin();
    }
    g_new_storage_with_transfer_mode = false;
}

void Widget::insert_new_password()
{
    const int pass_level = ui->cmbbx_password_level->currentIndex();
    QString pswd = utils_global::try_to_get_password(g_current_password_len, pass_level);

    if (pswd.length() < g_current_password_len) {
        utils_global::request_passwords(watcher_passwords, g_current_password_len);
        pswd = utils_global::try_to_get_password(g_current_password_len, pass_level);
    }

    ui->tableWidget->insertRow(ui->tableWidget->rowCount());
    const int row = ui->tableWidget->rowCount() - 1;

    ui->tableWidget->setItem(row, 0, new QTableWidgetItem(""));

    // Секция пароля
    {
        QTableWidgetItem *item = new QTableWidgetItem(pswd);
        ui->tableWidget->setItem(row, constants::pswd_column_idx, item);
    }

    ui->tableWidget->setItem(row, 2, new QTableWidgetItem(""));

    // Секция даты
    {
        const auto& date = QDate::currentDate().toString("yyyy.MM.dd");
        QTableWidgetItem* item = new QTableWidgetItem();
        item->setText(date);
        ui->tableWidget->setItem(row, constants::date_column_idx, item);
    }

    // Задаем фиксированную ширину вместо resizeColumnToContents
    ui->tableWidget->setColumnWidth(constants::pswd_column_idx, 200);

    // Убираем отсюда жесткие ресайзы, так как HeaderView::Stretch в макросе
    // теперь сам автоматически растягивает комментарии на всю оставшуюся ширину окна.
    ui->tableWidget->scrollToBottom();
    ui->btn_generate->setEnabled(true);
    ui->btn_generate->setFocus();

    this->is_modified = true;
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
    ui->btn_generate->setEnabled(false);
    emit passwords_ready();
}

void Widget::on_spbx_pass_len_valueChanged(int arg1)
{
    g_current_password_len = arg1 - (arg1 % constants::password_len_step);
}

void Widget::on_spbx_pass_len_editingFinished()
{
    if (ui->spbx_pass_len->value() != g_current_password_len)
        ui->spbx_pass_len->setValue(g_current_password_len);
}

void Widget::tableWidget_customContextMenuRequested(const QPoint &pos)
{
    // Получаем индекс строго по координатам клика
    QModelIndex index = ui->tableWidget->indexAt(pos);

    // Привязываем элемент, по которому кликнули (будет nullptr, если клик по пустому месту)
    pointers::selected_context_table_item = index.isValid() ?
                                                ui->tableWidget->item(index.row(), index.column()) : nullptr;

    // Если кликнули по пустому месту И в таблице вообще ничего не выбрано — меню не показываем
    if (!pointers::selected_context_table_item && !ui->tableWidget->currentItem()) {
        return;
    }

    QMenu menu(this);

    if (pointers::selected_context_table_item) {
        // Кликнули точно по ячейке: доступны копирование и удаление
        menu.addAction(copyAct);
        menu.addAction(removeAct);

        // Если это колонка с паролем — добавляем спец-действия
        if (pointers::selected_context_table_item->column() == constants::pswd_column_idx) {
            menu.addSeparator(); // Визуальный разделитель для красоты
            menu.addAction(updatePassAct);
            menu.addAction(showPassDateAct);
        }
    } else {
        // Кликнули по пустому месту таблицы, но какая-то строка до этого была выделена
        if (ui->tableWidget->currentItem()->isSelected()) {
            menu.addAction(removeAct);
        }
    }

    // Показываем меню, если в него добавился хоть один экшен
    if (!menu.actions().isEmpty()) {
        menu.exec(ui->tableWidget->viewport()->mapToGlobal(pos));
    }
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
            // Блокируем сигналы таблицы. Теперь изменение ячейки даты
            // не будет сбивать фокус клавиатуры у активного поля ввода пароля.
            ui->tableWidget->blockSignals(true);

            date_item->setText(date);
            qDebug() << "Set date: " << date;

            const auto& current_date = QDate::currentDate();
            highlight_pswd(ui->tableWidget, row, current_date);

            // Возвращаем сигналы в исходное состояние
            ui->tableWidget->blockSignals(false);
        }
    }
    // Взводим флаг изменений
    this->is_modified = true;
}

bool Widget::save_to_store()
{
    const QTableWidget* const table = ui->tableWidget;
    // Возвращаем результат выполнения
    return storage_manager->SaveToStorage(table);
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
            tr("Вы действительно хотите восстановить таблицу из текущего хранилища?"
                "После успешного ввода пин-кода текущая таблица будет перезаписана.")))
    {
        return;
    }
    MyDialog<constants::pin_code_len> dialog;
    int result = dialog.exec();
    if (result == QDialog::Accepted) {
        ;
    } else {
        return;
    }
    PinCode pin{dialog.get_secure_pin()};
    dialog.clear_pin();
    if (!utils_global::check_pin(pin)) {
        warning_message_box(QString::fromUtf8(""),
                            QString::fromUtf8("Введен неверный пин-код. Изменений не будет."));
        pin.clear();
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
                                 QString::fromUtf8("Невосстановимая ошибка. Восстановите файл хранилища из Вашей копии"
                                                    "и перезапустите программу."));
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

    MyDialog<constants::pin_code_len> dialog(QString::fromUtf8("Введите новый PIN-код"));
    int result = dialog.exec();
    if (result == QDialog::Accepted) {
        ;
    } else {
        warning_message_box(QString::fromUtf8(""),
                            QString::fromUtf8("Ввод пин-кода был отменен. Изменений не будет."));
        return;
    }
    PinCode pin{dialog.get_secure_pin()};
    dialog.clear_pin();
    if (pin.length() != constants::pin_code_len) {
        QMessageBox mb(QMessageBox::Critical,
                       QString::fromUtf8("Ошибка PIN-кода"),
                       QString::fromUtf8("PIN-код должен быть любым 4-значным числом"));
        mb.exec();
        return;
    }

    g_new_storage_with_transfer_mode = true;
    utils_global::back_up_pin();
    utils_global::set_global_pin(pin);
    pin.clear();

    warning_message_box(QString::fromUtf8(""),
                            QString::fromUtf8("После ввода новой мастер-фразы будет активировано новое хранилище."
                                            "Однако, старое при этом будет доступно. Вы можете его удалить вручную."
                                            "Если фраза введена не будет, то изменений не произойдет."));

    input_master_phrase();
}

void Widget::btn_create_usb_key_clicked()
{
    MyDialog<constants::pin_code_len> dialog;
    int result = dialog.exec();
    if (result == QDialog::Accepted) {
        ;
    } else {
        return;
    }    
    PinCode pin{dialog.get_secure_pin()};
    dialog.clear_pin();
    if (!utils_global::check_pin(pin)) {
        warning_message_box(QString::fromUtf8(""), QString::fromUtf8("Введен неверный пин-код."));
        return;
    }
    pin.clear();

    warning_message_box(
        QString::fromUtf8(""),
        QString::fromUtf8(
            "Подготовьте usb-носитель. После подтверждения мастер-фразы будет предложено"
            "окно выбора usb-носителя. Если фраза введена не будет, то ничего не произойдет."));

    if (m_masterPhraseConn) {
        QObject::disconnect(m_masterPhraseConn);
    }
    m_tempConn = connect(pointers::txt_edit_master_phrase, &MyTextEdit::sig_closing, this, [this]() {
        QString text {pointers::txt_edit_master_phrase->toPlainText()};
        pointers::txt_edit_master_phrase->clear();

        if (!text.isEmpty()) {
            auto hash_storage = utils_global::gen_hash_for_storage(text);
            auto hash_enc = utils_global::gen_hash_for_encryption(text);
            auto hash_inn_enc = utils_global::gen_hash_for_inner_encryption(text);

            utils::erase_string(text);

            // 1. Выделяем память под итоговый массив ровно один раз (16 * 3 = 48 байт, 32 байта crc )
            QByteArray data;
            data.reserve(3 * sizeof(lfsr_hash::u128) + 32);

            // 2. Поочередно конвертируем и сразу вшиваем хэши в монолитный буфер
            QByteArray tmp1 = utils::lfsr_hash_to_bytes(hash_storage);
            data.append(tmp1);
            utils::erase_bytes(tmp1); // Тут же сжигаем временную копию в ОЗУ!

            QByteArray tmp2 = utils::lfsr_hash_to_bytes(hash_enc);
            data.append(tmp2);
            utils::erase_bytes(tmp2); // Сжигаем хэш шифрования

            QByteArray tmp3 = utils::lfsr_hash_to_bytes(hash_inn_enc);
            data.append(tmp3);
            utils::erase_bytes(tmp3); // Сжигаем внутренний хэш шифрования

            QByteArray crc256 = QCryptographicHash::hash(data, QCryptographicHash::Sha256);
            data.append(crc256);
            utils::erase_bytes(crc256);

            auto stack_pin_str = password::pin_code.to_numeric_string();
            UsbStorages usb_storages{std::string_view{stack_pin_str.data(), stack_pin_str.size()},
                                     QString::fromUtf8("all_pass_token.enc"),
                                     data};

            // Делаем главное окно токена модальным (блокирует клики по родительскому окну Widget)
            usb_storages.setWindowModality(Qt::ApplicationModal);

            // Настраиваем автоматическую отправку сигнала destroyed при закрытии окна
            usb_storages.setAttribute(Qt::WA_DeleteOnClose, false); // Важно: false, так как объект на стеке!

            usb_storages.show();
            usb_storages.raise(); // Выводим окно на передний план
            usb_storages.activateWindow();
            usb_storages.setFocus();

            // Создаем локальный цикл ожидания событий Qt
            QEventLoop loop;

            // Теперь цикл событий закроется СТРОГО в момент нажатия на крестик окна,
            // до того как начнется деструкция стека
            QObject::connect(&usb_storages, &UsbStorages::sig_finished, &loop, &QEventLoop::quit);
            loop.exec();

            stack_pin_str.fill('\0');

            utils::erase_bytes(data);

            QObject::disconnect(m_tempConn);

            m_masterPhraseConn = connect(pointers::txt_edit_master_phrase, &MyTextEdit::sig_closing,
                                         this, &Widget::update_master_phrase);
        }
    });

    input_master_phrase();
}

void Widget::btn_clear_table_clicked()
{
    if (!question_message_box(
            tr("Очистка текущей таблицы."),
            tr("Вы действительно хотите очистить текущую таблицу? После успешного"
                    "ввода пин-кода текущая таблица будет очищена. В случае необходимости"
                     "ее можно восстановить из текущего хранилища, не закрывая приложения.")))
    {
        return;
    }
    MyDialog<constants::pin_code_len> dialog;
    int result = dialog.exec();
    if (result == QDialog::Accepted) {
        ;
    } else {
        return;
    }
    PinCode pin{dialog.get_secure_pin()};
    dialog.clear_pin();
    if (!utils_global::check_pin(pin)) {
        warning_message_box(QString::fromUtf8(""),
                            QString::fromUtf8("Введен неверный пин-код. Изменений не будет."));
        pin.clear();
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
#if defined(Q_OS_LINUX) || defined(Q_OS_WIN)
    btn_create_usb_key->setEnabled(true);
#endif

    storage_manager->RemoveTmpFile();
    storage_manager->SetTryToLoadFromTmp(false);

    update_number_of_rows();
    highlight_items(); // Подсветить просроченные пароли.
}
