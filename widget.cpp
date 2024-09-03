/**
 * @author nawww83@gmail.com
 */

#include "widget.h"
#include "./ui_widget.h"

#include <QMessageBox>
#include <QMenu>
#include <QContextMenuEvent>
#include <QIcon>
#include <QClipboard>
#include <QItemDelegate>
#include <QFile>
#include <QStringEncoder>

#include <random> // std::random_device

#include "utils.h"

static constexpr auto VERSION = "#v1.00";

namespace {
    const auto gen_pass_txt = QString::fromUtf8("Insert a row with a new password");
    MyTextEdit* txt_edit_master_phrase = nullptr;
    QTableWidgetItem* selected_context_item = nullptr;
    constexpr int num_of_passwords = 10; // in pswd_buff.
    constexpr int password_len_per_request = 10; // 64 bit = 2*32 = 2*5 ascii94 symbols.
    int password_len;
    constexpr int pswd_column_idx = 1;
    const char* asterics {"*************"};
}

static QString GetPassword(int len)
{
    QString pswd{};
    int capacity = 2;
    lfsr8::u64 raw64;
    while (pswd.size() < len) {
        if (main::pswd_buff.empty()) {
            break;
        }
        #pragma optimize( "", off )
        raw64 = capacity == 2 ? main::pswd_buff.back() : raw64;
        if (capacity == 2) {
            main::pswd_buff.back() = 0;
            main::pswd_buff.pop_back();
        }
        pswd += Encode94(raw64);
        capacity -= 1;
        capacity = capacity == 0 ? 2 : capacity;
        raw64 >>= 32;
        #pragma optimize( "", on )
    }
    return pswd;
}

void insert_hash128_256padd(QByteArray& bytes) {
    lfsr_hash::u128 hash = pin_to_hash_2();
    constexpr size_t blockSize = 256;
    {
        {
            const auto bytesRead = bytes.size();
            const size_t r = bytesRead % blockSize;
            bytes.resize(bytesRead + (r > 0 ? blockSize - r : 0), '\0'); // Zero padding.
        }
        const auto bytesRead = bytes.size();
        {
            using namespace lfsr_hash;
            const salt& original_size_salt = pin_to_salt_4(bytesRead, blockSize);
            const size_t n = bytesRead / blockSize;
            for (size_t i=0; i<n; ++i) {
                u128 inner_hash = hash128<blockSize>(main::hash_gen,
                                                     reinterpret_cast<const uint8_t*>(bytes.data() + i*blockSize), original_size_salt);
                hash.first ^= inner_hash.first;
                hash.second ^= inner_hash.second;
            }
        }
    }
    while (hash.first) {
        bytes.append(char(hash.first));
        hash.first >>= 8;
    }
    while (hash.second) {
        bytes.append(char(hash.second));
        hash.second >>= 8;
    }
}

bool extract_and_check_hash128_256padd(QByteArray& bytes) {
    if (bytes.size() < 16) {
        qDebug() << "Small size while hash128 extracting: " << bytes.size();
        return false;
    }
    lfsr_hash::u128 extracted_hash = {0, 0};
    for (int i=0; i<8; ++i) {
        extracted_hash.second |= lfsr8::u64(uint8_t(bytes.back())) << (7-i)*8;
        bytes.removeLast();
    }
    for (int i=0; i<8; ++i) {
        extracted_hash.first |= lfsr8::u64(uint8_t(bytes.back())) << (7-i)*8;
        bytes.removeLast();
    }
    lfsr_hash::u128 hash = pin_to_hash_2();
    constexpr size_t blockSize = 256;
    {
        const auto bytesRead = bytes.size();
        {
            using namespace lfsr_hash;
            const salt& original_size_salt = pin_to_salt_4(bytesRead, blockSize);
            const size_t n = bytesRead / blockSize;
            for (size_t i=0; i<n; ++i) {
                u128 inner_hash = hash128<blockSize>(main::hash_gen,
                                                     reinterpret_cast<const uint8_t*>(bytes.data() + i*blockSize), original_size_salt);
                hash.first ^= inner_hash.first;
                hash.second ^= inner_hash.second;
            }
        }
    }
    while (!bytes.isEmpty() && bytes.back() == '\0') {
        bytes.removeLast();
    }
    return extracted_hash == hash;
}

static QString GetFileName(lfsr_hash::u128 hash)
{
    using namespace lfsr_hash;
    static constexpr auto allowed {"0123456789abcdefghijklmnopqrstuvwxyz"};
    const int allowed_len = std::strlen(allowed);
    if (allowed_len < 36) {
        qDebug() << "Allowed alphabet is small.";
        return "";
    }
    if (allowed_len > 36) {
        qDebug() << "Allowed alphabet is big.";
        return "";
    }
    uint8_t b_[64]{};
    for (int i=0; i<8; ++i) {
        b_[2*i] = hash.first >> 8*i;
        b_[2*i + 1] = hash.second >> 8*i;
    }
    u128 hash2 = hash128<64>(main::hash_gen, b_, hash_to_salt_1(hash));
    QString name {};
    for (int i=0; i<8; ++i) {
        name.push_back( allowed[(hash2.first >> 8*i) % 36] );
        name.push_back( allowed[(hash2.second >> 8*i) % 36] );
    }
    for (int i=0; i<8; ++i) {
        b_[16 + 2*i] = hash2.first >> 8*i;
        b_[16 + 2*i + 1] = hash2.second >> 8*i;
    }
    u128 hash3 = hash128<64>(main::hash_gen, b_, hash_to_salt_2(hash2));
    for (int i=0; i<8; ++i) {
        name.push_back( allowed[(hash3.first >> 8*i) % 36] );
        name.push_back( allowed[(hash3.second >> 8*i) % 36] );
    }
    return name;
}

class PassEditDelegate : public QItemDelegate
{
public:
    explicit PassEditDelegate(QObject* parent = nullptr)
        : QItemDelegate(parent)
    {}
    void setEditorData(QWidget *editor, const QModelIndex &index) const {
        QVariant value = index.model()->data(index, Qt::UserRole);
        QLineEdit * edit = qobject_cast<QLineEdit *>(editor);
        if (edit) {
            edit->setText(value.toString());
        } else {
            QItemDelegate::setEditorData(editor, index);
        }
    }
    void setModelData(QWidget *editor, QAbstractItemModel *model, const QModelIndex &index) const {
        QLineEdit * edit = qobject_cast<QLineEdit *>(editor);
        if (edit) {
            const QString value = edit->text();
            model->setData(index, asterics, Qt::DisplayRole);
            model->setData(index, value, Qt::UserRole);
        } else {
            QItemDelegate::setModelData(editor, model, index);
        }
    }
};


Widget::Widget(QString&& pin, QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Widget)
{
    {
        QString mPin {pin};
        main::pin_code[0] = mPin[0].digitValue();
        main::pin_code[1] = mPin[1].digitValue();
        main::pin_code[2] = mPin[2].digitValue();
        main::pin_code[3] = mPin[3].digitValue();
        #pragma optimize( "", off )
        for (auto& el : mPin) {
            el = '\0';
        }
        #pragma optimize( "", on )
    }
    //
    ui->setupUi(this);
    //
    QString title = "AllPass 128-bit ";
    QString version = QString(VERSION).remove("#");
    title.append(version);
    title.append(QString(" - Password Manager"));
    this->setWindowTitle( title );
    //
    txt_edit_master_phrase = new MyTextEdit();
    txt_edit_master_phrase->setWindowTitle("Master phrase input");
    txt_edit_master_phrase->setStyleSheet("color: white; background-color: black; font: 14px;");
    txt_edit_master_phrase->setVisible(false);
    //
    connect(txt_edit_master_phrase, &MyTextEdit::sig_closing, this, &Widget::update_master_phrase);
    connect(this, &Widget::master_phrase_ready, this, &Widget::set_master_key);
    //
    password_len = ui->spbx_pass_len->value();
    //
    ui->btn_generate->setText(gen_pass_txt);
    ui->btn_generate->setEnabled(false);
    ui->btn_add_empty_row->setEnabled(false);
    //
    ui->tableWidget->setSortingEnabled(false);
    QStringList table_header {"Login","Password","Comments"};
    ui->tableWidget->setHorizontalHeaderLabels(table_header);
    ui->tableWidget->verticalHeader()->setVisible(false);
    ui->tableWidget->setColumnWidth(0, 200);
    ui->tableWidget->setColumnWidth(1, 200);
    ui->tableWidget->setColumnWidth(2, 370);
    PassEditDelegate* pass_delegate = new PassEditDelegate(this);
    ui->tableWidget->setItemDelegateForColumn(pswd_column_idx, pass_delegate);
    ui->tableWidget->installEventFilter(this);
    ui->tableWidget->setEditTriggers(QAbstractItemView::DoubleClicked);
    ui->tableWidget->setContextMenuPolicy(Qt::CustomContextMenu);
    ui->tableWidget->setSelectionMode(QAbstractItemView::SingleSelection);
    connect(ui->tableWidget, &QTableWidget::customContextMenuRequested, this, &Widget::tableWidget_customContextMenuRequested);
    copyAct = new QAction(QIcon(),
                         tr("&Copy the item to the clipboard"), this);
    copyAct->setShortcuts(QKeySequence::Copy);
    copyAct->setStatusTip(tr("Copy the item to the clipboard"));
    connect(copyAct, &QAction::triggered, this, &Widget::copy_clipboard);
    removeAct = new QAction(QIcon(),
                          tr("&Delete the current row"), this);
    removeAct->setShortcuts(QKeySequence::Delete);
    removeAct->setStatusTip(tr("Delete the current row"));
    connect(removeAct, &QAction::triggered, this, &Widget::delete_row);
    updatePassAct = new QAction(QIcon(),
                                tr("&Change the password to a new one"), this);
    updatePassAct->setStatusTip(tr("Change the password to a new one"));
    connect(updatePassAct, &QAction::triggered, this, &Widget::update_pass);
    //
    connect(&watcher_seed_pass_gen, &QFutureWatcher<lfsr_rng::Generators>::finished, this, &Widget::seed_pass_has_been_set);
    //
    ui->btn_input_master_phrase->setFocus();
}

Widget::~Widget()
{
    save_to_store();
    delete ui;
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
            QMessageBox mb;
            mb.setInformativeText(QString::fromUtf8("Do you want to remove the row?"));
            mb.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
            mb.setDefaultButton(QMessageBox::No);
            int ret = mb.exec();
            if (ret != QMessageBox::Yes) {
                return false;
            }
            const int row = ui->tableWidget->currentRow();
            ui->tableWidget->removeRow(row);
            return true;
        }
    }
    if (event->type() == QEvent::KeyRelease)
    {
        QKeyEvent* pKeyEvent = static_cast<QKeyEvent*>(event);
        if (foundCopy)
        {
            selected_context_item = ui->tableWidget->currentItem();
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
    if (!selected_context_item) {
        return;
    }
    QClipboard * clipboard = QApplication::clipboard();
    if (selected_context_item->column() == pswd_column_idx) {
        clipboard->setText(selected_context_item->data(Qt::UserRole).toString());
    } else {
        clipboard->setText(selected_context_item->text());
    }
    selected_context_item = nullptr;
}

void Widget::delete_row() {
    QMessageBox mb;
    mb.setInformativeText(QString::fromUtf8("Do you want to remove the row?"));
    mb.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    mb.setDefaultButton(QMessageBox::No);
    int ret = mb.exec();
    if (ret != QMessageBox::Yes) {
        return;
    }
    if (!selected_context_item) {
        const int row = ui->tableWidget->currentRow();
        ui->tableWidget->removeRow(row);
        return;
    }
    ui->tableWidget->removeRow(selected_context_item->row());
    selected_context_item = nullptr;
}

static void RequestPasswords(QFutureWatcher<QVector<lfsr8::u64>>& watcher) {
    const int Nw = (password_len * num_of_passwords) / password_len_per_request + 1;
    watcher.setFuture( main::worker.gen_n(std::ref(main::pass_gen), Nw) );
    watcher.waitForFinished();
    main::pswd_buff = watcher.result();
}

void Widget::update_pass() {
    if (!selected_context_item) {
        return;
    }
    if (selected_context_item->column() == pswd_column_idx) {
        if (!selected_context_item->data(Qt::UserRole).toString().isEmpty()) {
            QMessageBox mb;
            mb.setInformativeText(QString::fromUtf8("Do you really want to replace the current password by a new one?"));
            mb.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
            mb.setDefaultButton(QMessageBox::No);
            int ret = mb.exec();
            if (ret != QMessageBox::Yes) {
                return;
            }
        }
        QString pswd = GetPassword(password_len);
        if (pswd.length() < password_len) {
            RequestPasswords(watcher_passwords);
            pswd = GetPassword(password_len);
        }
        selected_context_item->setData(Qt::DisplayRole, asterics);
        selected_context_item->setData(Qt::UserRole, pswd);
    } else {
        ;
    }
    selected_context_item = nullptr;
}

void Widget::seed_pass_has_been_set()
{
    main::pass_gen = watcher_seed_pass_gen.result();
    QMessageBox mb;
    if (!main::pass_gen.is_succes())
    {
        mb.warning(this, "Failure", "The key was not set: put another phrase.");
    } else {
        if (!main::storage.isEmpty()) {
            mb.information(this, "Success", "The key was set");
            ui->tableWidget->clearContents();
            while (ui->tableWidget->rowCount() > 0) {
                ui->tableWidget->removeRow(0);
            }
            load_storage();
            ui->btn_input_master_phrase->setText(QString::fromUtf8("Your storage: %1").arg(main::storage));
            ui->btn_generate->setEnabled(!main::storage.isEmpty());
            ui->btn_add_empty_row->setEnabled(!main::storage.isEmpty());
            ui->btn_generate->setFocus();
            ui->btn_generate->setText(gen_pass_txt);
        }
    }
}

void Widget::on_btn_input_master_phrase_clicked()
{
    txt_edit_master_phrase->setVisible(true);
    txt_edit_master_phrase->resize(400, 250);
    txt_edit_master_phrase->setFocus();
}

void Widget::update_master_phrase()
{
    QString text {txt_edit_master_phrase->toPlainText()};
    txt_edit_master_phrase->clear();
    if (text.isEmpty()) {
        return;
    }
    ui->btn_input_master_phrase->setEnabled(false);
    lfsr_hash::u128 hash = pin_to_hash_1();
    constexpr size_t blockSize = 64;
    {
        auto bytes = text.toUtf8();
        auto seed = std::random_device{}();
        while (seed != 0) {
            bytes.push_back( static_cast<char>(seed % 256));
            seed >>= 8;
        }
        {
            const auto bytesRead = bytes.size();
            const size_t r = bytesRead % blockSize;
            bytes.resize(bytesRead + (r > 0 ? blockSize - r : 0), '\0'); // Zero padding.
        }
        const auto bytesRead = bytes.size();
        {
            using namespace lfsr_hash;
            const salt& original_size_salt = pin_to_salt_3(bytesRead, blockSize);
            const size_t n = bytesRead / blockSize;
            for (size_t i=0; i<n; ++i) {
                u128 inner_hash = hash128<blockSize>(main::hash_gen,
                                                     reinterpret_cast<const uint8_t*>(bytes.data() + i*blockSize), original_size_salt);
                hash.first ^= inner_hash.first;
                hash.second ^= inner_hash.second;
            }
        }
    }
    //
    auto x = hash.first;
    auto y = hash.second;
    {
        using main::key;
        key.set_key(x % 65536, 3);
        key.set_key((x >> 16) % 65536, 2);
        key.set_key((x >> 32) % 65536, 1);
        key.set_key((x >> 48) % 65536, 0);
        key.set_key(y % 65536, 7);
        key.set_key((y >> 16) % 65536, 6);
        key.set_key((y >> 32) % 65536, 5);
        key.set_key((y >> 48) % 65536, 4);
    }
    // Clear
    #pragma optimize( "", off )
        x ^= x; y ^= y;
        hash.first = 0; hash.second = 0;
    #pragma optimize( "", on )
    //
    {
        lfsr_hash::u128 hash_fs = pin_to_hash_2();
        constexpr size_t blockSize = 64;
        {
            auto bytes = text.toUtf8();
            {
                const auto bytesRead = bytes.size();
                const size_t r = bytesRead % blockSize;
                bytes.resize(bytesRead + (r > 0 ? blockSize - r : 0), '\0'); // Zero padding.
            }
            const auto bytesRead = bytes.size();
            {
                using namespace lfsr_hash;
                const salt& original_size_salt = pin_to_salt_4(bytesRead, blockSize);
                const size_t n = bytesRead / blockSize;
                for (size_t i=0; i<n; ++i) {
                    u128 inner_hash = hash128<blockSize>(main::hash_gen,
                                                         reinterpret_cast<const uint8_t*>(bytes.data() + i*blockSize), original_size_salt);
                    hash_fs.first ^= inner_hash.first;
                    hash_fs.second ^= inner_hash.second;
                }
            }
        }
        main::storage = GetFileName(hash_fs);
        lfsr_hash::u128 hash_enc = pin_to_hash_1();
        {
            auto bytes = text.toUtf8();
            {
                const auto bytesRead = bytes.size();
                const size_t r = bytesRead % blockSize;
                bytes.resize(bytesRead + (r > 0 ? blockSize - r : 0), '\0'); // Zero padding.
            }
            const auto bytesRead = bytes.size();
            {
                using namespace lfsr_hash;
                const salt& original_size_salt = pin_to_salt_4(bytesRead, blockSize);
                const size_t n = bytesRead / blockSize;
                for (size_t i=0; i<n; ++i) {
                    u128 inner_hash = hash128<blockSize>(main::hash_gen,
                                                         reinterpret_cast<const uint8_t*>(bytes.data() + i*blockSize), original_size_salt);
                    hash_enc.first ^= inner_hash.first;
                    hash_enc.second ^= inner_hash.second;
                }
            }
        }
        lfsr_rng::STATE st;
        for (int i=0; i<8; ++i) {
            lfsr_hash::u16 byte_1 = 255 & (hash_enc.first >> 8*i);
            lfsr_hash::u16 byte_2 = 255 & (hash_enc.second >> 8*i);
            st[i] = (byte_1 << 8) | byte_2;
        }
        watcher_seed_enc_gen.setFuture(main::worker.seed(st));
        watcher_seed_dec_gen.setFuture(main::worker.seed(st));
        //
        lfsr_hash::u128 hash_enc_inner = pin_to_hash_2();
        {
            auto bytes = text.toUtf8();
            {
                const auto bytesRead = bytes.size();
                const size_t r = bytesRead % blockSize;
                bytes.resize(bytesRead + (r > 0 ? blockSize - r : 0), '\0'); // Zero padding.
            }
            const auto bytesRead = bytes.size();
            {
                using namespace lfsr_hash;
                const salt& original_size_salt = pin_to_salt_3(bytesRead, blockSize);
                const size_t n = bytesRead / blockSize;
                for (size_t i=0; i<n; ++i) {
                    u128 inner_hash = hash128<blockSize>(main::hash_gen,
                                                         reinterpret_cast<const uint8_t*>(bytes.data() + i*blockSize), original_size_salt);
                    hash_enc_inner.first ^= inner_hash.first;
                    hash_enc_inner.second ^= inner_hash.second;
                }
            }
        }
        for (int i=0; i<8; ++i) {
            lfsr_hash::u16 byte_1 = 255 & (hash_enc_inner.first >> 8*i);
            lfsr_hash::u16 byte_2 = 255 & (hash_enc_inner.second >> 8*i);
            st[i] = (byte_1 << 8) | byte_2;
        }
        watcher_seed_enc_inner_gen.setFuture(main::worker.seed(st));
        watcher_seed_dec_inner_gen.setFuture(main::worker.seed(st));
        watcher_seed_enc_gen.waitForFinished();
        watcher_seed_dec_gen.waitForFinished();
        watcher_seed_enc_inner_gen.waitForFinished();
        watcher_seed_dec_inner_gen.waitForFinished();
        enc::gamma_gen = watcher_seed_enc_gen.result();
        dec::gamma_gen = watcher_seed_dec_gen.result();
        enc_inner::gamma_gen = watcher_seed_enc_inner_gen.result();
        dec_inner::gamma_gen = watcher_seed_dec_inner_gen.result();
        // Clear
        #pragma optimize( "", off )
            hash_fs = {0, 0};
            hash_enc = {0, 0};
            hash_enc_inner = {0, 0};
            st[0] = 0;
            st[1] = 0;
            st[2] = 0;
            st[3] = 0;
            st[4] = 0;
            st[5] = 0;
            st[6] = 0;
            st[7] = 0;
        #pragma optimize( "", on )
    }
    //
    emit master_phrase_ready();
}

void Widget::set_master_key()
{
    lfsr_rng::STATE st; // key => state => generator
    for (int i=0; i<main::key.N(); ++i) {
        st[i] = main::key.get_key(i);
    }
    // Clear
    #pragma optimize( "", off )
        using main::key;
        key.set_key(0, 3);
        key.set_key(0, 2);
        key.set_key(0, 1);
        key.set_key(0, 0);
        key.set_key(0, 7);
        key.set_key(0, 6);
        key.set_key(0, 5);
        key.set_key(0, 4);
    #pragma optimize( "", on )
    watcher_seed_pass_gen.setFuture( main::worker.seed(st) );
    // Clear
    #pragma optimize( "", off )
        st[0] = 0;
        st[1] = 0;
        st[2] = 0;
        st[3] = 0;
        st[4] = 0;
        st[5] = 0;
        st[6] = 0;
        st[7] = 0;
    #pragma optimize( "", on )
}

void Widget::on_btn_generate_clicked()
{
    if (!watcher_seed_pass_gen.isFinished()) {
        qDebug() << "Rejected: PRNG is not initialized yet!";
        return;
    }
    if (num_of_passwords < 1) {
        qDebug() << "Rejected: not correct password length!";
        return;
    }
    if (!main::pass_gen.is_succes()) {
        qDebug() << "Rejected: set the master phrase first!";
        return;
    }
    ui->btn_generate->setText(QString::fromUtf8("Wait..."));
    ui->btn_generate->setEnabled(false);
    QString pswd = GetPassword(password_len);
    if (pswd.length() < password_len) {
        RequestPasswords(watcher_passwords);
        pswd = GetPassword(password_len);
    }
    ui->tableWidget->insertRow(ui->tableWidget->rowCount());
    const int row = ui->tableWidget->rowCount() - 1;
    QTableWidgetItem* item = new QTableWidgetItem();
    item->setData(Qt::DisplayRole, asterics);
    item->setData(Qt::UserRole, pswd);
    ui->tableWidget->setItem(row, pswd_column_idx, item);
    ui->tableWidget->resizeColumnToContents(pswd_column_idx);
    ui->btn_generate->setText(gen_pass_txt);
    ui->btn_generate->setEnabled(true);
    ui->btn_generate->setFocus();
}

void Widget::on_spbx_pass_len_valueChanged(int arg1)
{
    password_len = arg1 - (arg1 % 5);
}

void Widget::on_spbx_pass_len_editingFinished()
{
    if (ui->spbx_pass_len->value() != password_len)
        ui->spbx_pass_len->setValue(password_len);
}

void Widget::tableWidget_customContextMenuRequested(const QPoint &pos)
{
    selected_context_item = ui->tableWidget->itemAt(pos);
    if (!selected_context_item) {
        QMenu menu;
        menu.addAction(removeAct);
        menu.exec(ui->tableWidget->mapToGlobal(pos));
        return;
    }
    QMenu menu;
    menu.addAction(copyAct);
    menu.addAction(removeAct);
    if (selected_context_item->column() == pswd_column_idx) {
        menu.addAction(updatePassAct);
    }
    menu.exec(ui->tableWidget->mapToGlobal(pos));
}

void Widget::on_btn_add_empty_row_clicked()
{
    ui->tableWidget->insertRow(ui->tableWidget->rowCount());
    ui->tableWidget->setItem(ui->tableWidget->rowCount()-1, pswd_column_idx, new QTableWidgetItem(""));
}

void Widget::save_to_store()
{
    if (main::storage.isEmpty()) {
        qDebug() << "Empty storage.";
        return;
    }
    if (!enc::gamma_gen.is_succes()) {
        qDebug() << "Empty encryption.";
        return;
    }
    if (!enc_inner::gamma_gen.is_succes()) {
        qDebug() << "Empty inner encryption.";
        return;
    }
    QFile file(main::storage);
    if (file.open(QFile::WriteOnly))
    {
        QStringList strList;
        QByteArray out;
        QByteArray encoded_string;
        init_encryption();
        const int rc = ui->tableWidget->rowCount();
        const int cc = ui->tableWidget->columnCount();
        for( int row = 0; row < rc; ++row )
        {
            strList.clear();
            for( int col = 0; col < cc; ++col )
            {
                if (ui->tableWidget->item(row, col)) {
                    if (col != pswd_column_idx) {
                        const auto& txt = ui->tableWidget->item(row, col)->text();
                        strList << (txt == "" ? QChar(0x0008) : txt);
                    } else {
                        strList << ui->tableWidget->item(row, col)->data(Qt::UserRole).toString();
                    }
                }
                else {
                    strList << QChar(0x0008);
                }
            }
            auto fromUtf16 = QStringEncoder(QStringEncoder::Utf8);
            QString tmp = strList.join( QChar(0x001E) );
            tmp.append( (row < ui->tableWidget->rowCount() - 1 ? QChar(0x001F) : QChar(0x0003)) );
            encoded_string.append(fromUtf16( tmp ));
        }
        padd_256(encoded_string);
        QByteArray encrypted_inner;
        encrypt256_inner(encoded_string, encrypted_inner);
        QByteArray permuted;
        encode_dlog256(encrypted_inner, permuted);
        encrypt(permuted, out);
        finalize_encryption();
        encode_crc(out);
        out.append(VERSION);
        insert_hash128_256padd(out);
        file.write(out);
        file.close();
        qDebug() << "Table has been saved!";
    } else {
        ;
    }
}

void Widget::load_storage()
{
    if (main::storage.isEmpty()) {
        qDebug() << "Empty storage.";
        return;
    }
    if (!dec::gamma_gen.is_succes()) {
        qDebug() << "Empty decryption.";
        return;
    }
    if (!dec_inner::gamma_gen.is_succes()) {
        qDebug() << "Empty inner decryption.";
        return;
    }
    if (ui->tableWidget->rowCount() > 0) {
        qDebug() << "Table is not empty.";
        return;
    }
    QFile file(main::storage);
    QStringList rowOfData;
    QStringList rowData;
    QByteArray data;
    if (file.open(QFile::ReadOnly))
    {
        data = file.readAll();
        const bool hash_check_is_ok = extract_and_check_hash128_256padd(data);
        if (!hash_check_is_ok) {
            QMessageBox mb;
            mb.critical(nullptr, QString::fromUtf8("LFSR hash128: storage data failure"),
                        QString::fromUtf8("See the file: %1").arg(main::storage));
            main::storage = "";
            return;
        }
        QString version;
        while (!data.isEmpty() && data.back() != '#') {
            version.push_back(data.back());
            data.removeLast();
        }
        if (!data.isEmpty()) {
            data.removeLast();
        }
        std::reverse(version.begin(), version.end());
        const QString etalon_version = QString(VERSION).remove("#");
        if (version != etalon_version) {
            qDebug() << "Unrecognized version: " << version;
            return;
        }
        if (!decode_crc(data)) {
            qDebug() << "CRC: storage data failure: " << main::storage;
            QMessageBox mb;
            mb.critical(nullptr, QString::fromUtf8("CRC: storage data failure"),
                        QString::fromUtf8("See the file: %1").arg(main::storage));
            main::storage = "";
            return;
        }
        init_decryption();
        QByteArray decrypted;
        decrypt(data, decrypted);
        QByteArray depermuted;
        decode_dlog256(decrypted, depermuted);
        QByteArray decrypted_inner;
        decrypt256_inner(depermuted, decrypted_inner);
        dpadd_256(decrypted_inner);
        auto toUtf16 = QStringDecoder(QStringDecoder::Utf8);
        QString decoded_string = toUtf16(decrypted_inner);
        decoded_string.removeLast(); // 0x0003
        rowOfData = decoded_string.split(QChar(0x001F));
        finalize_decryption();
        file.close();
    } else {
        // qDebug() << "Storage cannot be opened.";
        return;
    }
    if (rowOfData.isEmpty()) {
        qDebug() << "Empty row data.";
        return;
    }
    for (int row = 0; row < rowOfData.size(); row++)
    {
        rowData = rowOfData.at(row).split(QChar(0x001E));
        if (rowData.size() == ui->tableWidget->columnCount()) {
            ui->tableWidget->insertRow(row);
        } else {
            qDebug() << "Unrecognized column size: " << ui->tableWidget->columnCount() << " vs " << rowData.size();
            break;
        }
        for (int col = 0; col < rowData.size(); col++)
        {
            const QString& row_str = rowData.at(col);
            QTableWidgetItem *item = new QTableWidgetItem();
            if (col == pswd_column_idx) {
                item->setData(Qt::DisplayRole, asterics);
                item->setData(Qt::UserRole, row_str.at(0) == QChar(0x0008) ? "" : row_str);
            } else {
                item->setText(row_str.at(0) == QChar(0x0008)  ? "" : row_str);
            }
            ui->tableWidget->setItem(row, col, item);
        }
    }
    ui->tableWidget->resizeColumnToContents(pswd_column_idx);
    qDebug() << "Table has been loaded!";
}
