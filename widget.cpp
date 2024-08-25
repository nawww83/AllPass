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

#include "worker.h"
#include "key.h"
#include "lfsr_hash.h"

static constexpr auto VERSION = "v1.0";

namespace main {
    lfsr_rng::Generators pass_gen;
    Worker worker;
    key::Key key;
    lfsr_hash::gens hash_gen;
    QVector<lfsr8::u64> pswd_buff{};
    QString storage{};
    int pin_code[4]{};
    bool needToGeneratePasswords = true;
}

namespace enc {
    lfsr_rng::Generators gamma_gen;
    Worker worker;
}

namespace dec {
    lfsr_rng::Generators gamma_gen;
    Worker worker;
}

namespace {
    const auto gen_pass_txt = QString::fromUtf8("Generate a password");
    MyTextEdit* txt_edit_master_phrase = nullptr;
    QTableWidgetItem* selected_context_item = nullptr;
    constexpr int num_of_passwords = 10; // in pswd_buff.
    constexpr int password_len_per_request = 10; // 64 bit = 2*32 = 2*5 ascii94 symbols.
    int password_len;
    constexpr int pswd_column_idx = 1;
    const char* asterics {"*********"};
}

static inline uint8_t rotl8(uint8_t n, unsigned int c)
{
    const unsigned int mask = CHAR_BIT*sizeof(n) - 1;
    c &= mask;
    return (n << c) | (n >> ( (-c) & mask ));
}

static inline uint8_t rotr8(uint8_t n, unsigned int c)
{
    const unsigned int mask = CHAR_BIT*sizeof(n) - 1;
    c &= mask;
    return (n >> c) | (n << ( (-c) & mask ));
}

static QString encode_94(lfsr8::u32 x)
{
    constexpr int m = 5; // See the password_len_per_request.
    QString res;
    res.resize(m);
    for (int i=0; i<m; ++i) {
        auto y = x % 94;
        res[m-i-1] = (char)(y + 33);
        x -= y;
        x /= 94;
    }
    return res;
}

static QString get_password(int len)
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
        pswd += encode_94(raw64);
        capacity -= 1;
        capacity = capacity == 0 ? 2 : capacity;
        raw64 >>= 32;
        #pragma optimize( "", on )
    }
    return pswd;
}

static lfsr_hash::salt pin_to_salt_1()
{
    using namespace lfsr_hash;
    const int x1_4bit = (main::pin_code[0] + 0) ^ (main::pin_code[1] + 0) ^ (main::pin_code[2] + 3) ^ (main::pin_code[3] + 6);
    const int x2_4bit = (main::pin_code[0] + 0) ^ (main::pin_code[1] + 6) ^ (main::pin_code[2] + 3) ^ (main::pin_code[3] + 0);
    return {((x1_4bit << 4) | x2_4bit) % 31 + 32,
            static_cast<u16>(1800*(main::pin_code[0] + main::pin_code[1] - main::pin_code[2] - main::pin_code[3]) + 32768),
            static_cast<u16>(1800*(main::pin_code[0] - main::pin_code[1] + main::pin_code[2] - main::pin_code[3]) + 32768) };
}

static lfsr_hash::salt pin_to_salt_2()
{
    using namespace lfsr_hash;
    const int x1_4bit = (main::pin_code[0] + 3) ^ (main::pin_code[1] + 0) ^ (main::pin_code[2] + 6) ^ (main::pin_code[3] + 0);
    const int x2_4bit = (main::pin_code[0] + 6) ^ (main::pin_code[1] + 0) ^ (main::pin_code[2] + 0) ^ (main::pin_code[3] + 3);
    return {((x1_4bit << 4) | x2_4bit) % 29 + 32,
            static_cast<u16>(1800*(-main::pin_code[0] - main::pin_code[1] + main::pin_code[2] + main::pin_code[3]) + 32768),
            static_cast<u16>(1800*(-main::pin_code[0] + main::pin_code[1] - main::pin_code[2] + main::pin_code[3]) + 32768) };
}

static lfsr_hash::salt hash_to_salt_1(lfsr_hash::u128 hash)
{
    using namespace lfsr_hash;
    return {static_cast<int>(hash.first % 31) + static_cast<int>(hash.first % 17) + 11,
            static_cast<u16>(hash.first),
            static_cast<u16>(hash.second)};
}

static lfsr_hash::salt hash_to_salt_2(lfsr_hash::u128 hash)
{
    using namespace lfsr_hash;
    return  {static_cast<int>(hash.first % 19) + static_cast<int>(hash.first % 31) + 13,
            static_cast<u16>(hash.first),
            static_cast<u16>(hash.second)};
}

static lfsr_hash::u128 pin_to_hash_1()
{
    using namespace lfsr_hash;
    const int x1_4bit = (main::pin_code[0] + 0) ^ (main::pin_code[1] + 0) ^ (main::pin_code[2] + 3) ^ (main::pin_code[3] + 6);
    const int x2_4bit = (main::pin_code[0] + 0) ^ (main::pin_code[1] + 6) ^ (main::pin_code[2] + 3) ^ (main::pin_code[3] + 0);
    uint8_t b_[64]{static_cast<uint8_t>(x1_4bit),
                   static_cast<uint8_t>(x2_4bit),
                   static_cast<uint8_t>((x1_4bit << 4) | x2_4bit),
                   static_cast<uint8_t>((x2_4bit << 4) | x1_4bit)};
    return hash128<64>(main::hash_gen, b_, pin_to_salt_1());
}

static lfsr_hash::u128 pin_to_hash_2() {
    using namespace lfsr_hash;
    const int x1_4bit = (main::pin_code[0] + 3) ^ (main::pin_code[1] + 0) ^ (main::pin_code[2] + 6) ^ (main::pin_code[3] + 0);
    const int x2_4bit = (main::pin_code[0] + 6) ^ (main::pin_code[1] + 0) ^ (main::pin_code[2] + 0) ^ (main::pin_code[3] + 3);
    uint8_t b_[64]{static_cast<uint8_t>(x2_4bit),
                   static_cast<uint8_t>(x1_4bit),
                   static_cast<uint8_t>((x2_4bit << 4) | x1_4bit),
                   static_cast<uint8_t>((x1_4bit << 4) | x2_4bit)};
    return hash128<64>(main::hash_gen, b_, pin_to_salt_2());
}

static lfsr_hash::salt pin_to_salt_3(size_t bytesRead, size_t blockSize)
{
    using namespace lfsr_hash;
    const int x1_4bit = (main::pin_code[0] + 0) ^ (main::pin_code[1] + 0) ^ (main::pin_code[2] + 3) ^ (main::pin_code[3] + 6);
    const int x2_4bit = (main::pin_code[0] + 0) ^ (main::pin_code[1] + 6) ^ (main::pin_code[2] + 3) ^ (main::pin_code[3] + 0);
    return {((x1_4bit << 4) | x2_4bit) % 31 + 32,
            static_cast<u16>(1800*(main::pin_code[0] + main::pin_code[1] - main::pin_code[2] - main::pin_code[3]) + blockSize),
            static_cast<u16>(1800*(main::pin_code[0] - main::pin_code[1] + main::pin_code[2] - main::pin_code[3]) + bytesRead) };
}

static lfsr_hash::salt pin_to_salt_4(size_t bytesRead, size_t blockSize)
{
    using namespace lfsr_hash;
    const int x1_4bit = (main::pin_code[0] + 3) ^ (main::pin_code[1] + 0) ^ (main::pin_code[2] + 6) ^ (main::pin_code[3] + 0);
    const int x2_4bit = (main::pin_code[0] + 6) ^ (main::pin_code[1] + 0) ^ (main::pin_code[2] + 0) ^ (main::pin_code[3] + 3);
    return {((x1_4bit << 4) | x2_4bit) % 29 + 32,
            static_cast<u16>(1800*(-main::pin_code[0] - main::pin_code[1] + main::pin_code[2] + main::pin_code[3]) + bytesRead),
            static_cast<u16>(1800*(-main::pin_code[0] + main::pin_code[1] - main::pin_code[2] + main::pin_code[3]) + blockSize) };
}

static QString get_file_name(lfsr_hash::u128 hash)
{
    using namespace lfsr_hash;
    static const auto allowed {"0123456789abcdefghijklmnopqrstuvwxyz"};
    if (std::strlen(allowed) < 36) {
        qDebug() << "Allowed alphabet is small.";
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
    title.append(VERSION);
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
    ui->tableWidget->setColumnWidth(0, 170);
    ui->tableWidget->setColumnWidth(1, 200);
    ui->tableWidget->setColumnWidth(2, 350);
    PassEditDelegate* pass_delegate = new PassEditDelegate(this);
    ui->tableWidget->setItemDelegateForColumn(pswd_column_idx, pass_delegate);
    ui->tableWidget->installEventFilter(this);
    ui->tableWidget->setEditTriggers(QAbstractItemView::DoubleClicked);
    ui->tableWidget->setContextMenuPolicy(Qt::CustomContextMenu);
    ui->tableWidget->setSelectionMode(QAbstractItemView::SingleSelection);
    connect(ui->tableWidget, &QTableWidget::customContextMenuRequested, this, &Widget::tableWidget_customContextMenuRequested);
    copyAct = new QAction(QIcon(),
                         tr("&Copy the item"), this);
    copyAct->setShortcuts(QKeySequence::Copy);
    copyAct->setStatusTip(tr("Copy the item content to clipboard"));
    connect(copyAct, &QAction::triggered, this, &Widget::copy_clipboard);
    removeAct = new QAction(QIcon(),
                          tr("&Delete the row"), this);
    removeAct->setShortcuts(QKeySequence::Delete);
    removeAct->setStatusTip(tr("Delete the current row"));
    connect(removeAct, &QAction::triggered, this, &Widget::delete_row);
    //
    connect(&watcher_seed_pass_gen, &QFutureWatcher<lfsr_rng::Generators>::finished, this, &Widget::seed_pass_has_been_set);
    connect(&watcher_passwords, &QFutureWatcher<QVector<lfsr8::u64> >::finished, this, &Widget::values_have_been_generated);
    connect(&watcher_seed_enc_gen, &QFutureWatcher<lfsr_rng::Generators>::finished, this, &Widget::seed_enc_has_been_set);
    connect(&watcher_seed_dec_gen, &QFutureWatcher<lfsr_rng::Generators>::finished, this, &Widget::seed_dec_has_been_set);
    connect(this, &Widget::values_ready, this, &Widget::try_to_add_row);
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
        if (pKeyEvent->matches(QKeySequence::Copy))
        {
            foundCopy = true;
            return true;
        }
        else
        {
            foundCopy = false;
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
    clipboard->setText(selected_context_item->data(Qt::UserRole).toString());
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

void Widget::seed_pass_has_been_set()
{
    main::pass_gen = watcher_seed_pass_gen.result();
    QMessageBox mb;
    if (!main::pass_gen.is_succes())
    {
        mb.warning(this, "Failure", "The key was not set: put another phrase.");
    } else {
        mb.information(this, "Success", "The key was set");
    }
}

void Widget::seed_enc_has_been_set()
{
    enc::gamma_gen = watcher_seed_enc_gen.result();
    QMessageBox mb;
    if (!enc::gamma_gen.is_succes())
    {
        mb.warning(this, "Failure", "The encryption was not set: put another phrase or pin.");
    } else {
        // qDebug() << enc::gamma_gen.next_u64();
        // mb.information(this, "Success", "The encryption was set");
    }
}

void Widget::seed_dec_has_been_set()
{
    dec::gamma_gen = watcher_seed_dec_gen.result();
    QMessageBox mb;
    if (!dec::gamma_gen.is_succes())
    {
        mb.warning(this, "Failure", "The decryption was not set: put another phrase or pin.");
    } else {
        // qDebug() << dec::gamma_gen.next_u64();
        // mb.information(this, "Success", "The encryption was set");
        ui->tableWidget->clearContents();
        while (ui->tableWidget->rowCount() > 0) {
            ui->tableWidget->removeRow(0);
        }
        load_storage();
        ui->btn_generate->setEnabled(true);
        ui->btn_add_empty_row->setEnabled(true);
        ui->btn_generate->setFocus();
    }
    ui->btn_generate->setText(gen_pass_txt);
}

void Widget::on_btn_input_master_phrase_clicked()
{
    if (ui->tableWidget->rowCount() != 0) {
        QMessageBox mb;
        mb.setText(QString::fromUtf8("After setting the key, unsaved data will be lost."));
        mb.setInformativeText(QString::fromUtf8("Do you agree?"));
        mb.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
        mb.setDefaultButton(QMessageBox::No);
        int ret = mb.exec();
        if (ret != QMessageBox::Yes) {
            return;
        }
    }
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
    lfsr_hash::u128 hash = pin_to_hash_1();
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
        main::storage = get_file_name(hash_fs);
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
        watcher_seed_enc_gen.setFuture(enc::worker.seed(st));
        watcher_seed_dec_gen.setFuture(dec::worker.seed(st));
        // Clear
        #pragma optimize( "", off )
            hash_fs = {0, 0};
            hash_enc = {0, 0};
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
    watcher_seed_pass_gen.setFuture( main::worker.seed(st) );
}

void Widget::try_to_add_row() {
    QString pswd = get_password(password_len);
    if (pswd.size() < password_len) {
        main::needToGeneratePasswords = true;
        return;
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

void Widget::on_btn_generate_clicked()
{
    if (!main::needToGeneratePasswords) {
        try_to_add_row();
        if (!main::needToGeneratePasswords) {
            return;
        }
    }
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
    const int Nw = (password_len * num_of_passwords) / password_len_per_request + 1;
    watcher_passwords.setFuture( main::worker.gen_n(std::ref(main::pass_gen), Nw) );
}

void Widget::values_have_been_generated()
{
    main::pswd_buff = watcher_passwords.result();
    emit values_ready();
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
    menu.exec(ui->tableWidget->mapToGlobal(pos));
}

void Widget::on_btn_add_empty_row_clicked()
{
    ui->tableWidget->insertRow(ui->tableWidget->rowCount());
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
    if (ui->tableWidget->rowCount() < 1) {
        qDebug() << "Table is empty.";
        return;
    }
    QFile file(main::storage);
    if (file.open(QFile::WriteOnly))
    {
        QStringList strList;
        int aligner64 = 0;
        const int sum_of_pin = main::pin_code[0] + main::pin_code[1] + main::pin_code[2] + main::pin_code[3] + 16;
        #pragma optimize( "", off )
        for (int i = 0; i < sum_of_pin; ++i) {
            enc::gamma_gen.next_u64();
        }
        #pragma optimize( "", on )
        lfsr_rng::u64 gamma = 0;
        QByteArray out;
        for( int r = 0; r < ui->tableWidget->rowCount(); ++r )
        {
            strList.clear();
            for( int c = 0; c < ui->tableWidget->columnCount(); ++c )
            {
                if (ui->tableWidget->item(r, c)) {
                    if (c != pswd_column_idx) {
                        strList << ui->tableWidget->item(r, c)->text();
                    } else {
                        strList << ui->tableWidget->item(r, c)->data(Qt::UserRole).toString();
                    }
                }
                else {
                    strList << "\08";
                }
            }
            auto fromUtf16 = QStringEncoder(QStringEncoder::Utf8);
            QByteArray encodedString = fromUtf16(strList.join( "\30" ) + (r < ui->tableWidget->rowCount()-1 ? "\31" : "\0"));
            QByteArray in = encodedString.toHex();
            for (auto it = in.begin(); it != in.end(); it++) {
                if (aligner64 % sizeof(lfsr_rng::u64) == 0) {
                    gamma = enc::gamma_gen.next_u64();

                }
                uint8_t b = *it;
                const int rot = gamma % 8;
                b = rotr8(b, rot);
                out.push_back(char(b) ^ char(gamma));
                gamma >>= 8;
                ++aligner64;
            }
        }
        #pragma optimize( "", off )
        if (aligner64 % sizeof(lfsr_rng::u64) != 0) {
            enc::gamma_gen.next_u64();
        }
        #pragma optimize( "", on )
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
        const int sum_of_pin = main::pin_code[0] + main::pin_code[1] + main::pin_code[2] + main::pin_code[3] + 16;
        #pragma optimize( "", off )
        for (int i = 0; i < sum_of_pin; ++i) {
            dec::gamma_gen.next_u64();
        }
        #pragma optimize( "", on )
        int aligner64 = 0;
        lfsr_rng::u64 gamma = 0;
        QByteArray in;
        for (auto it = data.begin(); it != data.end(); it++) {
            if (aligner64 % sizeof(lfsr_rng::u64) == 0) {
                gamma = dec::gamma_gen.next_u64();
            }
            const int rot = gamma % 8;
            uint8_t b = *it ^ char(gamma);
            b = rotl8(b, rot);
            in.push_back(char(b));
            gamma >>= 8;
            ++aligner64;
        }
        auto toUtf16 = QStringDecoder(QStringDecoder::Utf8);
        QString decoded_string = toUtf16(QByteArray::fromHex(in));
        rowOfData = decoded_string.split("\31");
        #pragma optimize( "", off )
        if (aligner64 % sizeof(lfsr_rng::u64) != 0) {
            dec::gamma_gen.next_u64();
        }
        #pragma optimize( "", on )
        file.close();
    } else {
        // qDebug() << "Storage cannot be opened.";
        return;
    }
    if (rowOfData.isEmpty()) {
        qDebug() << "Empty row data.";
        return;
    }
    for (int x = 0; x < rowOfData.size(); x++)
    {
        rowData = rowOfData.at(x).split("\30");
        if (rowData.size() == ui->tableWidget->columnCount()) {
            ui->tableWidget->insertRow(x);
        } else {
            qDebug() << "Unrecognized column size: " << ui->tableWidget->columnCount() << " vs " << rowData.size();
            break;
        }
        for (int y = 0; y < rowData.size(); y++)
        {
            const QString& row_str = rowData.at(y);
            QTableWidgetItem *item = new QTableWidgetItem();
            if (y == pswd_column_idx) {
                item->setData(Qt::DisplayRole, asterics);
                item->setData(Qt::UserRole, row_str == "\08" ? "" : row_str);
            } else {
                item->setText(row_str == "\08" ? "" : row_str);
            }
            ui->tableWidget->setItem(x, y, item);
        }
    }
    ui->tableWidget->resizeColumnToContents(pswd_column_idx);
    qDebug() << "Table has been loaded!";
}
