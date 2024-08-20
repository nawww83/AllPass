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
#include <QStyledItemDelegate>

#include "worker.h"
#include "key.h"
#include "lfsr_hash.h"

static constexpr auto VERSION = "v1.0";

namespace main {
lfsr_rng::Generators cipher;
Worker worker;
key::Key key;
lfsr_hash::gens generator;
QVector<lfsr8::u64> pswd_buff;
bool needToGeneratePasswords = true;
}

namespace {
const auto gen_pass_txt = QString::fromUtf8("Generate a password");
MyTextEdit* txt_edit_master_phrase = nullptr;
QTableWidgetItem* selected_context_item = nullptr;
constexpr int num_of_passwords = 10; // buffer.
constexpr int password_len_per_request = 10; // 64 bit = 2*32 = 2*5 ascii94 symbols.
int password_len;
int pin_code[4]{};
}

static QString encode_94(lfsr8::u32 x) {
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

static QString get_password(int len) {
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

static QString get_file_name(lfsr_hash::u128 hash) {
    static const auto allowed {"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"};
    assert(std::strlen(allowed) == 62);
    uint8_t b_[64]{};
    for (int i=0; i<8; ++i) {
        b_[2*i] = hash.first >> 8*i;
        b_[2*i + 1] = hash.second >> 8*i;
    }
    using namespace lfsr_hash;
    const lfsr_hash::salt pin_salt {static_cast<int>(hash.first % 31) + static_cast<int>(hash.first % 17) + 11,
                                   static_cast<u16>(hash.first),
                                   static_cast<u16>(hash.second)};
    lfsr_hash::u128 hash2 = lfsr_hash::hash128<64>(main::generator, b_, pin_salt);
    QString name {};
    for (int i=0; i<8; ++i) {
        name.push_back( allowed[(hash2.first >> 8*i) % 62] );
        name.push_back( allowed[(hash2.second >> 8*i) % 62] );
    }
    for (int i=0; i<8; ++i) {
        b_[16 + 2*i] = hash2.first >> 8*i;
        b_[16 + 2*i + 1] = hash2.second >> 8*i;
    }
    const lfsr_hash::salt pin_salt2 {static_cast<int>(hash2.first % 17) + static_cast<int>(hash2.first % 31) + 13,
                                   static_cast<u16>(hash2.first),
                                   static_cast<u16>(hash2.second)};
    lfsr_hash::u128 hash3 = lfsr_hash::hash128<64>(main::generator, b_, pin_salt2);
    for (int i=0; i<8; ++i) {
        name.push_back( allowed[(hash3.first >> 8*i) % 62] );
        name.push_back( allowed[(hash3.second >> 8*i) % 62] );
    }
    return name;
}

class FilterDelegate : public QStyledItemDelegate
{
public:
    FilterDelegate(QObject *filter, QObject *parent = 0) :
        QStyledItemDelegate(parent), filter(filter)
    { }

    virtual QWidget *createEditor(QWidget *parent,
                                  const QStyleOptionViewItem &option,
                                  const QModelIndex &index) const
    {
        QWidget *editor = QStyledItemDelegate::createEditor(parent, option, index);
        editor->installEventFilter(filter);
        return editor;
    }

private:
    QObject *filter;
};

Widget::Widget(QString&& pin, QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Widget)
{
    {
        QString mPin {pin};
        pin_code[0] = mPin[0].digitValue();
        pin_code[1] = mPin[1].digitValue();
        pin_code[2] = mPin[2].digitValue();
        pin_code[3] = mPin[3].digitValue();
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
    ui->btn_save_to_store->setEnabled(false);
    //
    ui->tableWidget->setSortingEnabled(false);
    QStringList table_header {"Login","Password","Comments"};
    ui->tableWidget->setHorizontalHeaderLabels(table_header);
    ui->tableWidget->verticalHeader()->setVisible(false);
    ui->tableWidget->setColumnWidth(0, 170);
    ui->tableWidget->setColumnWidth(1, 200);
    ui->tableWidget->setColumnWidth(2, 350);
    ui->tableWidget->setItemDelegate(new FilterDelegate(ui->tableWidget));
    ui->tableWidget->installEventFilter(this);
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
    connect(&watcher_seed, &QFutureWatcher<lfsr_rng::Generators>::finished, this, &Widget::seed_has_been_set);
    connect(&watcher_generate, &QFutureWatcher<QVector<lfsr8::u64> >::finished, this, &Widget::values_have_been_generated);
    connect(this, &Widget::values_ready, this, &Widget::try_to_add_row);
    //
    ui->btn_input_master_phrase->setFocus();
}

Widget::~Widget()
{
    delete ui;
}

bool Widget::eventFilter(QObject *object, QEvent *event)
{
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
    }
    return QWidget::eventFilter(object, event);
}

void Widget::copy_clipboard() {
    if (!selected_context_item) {
        return;
    }
    QClipboard * clipboard = QApplication::clipboard();
    clipboard->setText(selected_context_item->text());
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

void Widget::seed_has_been_set()
{
    main::cipher = watcher_seed.result();
    QMessageBox mb;
    if (!main::cipher.is_succes())
    {
        mb.warning(this, "Failure", "The key was not set: put another phrase.");
    } else {
        mb.information(this, "Success", "The key was set");
        ui->btn_generate->setText(gen_pass_txt);
        ui->tableWidget->clearContents();
        while (ui->tableWidget->rowCount() > 0) {
            ui->tableWidget->removeRow(0);
        }
        ui->btn_generate->setFocus();
    }
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
    uint8_t b_[64]{static_cast<uint8_t>(pin_code[0] + 12),
                    static_cast<uint8_t>(pin_code[1] + 5),
                    static_cast<uint8_t>(pin_code[2] + 1),
                    static_cast<uint8_t>(pin_code[3] + 13)};
    using namespace lfsr_hash;
    const lfsr_hash::salt pin_salt {(((pin_code[0] + pin_code[1]) << 4) | (pin_code[2] + pin_code[3])) % 64,
                                    static_cast<u16>(13*pin_code[0] + pin_code[1] + 7*pin_code[2] + pin_code[3] + 63),
                                    static_cast<u16>(pin_code[0] + 41*pin_code[1] + pin_code[2] + 11*pin_code[3] + 61)};
    lfsr_hash::u128 hash = lfsr_hash::hash128<64>(main::generator, b_, pin_salt);
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
            const salt& original_size_salt {static_cast<int>((bytesRead + 7 + pin_code[0] + pin_code[1] + pin_code[2] + pin_code[3]) % blockSize),
                                           static_cast<u16>(bytesRead*5 + 1 + 3*pin_code[0] + pin_code[1] + 5*pin_code[2] + pin_code[3]),
                                           static_cast<u16>(bytesRead*2 + 5 + pin_code[0] + 2*pin_code[1] + 17*pin_code[2] + pin_code[3])};
            const size_t n = bytesRead / blockSize;
            for (size_t i=0; i<n; ++i) {
                u128 inner_hash = hash128<blockSize>(main::generator,
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
        for (auto& el : text) {
            el = '\0';
        }
    #pragma optimize( "", on )
    //
    {
        uint8_t b_[64]{static_cast<uint8_t>(pin_code[1] + 31),
                       static_cast<uint8_t>(pin_code[0] + 51),
                       static_cast<uint8_t>(pin_code[2] + 22),
                       static_cast<uint8_t>(pin_code[3] + 7)};
        using namespace lfsr_hash;
        const lfsr_hash::salt pin_salt {(((pin_code[2] + pin_code[1]) << 4) | (pin_code[0] + pin_code[3])) % 64,
                                       static_cast<u16>(23*pin_code[0] + 5*pin_code[1] + 3*pin_code[2] + 8*pin_code[3] + 35),
                                       static_cast<u16>(3*pin_code[0] + pin_code[1] + 3*pin_code[2] + 7*pin_code[3] + 17)};
        lfsr_hash::u128 hash_fs = lfsr_hash::hash128<64>(main::generator, b_, pin_salt);
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
                const salt& original_size_salt {static_cast<int>((bytesRead + 8 + pin_code[0] + pin_code[1] + pin_code[2] + 7*pin_code[3]) % blockSize),
                                               static_cast<u16>(bytesRead*2 + 4 + 7*pin_code[0] + pin_code[1] + 3*pin_code[2] + 2*pin_code[3]),
                                               static_cast<u16>(bytesRead*5 + 7 + pin_code[0] + 5*pin_code[1] + 12*pin_code[2] + pin_code[3])};
                const size_t n = bytesRead / blockSize;
                for (size_t i=0; i<n; ++i) {
                    u128 inner_hash = hash128<blockSize>(main::generator,
                                                         reinterpret_cast<const uint8_t*>(bytes.data() + i*blockSize), original_size_salt);
                    hash_fs.first ^= inner_hash.first;
                    hash_fs.second ^= inner_hash.second;
                }
            }
        }
        QString storage = get_file_name(hash_fs);
        qDebug() << "Storage: " << storage;
    }
    emit master_phrase_ready();
}

void Widget::set_master_key()
{
    lfsr_rng::STATE st; // key => state => generator
    for (int i=0; i<main::key.N(); ++i) {
        st[i] = main::key.get_key(i);
    }
    watcher_seed.setFuture( main::worker.seed(st) );
    ui->btn_generate->setEnabled(true);
    ui->btn_add_empty_row->setEnabled(true);
}

void Widget::try_to_add_row() {
    QString pswd = get_password(password_len);
    if (pswd.size() < password_len) {
        main::needToGeneratePasswords = true;
        return;
    }
    ui->tableWidget->insertRow(ui->tableWidget->rowCount());
    const int row = ui->tableWidget->rowCount() - 1;
    QTableWidgetItem* item = new QTableWidgetItem(tr(pswd.toStdString().c_str()));
    item->setFlags(item->flags() ^ Qt::ItemIsEditable);
    ui->tableWidget->setItem(row, 1, item);
    ui->tableWidget->resizeColumnToContents(1);
    ui->btn_save_to_store->setEnabled(true);
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
    if (!watcher_seed.isFinished()) {
        qDebug() << "Rejected: the cipher is not initialized yet!";
        return;
    }
    if (num_of_passwords < 1) {
        qDebug() << "Rejected: set the correct N value!";
        return;
    }
    if (!main::cipher.is_succes()) {
        qDebug() << "Rejected: set the master key first!";
        return;
    }
    ui->btn_generate->setText(QString::fromUtf8("Wait..."));
    ui->btn_generate->setEnabled(false);
    const int Nw = (password_len * num_of_passwords) / password_len_per_request + 1;
    watcher_generate.setFuture( main::worker.gen_n(std::ref(main::cipher), Nw) );
}

void Widget::values_have_been_generated()
{
    main::pswd_buff = watcher_generate.result();
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

void Widget::on_btn_save_to_store_clicked()
{
    ;
}

