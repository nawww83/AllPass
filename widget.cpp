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
#include <qmimedata.h>

#include "worker.h"
#include "key.h"
#include "lfsr_hash.h"

static constexpr auto VERSION = "v1.0";

namespace main {
lfsr_rng::Generators cipher;
int num_of_passwords;
Worker w;
key::Key key;
lfsr_hash::gens generator;
QString copied_password;
}

namespace {
MyTextEdit* txt_edit_master_phrase{nullptr};
int password_len;
constexpr int password_len_per_request = 10; // 64 bit = 2*32 = 2*5 in ascii94
int IDX = 0;
}

static QString encode_94(lfsr8::u32 x) {
    constexpr int m = 5;
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

Widget::Widget(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Widget)
{
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
    main::num_of_passwords = ui->spbx_N_values->value();
    //
    ui->btn_generate->setText(QString::fromUtf8("Generate (%1)").arg(IDX));
    ui->btn_generate->setEnabled(false);
    //
    ui->tableWidget->setSortingEnabled(false);
    QStringList table_header {"Login","Password","Comments"};
    ui->tableWidget->setHorizontalHeaderLabels(table_header);
    ui->tableWidget->verticalHeader()->setVisible(false);
    ui->tableWidget->setColumnWidth(0, 170);
    ui->tableWidget->setColumnWidth(1, 200);
    ui->tableWidget->setColumnWidth(2, 350);
    ui->tableWidget->setContextMenuPolicy(Qt::CustomContextMenu);
    copyAct = new QAction(QIcon(),
                         tr("&Copy"), this);
    copyAct->setShortcuts(QKeySequence::Copy);
    copyAct->setStatusTip(tr("Copy to clipboard"));
    connect(copyAct, &QAction::triggered, this, &Widget::copy_clipboard);
    //
    connect(&watcher_seed, &QFutureWatcher<lfsr_rng::Generators>::finished, this, &Widget::seed_has_been_set);
    connect(&watcher_generate, &QFutureWatcher<QVector<lfsr8::u64> >::finished, this, &Widget::values_have_been_generated);
    //
    ui->btn_input_master_phrase->setFocus();
}

Widget::~Widget()
{
    delete ui;
}

void Widget::copy_clipboard() {
    if (main::copied_password.isEmpty()) {
        return;
    }
    QClipboard * clipboard = QApplication::clipboard();
    clipboard->setText(main::copied_password);
    // Clear
    #pragma optimize( "", off )
        for (auto& el : main::copied_password) {
            el = '\0';
        }
    #pragma optimize( "", on )
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
        IDX = 0;
        ui->btn_generate->setText(QString::fromUtf8("Generate (%1)").arg(IDX));
        QString tmp;
        for (int i=0; i<ui->tableWidget->rowCount(); ++i) {
            const size_t n = ui->tableWidget->item(i, 1)->text().size();
            tmp.clear();
            // Clear
            for (size_t i=0; i<n; ++i) {
                tmp.push_back('\0');
            }
            ui->tableWidget->item(i, 1)->setText(tmp);
        }
        ui->btn_generate->setFocus();
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
    auto text = txt_edit_master_phrase->toPlainText();
    txt_edit_master_phrase->clear();
    if (text.isEmpty()) {
        return;
    }
    lfsr_hash::u128 hash = {0, 0};
    constexpr size_t blockSize = 64;
    {
        using namespace lfsr_hash;
        auto bytes = text.toUtf8();
        {
            const auto bytesRead = bytes.size();
            const size_t r = bytesRead % blockSize;
            bytes.resize(bytesRead + (r > 0 ? blockSize - r : 0), '\0'); // Zero padding.
        }
        const auto bytesRead = bytes.size();
        {
            const salt& original_size_salt {static_cast<int>(bytesRead % blockSize),
                                           static_cast<u16>(bytesRead),
                                           static_cast<u16>(bytesRead)};
            const size_t n = bytesRead / blockSize;
            for (size_t i=0; i<n; ++i) {
                u128 inner_hash = hash128<blockSize>(main::generator,
                                                     reinterpret_cast<const uint8_t*>(bytes.data() + i*blockSize), original_size_salt);
                hash.first ^= inner_hash.first;
                hash.second ^= inner_hash.second;
            }
        }
    }
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
    emit master_phrase_ready();
}

void Widget::set_master_key()
{
    lfsr_rng::STATE st; // key => state => generator
    for (int i=0; i<main::key.N(); ++i) {
        st[i] = main::key.get_key(i);
    }
    watcher_seed.setFuture( main::w.seed(st) );
    ui->btn_generate->setEnabled(true);
}

void Widget::on_btn_generate_clicked()
{
    if (! watcher_seed.isFinished()) {
        qDebug() << "Rejected: the cipher is not initialized yet!";
        return;
    }
    if (main::num_of_passwords < 1) {
        qDebug() << "Rejected: set the correct N value!";
        return;
    }
    if (! main::cipher.is_succes()) {
        qDebug() << "Rejected: set the master key first!";
        return;
    }
    ui->btn_generate->setText("Wait...");
    ui->btn_generate->setEnabled(false);
    int Nw = (password_len * main::num_of_passwords) / password_len_per_request + 1;
    watcher_generate.setFuture( main::w.gen_n(std::ref(main::cipher), Nw) );
}

void Widget::values_have_been_generated()
{
    ++IDX;
    ui->btn_generate->setText(QString::fromUtf8("Generate (%1)").arg(IDX));
    const QVector<lfsr8::u64> v {watcher_generate.result()};
    QString pswd{};
    // ui->tableWidget->clearContents();
    while (ui->tableWidget->rowCount() > main::num_of_passwords) {
        ui->tableWidget->removeRow(ui->tableWidget->rowCount()-1);
    }
    while (ui->tableWidget->rowCount() < main::num_of_passwords) {
        ui->tableWidget->insertRow(0);
    }
    int c = 0; int row = 0;
    for (const auto& el : v) {
        lfsr8::u32 x = el;
        pswd += encode_94(x);
        if (pswd.length() == password_len) {
            QTableWidgetItem* item = new QTableWidgetItem(tr(pswd.toStdString().c_str()));
            item->setFlags(item->flags() ^ Qt::ItemIsEditable);
            ui->tableWidget->setItem(row++, 1, item);
            c++;
            pswd.clear();
        }
        if (c == main::num_of_passwords) {
            break;
        }
        x = el >> 32;
        pswd += encode_94(x);
        if (pswd.length() == password_len) {
            QTableWidgetItem* item = new QTableWidgetItem(tr(pswd.toStdString().c_str()));
            item->setFlags(item->flags() ^ Qt::ItemIsEditable);
            ui->tableWidget->setItem(row++, 1, item);
            c++;
            pswd.clear();
        }
        if (c == main::num_of_passwords) {
            break;
        }
    }
    ui->tableWidget->resizeColumnToContents(1);
    ui->btn_generate->setEnabled(true);
    ui->btn_generate->setFocus();
}

void Widget::on_spbx_pass_len_valueChanged(int arg1)
{
    password_len = arg1 - (arg1 % 5);
}

void Widget::on_spbx_N_values_valueChanged(int arg1)
{
    main::num_of_passwords = arg1;
}

void Widget::on_spbx_pass_len_editingFinished()
{
    if (ui->spbx_pass_len->value() != password_len)
        ui->spbx_pass_len->setValue(password_len);
}

void Widget::on_tableWidget_customContextMenuRequested(const QPoint &pos)
{
    if (!ui->tableWidget->itemAt(pos)) {
        return;
    }
    // Clear
    #pragma optimize( "", off )
        for (auto& el : main::copied_password) {
            el = '\0';
        }
    #pragma optimize( "", on )
    main::copied_password = ui->tableWidget->itemAt(pos)->text();
    QMenu menu;
    menu.addAction(copyAct);
    menu.exec(ui->tableWidget->mapToGlobal(pos));
}

